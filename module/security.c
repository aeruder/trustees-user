/*
 * Trustees ACL Project 
 *
 * Copyright (c) 1999-2000 Vyacheslav Zavadsky
 * Copyright (c) 2004 Andrew Ruder (aeruder@ksu.edu) 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2.
 *
 * The security module (LSM API) component of the trustees system
 *
 * One quick note: generally security modules with the LSM are supposed
 * to be solely restrictive modules.  Unless the trustees module were to 
 * require that people set all files rwx by all, it could not function
 * as it is meant to function as a solely restrictive module.
 *
 * To compensate, every process is given the capability CAP_DAC_OVERRIDE.
 * In other words, every process is first given full rights to the filesystem.
 * This is the only non-restricting portion of this module, since it -does-
 * in fact give additional permissions.  However, in the inode_permission hook,
 * any rights the user should not have are taken away.  
 *
 * Side effects: Posix ACLs or other filesystem-specific permissions are not 
 * honored.  Trustees ACLs can (and do) take into account the standard unix
 * permissions, but any permissions further than that are difficult, to say
 * the least, to take into account.  I, personally, do not find this to
 * be a problem since if you are using Trustees ACLs, why also require the use
 * of another ACL system?
 */

#include <linux/security.h>
#include <linux/capability.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/namespace.h>

#include "trustees_private.h"

static int trustees_capable(struct task_struct *tsk, int cap);
static int trustees_inode_permission(struct inode *inode,
				     int mask, struct nameidata *nd);

/* Checks if user has access to the inode due to root status
 */
static inline int has_root_perm(struct inode *inode, int mask)
{
	umode_t mode = inode->i_mode;

	if (!(mask & MAY_EXEC) || (mode & S_IXUGO) || S_ISDIR(mode))
		if (current->fsuid == 0)
			return 0;

	return -EACCES;
}

/* The logic for this was mostly stolen from vfs_permission.  The security API
 * doesn't give a good way to use the actual vfs_permission for this since our
 * CAP_DAC_OVERRIDE causes it to always return 0.  But if we didn't return
 * CAP_DAC_OVERRIDE, we'd never get to handle permissions!  Since we don't need
 * to handle capabilities and dealing with ACLs with trustees loaded isn't an
 * issue for me, the function ends up being pretty simple.
 */

static inline int has_unix_perm(struct inode *inode, int mask)
{
	umode_t mode = inode->i_mode;
	mask &= ~MAY_APPEND;

	if (current->fsuid == inode->i_uid)
		mode >>= 6;
	else if (in_group_p(inode->i_gid))
		mode >>= 3;

	if (((mode & mask & (MAY_READ | MAY_WRITE | MAY_EXEC)) == mask))
		return 0;

	return -EACCES;
}

/* Find a vfsmount given an inode */
static inline struct vfsmount *find_inode_mnt(struct inode *inode,
					      struct nameidata *nd)
{
	struct namespace *ns;
	struct vfsmount *mnt = NULL;

	if (likely(nd))
		return mntget(nd->mnt);

	/* Okay, we need to find the vfsmount by looking
	 * at the namespace now.
	 */
	ns = current->namespace;
	down_read(&ns->sem);

	list_for_each_entry(mnt, &ns->list, mnt_list) {
		if (mnt->mnt_sb == inode->i_sb) {
			mntget(mnt);
			goto out;
		}
	}

      out:
	up_read(&ns->sem);

	return mnt;
}

/* Find a dentry given an inode */
static inline struct dentry *find_inode_dentry(struct inode *inode,
					       struct nameidata *nd)
{
	struct dentry *dentry;

	if (likely(nd))
		return dget(nd->dentry);

	dentry = d_find_alias(inode);

	return dentry;
}

/* 
 * Return 1 if they are under the same set of trustees
 * otherwise return 0.
 */
static inline int have_same_trustees(struct dentry *old_dentry, 
				     struct dentry *new_dentry)
{
	struct vfsmount *mnt;
	char *old_file_name, *new_file_name;
	int old_depth, new_depth;
	struct trustee_hash_element *old_deep, *new_deep;
	int is_dir;
	int ret = 0;

	mnt = find_inode_mnt(old_dentry->d_inode, NULL);
	if (unlikely(!mnt)) {
		printk(KERN_ERR "Trustees: inode does not have a mnt!\n");
		return 0;
	}

	old_file_name = trustees_filename_for_dentry(old_dentry, &old_depth, 1);
	if (!old_file_name) {
		printk(KERN_ERR "Trustees: Couldn't allocate filename\n");
		goto out_old_dentry;
	}

	new_file_name = trustees_filename_for_dentry(new_dentry, &new_depth, 1);
	if (!new_file_name) {
		printk(KERN_ERR "Trustees: Couldn't allocate filename\n");
		goto out_new_dentry;
	}

	is_dir = S_ISDIR(old_dentry->d_inode->i_mode);

	trustee_perm(old_dentry, mnt, old_file_name, ret, old_depth, is_dir, 
		     &old_deep);
	trustee_perm(new_dentry, mnt, new_file_name, ret, new_depth, is_dir, 
		     &new_deep);
	if (old_deep == new_deep) {
		ret = 1;
	}

	kfree(new_file_name);
out_new_dentry:
	kfree(old_file_name);
out_old_dentry:
	mntput(mnt);

	return ret;
}


static int trustees_inode_rename(struct inode *old_dir,
				 struct dentry *old_dentry,
				 struct inode *new_dir,
				 struct dentry *new_dentry);
static int trustees_inode_link(struct dentry *old_dentry,
			       struct inode *dir,
			       struct dentry *new_dentry);
/* Structure where we fill in the various hooks we are implementing in this module
 */
struct security_operations trustees_security_ops = {
	.capable = trustees_capable,
	.inode_permission = trustees_inode_permission,
	.inode_link = trustees_inode_link,
	.inode_rename = trustees_inode_rename
};

#define ALL_MAYS (MAY_WRITE | MAY_EXEC | MAY_READ)
/* Converts a trustee_mask to a normal unix mask
 */
static int inline trustee_mask_to_normal_mask(int mask, int isdir)
{
	int r = 0;
	if ((mask & TRUSTEE_READ_MASK) && !isdir)
		r |= MAY_READ;
	if ((mask & TRUSTEE_READ_DIR_MASK) && isdir)
		r |= MAY_READ;
	if (mask & TRUSTEE_WRITE_MASK)
		r |= MAY_WRITE;
	if ((mask & TRUSTEE_BROWSE_MASK) && isdir)
		r |= MAY_EXEC;
	if ((mask & TRUSTEE_EXECUTE_MASK) && !isdir)
		r |= MAY_EXEC;
	return r;
}

/* This is the meat of the permissions checking.  First it checks for root,
 * otherwise it first checks for any errors finding the dentry/vfsmount for 
 * the inode, and then it looks up the dentry in the trustees hash.
 */
static int trustees_inode_permission(struct inode *inode,
				     int mask, struct nameidata *nd)
{
	struct dentry *dentry;
	struct vfsmount *mnt;
	char *file_name;
	int is_dir;
	int ret;
	int depth;
	int amask;
	int dmask;
	umode_t mode = inode->i_mode;

	if (has_root_perm(inode, mask) == 0)
		return 0;

	ret = has_unix_perm(inode, mask);

	mnt = find_inode_mnt(inode, nd);
	if (unlikely(!mnt)) {
		printk(KERN_ERR "Trustees: inode does not have a mnt!\n");
		return -EACCES;	/* has_unix_perm(inode, mask); */
	}

	dentry = find_inode_dentry(inode, nd);
	if (unlikely(!dentry)) {
		/* Most of the time when this happens, it is the /
		 * If it is not, we need to dump as much information
		 * as possible on it and dump it to logs, because
		 * I'm really not sure how it happens.
		 */
		if (inode == mnt->mnt_root->d_inode) {
			dentry = dget(mnt->mnt_root);
		} else {
			/* I have seen this happen once but I did not have any
			 * way to see what caused it.  I am gonna dump_stack
			 * until I have that happen again to see if the cause
			 * is something that I need to worry about.
			 */
			dump_stack();	/* DEBUG FIXME */
			TS_DEBUG_MSG("Inode number: %ld\n", inode->i_ino);
			printk(KERN_ERR
			       "Trustees: dentry does not exist!\n");
			goto out_mnt;
		}
	}
	file_name = trustees_filename_for_dentry(dentry, &depth, 1);
	if (!file_name) {
		printk(KERN_ERR "Trustees: Couldn't allocate filename\n");
		ret = -EACCES;
		goto out_dentry;
	}

	is_dir = S_ISDIR(inode->i_mode);

	amask = trustee_perm(dentry, mnt, file_name, ret, depth, is_dir, 
			     (struct trustee_hash_element **)NULL);
	dmask = amask >> TRUSTEE_NUM_ACL_BITS;

	/* no permission if denied */
	if (trustee_mask_to_normal_mask(dmask, is_dir) & mask & ALL_MAYS) {
		ret = -EACCES;
		goto out;
	}
	/* use unix perms */
	if (!(dmask & TRUSTEE_USE_UNIX_MASK) &&
	    (amask & TRUSTEE_USE_UNIX_MASK) && (!ret))
		goto out;

	/* if the file isn't executable, then the trustees shouldn't 
	 * make it executable
	 */
	if ((mask & MAY_EXEC) && !(mode & S_IXOTH) &&
	    !((mode >> 3) & S_IXOTH) & !((mode >> 6) & S_IXOTH) &&
	    (!is_dir)) {
		ret = -EACCES;
		goto out;
	}
	/* Check trustees for permission
	 */
	if ((trustee_mask_to_normal_mask(amask, is_dir) & mask & ALL_MAYS)
	    == mask) {
		ret = 0;
		goto out;
	} else
		ret = -EACCES;

      out:
	kfree(file_name);
      out_dentry:
	dput(dentry);
      out_mnt:
	mntput(mnt);

	return ret;
}

/* We should only allow hard links under one of two conditions:
 *   1. Its in the same trustee 
 *        - if the two dentries are covered by the same trustee, there shouldn't
 *          be much of a problem with allowing the hardlink to occur.
 *   2. fsuid = 0 
 */
static int trustees_inode_link(struct dentry *old_dentry,
			       struct inode *dir,
			       struct dentry *new_dentry)
{
	if (current->fsuid == 0)
		return 0;

	if (have_same_trustees(old_dentry, new_dentry))
		return 0;

	return -EXDEV;
}

/* TODO We have a few renames to protect against:
 *   1. Don't allow people to move hardlinked files into another trustee.
 *      - If someone can move hardlinked files into another trustee, it
 *        poses a security risk since additional permissions may come with
 *        the alternate trustee.
 *   2. We don't want people to move any file that gets different permissions
 *      in one place than another.
 *   3. We don't want people to move any directory where the directory either gets
 *      different permissions, or some file in that directory (or subdirectories thereof)
 *      gets different permissions.
 *
 * In any case above, we return -EXDEV which signifies to the calling program that
 * the files are on different devices, and assuming the program is written correctly
 * it should then handle the situation by copying the files and removing the originals
 * ( which will then use the trustees permissions as they are meant to be used )
 */
static int trustees_inode_rename(struct inode *old_dir,
				 struct dentry *old_dentry,
				 struct inode *new_dir,
				 struct dentry *new_dentry)
{
	if (current->fsuid == 0)
		return 0;

	if (S_ISDIR(old_dentry->d_inode->i_mode))
		return 0;

	if (old_dentry->d_inode->i_nlink <= 1) return 0;

	if (have_same_trustees(old_dentry, new_dentry)) return 0;

	return -EXDEV;
}

/* Return CAP_DAC_OVERRIDE on everything.  We want to handle our own
 * permissions (overriding those normally allowed by unix permissions)
 */
static int trustees_capable(struct task_struct *tsk, int cap)
{
	if (cap == CAP_DAC_OVERRIDE)
		return 0;

	if (cap_is_fs_cap(cap) ? tsk->fsuid == 0 : tsk->euid == 0)
		return 0;

	return -EPERM;
}

/* Register the security module
 */
int trustees_init_security(void)
{
	/* FIXME: add in secondary module register
	 * not worry about it now since I have better
	 * things to worry about. Comprende?
	 */
	if (register_security(&trustees_security_ops)) {
		TS_DEBUG_MSG("Could not register security component\n");
		return -EINVAL;
	}

	return 0;
}

/* Unregister the security module
 */
void trustees_deinit_security(void)
{
	if (unregister_security(&trustees_security_ops)) {
		TS_DEBUG_MSG
		    ("Failure unregistering security component...\n");
	}
}
