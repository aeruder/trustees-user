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

static inline int trustees_has_root_perm(struct inode *inode, int mask);
static inline int trustees_has_unix_perm(struct inode *inode, int mask);
static inline struct vfsmount *find_inode_mnt(
   struct inode *inode, struct nameidata *nd);
static inline struct dentry *find_inode_dentry(
   struct inode *inode, struct nameidata *nd);
static int trustees_inode_rename (struct inode *old_dir, struct dentry *old_dentry,
                            struct inode *new_dir, struct dentry *new_dentry);
static int trustees_inode_link (struct dentry *old_dentry,
                          struct inode *dir, struct dentry *new_dentry);

/* Structure where we fill in the various hooks we are implementing in this module
 */
struct security_operations trustees_security_ops = {
	.capable = trustees_capable,
	.inode_permission = trustees_inode_permission,
	.inode_link = trustees_inode_link,
	.inode_rename = trustees_inode_rename
};

static int inline trustee_mask_to_normal_mask(int mask, int isdir) {
	int r=0;
	if ((mask & TRUSTEE_READ_MASK)  && !isdir) r |= S_IROTH;
	if ((mask & TRUSTEE_READ_DIR_MASK)  && isdir) r |= S_IROTH;
	if (mask & TRUSTEE_WRITE_MASK) r |= S_IWOTH;
	if ((mask & TRUSTEE_BROWSE_MASK) && isdir) r |= S_IXOTH;
	if ((mask & TRUSTEE_EXECUTE_MASK) && !isdir) r |= S_IXOTH;
	return r;
}
static int trustees_inode_permission(struct inode *inode, 
    int mask, struct nameidata *nd) {
	struct dentry *dentry;
	struct vfsmount *mnt;
	char *file_name;
	int ret;
	int is_dir;
	int depth;
	int amask;
	int dmask;
	umode_t mode = inode->i_mode;

	if (trustees_has_root_perm(inode, mask) == 0) return 0;

	ret = trustees_has_unix_perm(inode, mask);
	
	mnt = find_inode_mnt(inode, nd);
	if (unlikely(!mnt)) {
		printk(KERN_ERR "Trustees: inode does not have a mnt!\n");
		return -EACCES;// trustees_has_unix_perm(inode, mask);
	}
		
	dentry = find_inode_dentry(inode, nd);
	if (unlikely(!dentry)) {
		dump_stack(); // DEBUG FIXME
		printk(KERN_ERR "Trustees: dentry does not exist!\n");
		goto out_mnt;
	}
	file_name = trustees_filename_for_dentry(dentry, &depth);
	if (!file_name) {
		printk(KERN_ERR "Trustees: Couldn't allocate filename\n");
		ret = -EACCES;
		goto out_dentry;
	}
	
	is_dir = S_ISDIR(inode->i_mode);

	amask = trustee_perm(dentry, mnt, file_name, ret, depth, is_dir);
//	TS_DEBUG_MSG("trustee_perm returned %x\n", amask);
	dmask = amask >> TRUSTEE_NUM_ACL_BITS;

	/* no permission if denied */
	if (trustee_mask_to_normal_mask(dmask, is_dir) &  
	    mask & S_IRWXO) { 
 		ret = -EACCES;
		goto out;
	}
	// use unix perms
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
	if ((trustee_mask_to_normal_mask(amask, is_dir) & mask & S_IRWXO) == mask) {
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
	
static int trustees_inode_link (struct dentry *old_dentry,
                          struct inode *dir, struct dentry *new_dentry) {
	if (current->fsuid == 0) return 0;
	
	if (old_dentry->d_parent == new_dentry->d_parent) {
		return 0;
	}

	return -EPERM;
}

static int trustees_inode_rename (struct inode *old_dir, struct dentry *old_dentry,
                            struct inode *new_dir, struct dentry *new_dentry) {
	int is_dir;

	if (current->fsuid == 0) return 0;
	
	is_dir = S_ISDIR(old_dentry->d_inode->i_mode);

	if (!is_dir && old_dentry->d_inode->i_nlink > 1) {
		if (old_dentry->d_parent == new_dentry->d_parent)
			return -EPERM;
	}

	return 0;
}
	
/* Return CAP_DAC_OVERRIDE on everything.  We want to handle our own
 * permissions and we don't want the filesystem stuff interfering.
 */
static int trustees_capable(struct task_struct *tsk, int cap)
{
	if (cap == CAP_DAC_OVERRIDE)
		return 0;

	if (cap_is_fs_cap (cap) ? tsk->fsuid == 0 : tsk->euid == 0)
		return 0;

	return -EPERM;
}

int trustees_init_security(void)
{
	/* FIXME: add in secondary module register
	 * not worry about it now since I have better
	 * things to worry about. Comprende?
	 */
	if (register_security (&trustees_security_ops)) {
		TS_DEBUG_MSG ("Could not register security component\n");
		return -EINVAL;
	}

	TS_DEBUG_MSG ("Security component registered\n");

	return 0;
}

void trustees_deinit_security(void)
{
	if (unregister_security (&trustees_security_ops)) {
		TS_DEBUG_MSG ("Failure unregistering security component...\n");
	}

	TS_DEBUG_MSG ("Security component unregistered\n");
}

static inline int trustees_has_root_perm(struct inode *inode, int mask) {
	umode_t mode = inode->i_mode;

	if (!(mask & MAY_EXEC) ||
	  (mode & S_IXUGO) || S_ISDIR(mode))
		if (current->fsuid == 0)
			return 0;
	
	return -EACCES;
}

// The logic for this was mostly stolen from vfs_permission.  The security API
// doesn't give a good way to use the actual vfs_permission for this since our
// CAP_DAC_OVERRIDE causes it to always return 0.  But if we didn't return
// CAP_DAC_OVERRIDE, we'd never get to handle permissions!  Since we don't need
// to handle capabilities and dealing with ACLs with trustees loaded isn't an
// issue for me, the function ends up being pretty simple.

static inline int trustees_has_unix_perm(struct inode *inode, int mask) {
	umode_t mode = inode->i_mode;

	if (current->fsuid == inode->i_uid)
		mode >>= 6;
	else if (in_group_p(inode->i_gid))
		mode >>= 3;

	if (((mode & mask & (MAY_READ|MAY_WRITE|MAY_EXEC)) == mask))
		return 0;

	return -EACCES;
}

// Find a vfsmount given an inode
static inline struct vfsmount *find_inode_mnt(
   struct inode *inode, struct nameidata *nd) {
	struct namespace *ns;
	struct vfsmount *mnt = NULL;
	
	if (likely(nd)) return mntget(nd->mnt);

	// Okay, we need to find the vfsmount by looking
	// at the namespace now.
	
	task_lock(current);
	spin_lock(&vfsmount_lock);
	
	// debug
	if (unlikely(!current->namespace)) goto out_wo_ns;
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
out_wo_ns: 	
	spin_unlock(&vfsmount_lock);
	task_unlock(current);

	return mnt;
}

// Find a dentry given an inode
static inline struct dentry *find_inode_dentry(
   struct inode *inode, struct nameidata *nd) {
	struct dentry *dentry;

	if (likely(nd)) return dget(nd->dentry);

	dentry = d_find_alias(inode);
	if (dentry) dget(dentry);

	return dentry;
}
