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


/* Structure where we fill in the various hooks we are implementing in this module
 */
struct security_operations trustees_security_ops = {
	.capable = trustees_capable,
	.inode_permission = trustees_inode_permission
};

static inline struct nameidata *find_nameidata(struct inode *inode, struct nameidata *nd) {
	struct namespace *namespace;
	
	if (likely(nd)) return nd;

	namespace = current->namespace;
	get_namespace(namespace);

	if (unlikely(!namespace)) {
		printk(KERN_ERR "namespace is NULL!");
		return NULL;
	}
}
	
static int trustees_inode_permission(struct inode *inode, 
    int mask, struct nameidata *nd) {

	umode_t mode = inode->i_mode;
	const char *device_name = NULL;
	char *file_name;
	int c = 0;
	struct dentry *dentry;
	
	if (!inode) {
		printk(KERN_INFO "Inode was 0!\n" );
		return 0;
	}
	if (list_empty(&inode->i_dentry)) {
		printk(KERN_INFO "dentry list was empty!\n");
		return 0;
	}
	if (!nd || !nd->mnt) {
		dentry = d_find_alias(inode);
		if (dentry) {
			file_name = trustees_filename_for_dentry(dentry);
			printk(KERN_INFO "TRUSTEES %s has an nd of %d\n", file_name, (int)nd);
		}
		dput(dentry);
		device_name = nd->mnt->mnt_devname;
	}
	
/*
	is_dir = indoe is directory
	find_alias dentry
	get_filename
	check_filename 
	
	dentry = d_find_alias(inode);
	list_for_each_entry(dent, &inode->i_dentry, d_alias) {
		
		file_name = trustees_filename_for_dentry(dent);
		printk(KERN_INFO "TRUSTEES %d %s %s\n", c, file_name, device_name);
		if (file_name) {
			kfree(file_name);
		}
		c++;
	}

	*/
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


// This should be called with sb_lock locked
int initialize_superblocks(void) {
	struct super_block *sb;

	list_for_each_entry(sb, super_blocks, s_list) {
		
		

	
	struct namespace *namespace;
	
	if (likely(nd)) return nd;

	namespace = current->namespace;
	get_namespace(namespace);

	if (unlikely(!namespace)) {
		printk(KERN_ERR "namespace is NULL!");
		return NULL;
	}

}

int trustees_init_security(void)
{
	/* FIXME: add in secondary module register
	 * not worry about it now since I have better
	 * things to worry about. Comprende?
	 */
	if (register_security (&trustees_security_ops)) {
		printk (KERN_INFO "Could not register security component\n");
		return -EINVAL;
	}

#ifdef TRUSTEES_DEBUG
	printk (KERN_DEBUG "Security component registered\n");
#endif

	return 0;
}

void trustees_deinit_security(void)
{
	if (unregister_security (&trustees_security_ops)) {
		printk (KERN_ALERT "Failure unregistering security component...\n");
	}

#ifdef TRUSTEES_DEBUG
	printk (KERN_DEBUG "Security component unregistered\n");
#endif
}
