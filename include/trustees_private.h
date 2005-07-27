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
 * Private methods and definitions used only within the module. 
 *
 */

#ifndef _LINUX_TRUSTEES_H
#define _LINUX_TRUSTEES_H
#include <linux/config.h>
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/kdev_t.h>
#include <linux/list.h>
#include "trustees.h"

#define TRUSTEE_DEFAULT_MASK TRUSTEE_USE_UNIX_MASK

struct trustee_ic {
	dev_t dev;
	char *devname;		/* ONLY if MAJOR(dev)==0 */
	struct list_head ic_list;
};

struct trustee_name {
	dev_t dev;
	char *filename;
	char *devname;		/* ONLY if MAJOR(dev)==0 */
};

struct trustee_permission_capsule {
	struct list_head perm_list;
	struct trustee_permission permission;
};

/* For the usage field */
#define TRUSTEE_HASH_ELEMENT_USED 2
#define TRUSTEE_HASH_ELEMENT_DELETED 1
#define TRUSTEE_HASH_ELEMENT_NOTUSED 0

struct trustee_hash_element {
	int usage;      
	struct trustee_name name;
	struct list_head perm_list;
};

extern char *trustees_filename_for_dentry(struct dentry *dentry, int *d, int trunc);

extern int trustees_funcs_init_globals(void);
extern int trustees_funcs_cleanup_globals(void);

int trustee_perm(struct dentry *dentry, struct vfsmount *mnt,
		 char *file_name, int unix_ret, int depth, int is_dir,
		 struct trustee_hash_element **deepest);

extern int trustees_process_command(const struct trustee_command __user *
				    command);

#define TRUSTEE_INITIAL_HASH_SIZE 32

#define TRUSTEE_INITIAL_NAME_BUFFER 256
#define TRUSTEE_HASDEVNAME(TNAME) (MAJOR((TNAME).dev)==0)

#ifdef TRUSTEES_DEBUG
#define TS_DEBUG_MSG(...) printk(KERN_ERR "Trustees: " __VA_ARGS__)
#else
#define TS_DEBUG_MSG(...)
#endif

/*
 * Magic number!
 * 
 * FIXME: Do I just make this up or is there some system for coming
 * up with magic numbers?
 */
#define TRUSTEES_MAGIC 0x32236975

int trustees_init_fs(void);
void trustees_deinit_fs(void);

int trustees_init_security(void);
void trustees_deinit_security(void);
#endif				/* _LINUX_TRUSTEES_H */
