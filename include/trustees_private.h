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

int trustees_init_security(void);
void trustees_deinit_security(void);

#ifndef _LINUX_TRUSTEES_H
#define _LINUX_TRUSTEES_H
#include <linux/config.h>
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/kdev_t.h>
#include "trustees.h"

/* this function evaluates the trustee mask applicable to given name for given user. it is does not checks the trustees for parent and higher levels 

result & TRUSTEES_ACL_MASK - allow mask
(result >> TRUSTEES_NUM_ACL_BITS) & TRUSTEES_ACL_MASK - deny mask
old_mask - the same mask for higher level
*/
#define TRUSTEES_DEFAULT_MASK TRUSTEES_USE_UNIX_MASK


struct trustee_name {
  dev_t dev;
  char * filename;
  char * devname; /* ONLY if MAJOR(dev)==0 */
      

};

extern char *trustees_filename_for_dentry(struct dentry *dent);
extern int trustees_has_unix_perm(struct inode *inode, int mask);

extern int  get_trustee_mask_for_name(const struct trustee_name * name,uid_t user,int oldmask,int height); 

extern int get_trustee_mask_for_dentry(struct dentry * dentry, uid_t user, struct nameidata *nd);

#define TRUSTEES_INITIAL_HASH_SIZE 4
#define TRUSTEES_INITIAL_NAME_BUFFER 256
#define TRUSTEES_HASDEVNAME(TNAME) ((MAJOR((TNAME).dev))==0)


/* name & permission are ignored if command=TRUSTEES_COMMAND_REMOVE_ALL */ 
/*  permission is ignored if command=TRUSTEES_COMMAND_REMOVE */ 



extern int sys_set_trustee(const struct trustee_command * c); 

/*#define TRUSTEES_DEBUG 1*/
#define TRUSTEES_DEBUG_USER 500
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
