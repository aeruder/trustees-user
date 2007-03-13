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
 * This code handles the virtual filesystem for trustees.
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include "trustees_private.h"


/* initialization code for the trustees filesystem */

/* File operations
 *
 * this is all the code for handling the file operations done on the few files
 * in the trustees filesystem
 */
static int trustees_open(struct inode *inode, struct file *filp);
static ssize_t trustees_read_bogus(struct file *filp, char __user * buf,
				   size_t count, loff_t * offset);
static ssize_t trustees_write_bogus(struct file *filp,
				    const char __user * buf, size_t count,
				    loff_t * offset);
static ssize_t trustees_read_status(struct file *filp, char __user * buf,
				    size_t count, loff_t * offset);
static ssize_t trustees_read_apiversion(struct file *filp, char __user * buf,
				    size_t count, loff_t * offset);
static ssize_t trustees_write_trustees(struct file *filp,
				       const char __user * buf,
				       size_t count, loff_t * offset);
static int trustees_fill_super(struct super_block *sb, void *data,
			       int silent);
static int trustees_get_super(struct file_system_type *fst,
					      int flags,
					      const char *devname,
					      void *data,
					      struct vfsmount *);

/* Various structs
 */
static struct file_system_type trustees_filesystem = {
	.owner = THIS_MODULE,
	.name = "trusteesfs",
	.get_sb = trustees_get_super,
	.kill_sb = kill_litter_super,
};

static struct file_operations trustees_ops_apiversion = {
	.open = trustees_open,
	.read = trustees_read_apiversion,
	.write = trustees_write_bogus,
};

static struct file_operations trustees_ops_status = {
	.open = trustees_open,
	.read = trustees_read_status,
	.write = trustees_write_bogus
};

static struct file_operations trustees_ops_trustees = {
	.open = trustees_open,
	.read = trustees_read_bogus,
	.write = trustees_write_trustees,
};

#define TRUSTEES_NUMBER_FILES 3 
struct tree_descr trustees_files[] = {
	{NULL, NULL, 0},
	{.name = "trustees",
	 .ops = &trustees_ops_trustees,
	 .mode = S_IWUSR,
	 },
	{.name = "status",
	 .ops = &trustees_ops_status,
	 .mode = S_IRUSR,
	 },
	{.name = "apiversion",
	 .ops = &trustees_ops_apiversion,
	 .mode = S_IRUSR | S_IRGRP | S_IROTH,
	 },
	{"", NULL, 0}
};

static int trustees_fill_super(struct super_block *sb, void *data,
			       int silent)
{
	return simple_fill_super(sb, TRUSTEES_MAGIC, trustees_files);
}

static int trustees_get_super(struct file_system_type *fst,
					      int flags,
					      const char *devname,
					      void *data,
					      struct vfsmount *mnt)
{
	return get_sb_single(fst, flags, data, trustees_fill_super, mnt);
}

int trustees_init_fs(void)
{
	return register_filesystem(&trustees_filesystem);
}

void trustees_deinit_fs(void)
{
	unregister_filesystem(&trustees_filesystem);
}

/*
 * They're opening the file...
 */

static int trustees_open(struct inode *inode, struct file *filp)
{
	if (inode->i_ino < 1 || inode->i_ino > TRUSTEES_NUMBER_FILES)
		return -ENODEV;
	return 0;
}

#define TMPSIZE 20
/* Do a read on a bogus file.  Just return nothing :) */
static ssize_t trustees_read_bogus(struct file *filp, char __user * buf,
				   size_t count, loff_t * offset)
{
	return 0;
}

/* Similar way to handle writes.  Just say we wrote the data and return */
static ssize_t trustees_write_bogus(struct file *filp,
				    const char __user * buf, size_t count,
				    loff_t * offset)
{
	return count;
}

/* Function for handling reading of the status. */
static ssize_t trustees_read_status(struct file *filp, char __user * buf,
				    size_t count, loff_t * offset)
{
	static const char msg[] = "Damnit, it works, OK?!\n";
	unsigned long nocopy;

	if (*offset >= (sizeof(msg) - 1)) {
		return 0;
	}

	if (count > (sizeof(msg) - 1 - *offset)) {
		count = sizeof(msg) - 1 - *offset;
	}
	nocopy = copy_to_user(buf, msg, count);
	(*offset) += count;
	(*offset) -= nocopy;

	return count;
}

/* Function for handling reading of the apiversion. */
static ssize_t trustees_read_apiversion(struct file *filp, char __user * buf,
				    size_t count, loff_t * offset)
{
	static const char msg[] = TRUSTEES_APIVERSION_STR "\n";

	unsigned long nocopy;

	if (*offset >= (sizeof(msg) - 1)) {
		return 0;
	}

	if (count > (sizeof(msg) - 1 - *offset)) {
		count = sizeof(msg) - 1 - *offset;
	}
	nocopy = copy_to_user(buf, msg, count);
	(*offset) += count;
	(*offset) -= nocopy;

	return count;
}
static ssize_t trustees_write_trustees(struct file *filp,
				       const char __user * buf,
				       size_t count, loff_t * offset)
{
	if (count != sizeof(struct trustee_command)) {
		return -EIO;
	}

	if (!trustees_process_command
	    ((const struct trustee_command __user *) buf)) {
		return count;
	}

	return -EIO;
}
