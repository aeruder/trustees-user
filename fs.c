/*
 * Trustees ACL Project 
 *
 * Copyright (c) 2004 Andrew Ruder (aeruder@ksu.edu) 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2.
 *
 * This code handles the virtual filesystem for trustees.
 *
 * History:
 * 
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include "fs.h"


// initialization code for the trustees filesystem
//
// this code basically just sets up the superblock and registers the filesystem
static int trustees_fill_super (struct super_block *sb, void *data, int silent);
static struct super_block *trustees_get_super(struct file_system_type *fst,
  int flags, const char *devname, void *data);

// File operations
//
// this is all the code for handling the file operations done on the few files
// in the trustees filesystem
static int trustees_open(struct inode *inode, struct file *filp);
static ssize_t trustees_read_bogus(struct file *filp, char *buf, 
                             size_t count, loff_t *offset);
static ssize_t trustees_write_bogus(struct file *filp, const char *buf,
                             size_t count, loff_t *offset);
static ssize_t trustees_read_status(struct file *filp, char *buf, 
                             size_t count, loff_t *offset);
static ssize_t trustees_write_trustees(struct file *filp, const char *buf,
                             size_t count, loff_t *offset);
static int trustees_fill_super (struct super_block *sb, void *data, int silent);
static struct super_block *trustees_get_super(struct file_system_type *fst,
  int flags, const char *devname, void *data);

// Various structs
static struct file_system_type trustees_filesystem = {
	.owner = THIS_MODULE,
	.name = "trusteesfs",
	.get_sb = trustees_get_super,
	.kill_sb = kill_litter_super,
};

static struct file_operations trustees_ops_status = {
	.open = trustees_open,
	.read = trustees_read_status,
	.write = trustees_write_bogus,
};

static struct file_operations trustees_ops_trustees = {
	.open = trustees_open,
	.read = trustees_read_bogus,
	.write = trustees_write_trustees,
};

#define TRUSTEES_NUMBER_FILES 2
struct tree_descr trustees_files[] = {
	{ NULL, NULL, 0 },
	{ .name = "trustees",
	  .ops = &trustees_ops_trustees,
	  .mode = S_IWUSR,
	},
	{ .name = "status",
	  .ops = &trustees_ops_status,
	  .mode = S_IRUSR,
	},
	{ "", NULL, 0 }
};

static int trustees_fill_super (struct super_block *sb, void *data, int silent)
{
	return simple_fill_super(sb, TRUSTEES_MAGIC, trustees_files);
}

static struct super_block *trustees_get_super(struct file_system_type *fst,
  int flags, const char *devname, void *data)
{
	return get_sb_single(fst, flags, data, trustees_fill_super);
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
	if (inode->i_ino < 1 || inode->i_ino > TRUSTEES_NUMBER_FILES) return -ENODEV; 
	return 0;
}

#define TMPSIZE 20
/* Do a read on a bogus file.  Just return nothing :) */
static ssize_t trustees_read_bogus(struct file *filp, char *buf, 
                             size_t count, loff_t *offset)
{
	return 0;
}

/* Similar way to handle writes.  Just say we wrote the data and return */
static ssize_t trustees_write_bogus(struct file *filp, const char *buf,
   size_t count, loff_t *offset)
{
	return count;
}

/* Function for handling reading of the status. */
static ssize_t trustees_read_status(struct file *filp, char *buf, 
                             size_t count, loff_t *offset)
{
	static const char msg[] = "Damnit, it works, OK?!\n";
	
	if (*offset >= (sizeof(msg) - 1)) {
		return 0;
	}
	
	if (count > (sizeof(msg) - 1 - *offset)) {
		count = sizeof(msg) - 1 - *offset;
	}

	// FIXME This needs to check return value
	copy_to_user(buf, msg, count);
	(*offset) += count;

	return count;
}
	
static ssize_t trustees_write_trustees(struct file *filp, const char *buf,
                             size_t count, loff_t *offset)
{
	return count;
}
