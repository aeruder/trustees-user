#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include "fs.h"

static int trustees_open(struct inode *inode, struct file *filp);
static ssize_t trustees_read_file(struct file *filp, char *buf, 
                             size_t count, loff_t *offset);
static ssize_t trustees_write_file(struct file *filp, const char *buf,
   size_t count, loff_t *offset);
static int trustees_fill_super (struct super_block *sb, void *data, int silent);
static struct super_block *trustees_get_super(struct file_system_type *fst,
  int flags, const char *devname, void *data);

static struct file_system_type trustees_filesystem = {
	.owner = THIS_MODULE,
	.name = "trusteesfs",
	.get_sb = trustees_get_super,
	.kill_sb = kill_litter_super,
};

static struct file_operations trustees_file_ops = {
	.open = trustees_open,
	.read = trustees_read_file,
	.write = trustees_write_file,
};
struct tree_descr trustees_files[] = {
	{ NULL, NULL, 0 },
	{ .name = "trustees",
	  .ops = &trustees_file_ops,
	  .mode = S_IWUSR|S_IRUGO,
	},
	{ "", NULL, 0 }
};

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
	if (inode->i_ino != 1) return -ENODEV; // wtf...
	return 0;
}

#define TMPSIZE 20
/*
 * Read the file... Right now it just needs to be empty...
 */
static ssize_t trustees_read_file(struct file *filp, char *buf, 
                             size_t count, loff_t *offset)
{
	char x;
	
	if (copy_to_user(buf, &x, 0))
		return -EFAULT;
	
	return 0;
}
	
static ssize_t trustees_write_file(struct file *filp, const char *buf,
   size_t count, loff_t *offset)
{
	return 0;
}

/* 
 * file ops struct
 */


static int trustees_fill_super (struct super_block *sb, void *data, int silent)
{
	return simple_fill_super(sb, TRUSTEES_MAGIC, trustees_files);
}

static struct super_block *trustees_get_super(struct file_system_type *fst,
  int flags, const char *devname, void *data)
{
	return get_sb_single(fst, flags, data, trustees_fill_super);
}

