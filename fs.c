static struct file_system_type trustees_filesystem = {
	.owner = THIS_MODULE,
	.name = "trusteefs",
	.get_sb = trustee_get_super,
	.kill_sb = kill_litter_super,
};

static struct file_operations trustee_file_ops = {
	.open = trustee_open,
	.read = trustee_read_file,
	.write = trustee_write_file,
};
struct tree_descr trustee_files[] = {
	{ NULL, NULL, 0 },
	{ .name = "trustees",
	  .ops = &trustee_file_ops,
	  .mode = S_IWUSR|S_IRUGO,
	},
	{ "", NULL, 0 }
};
int trustees_init_fs(void) 
{

}

void trustees_deinit_fs(void) {
}

/*
 * They're opening the file...
 */

static int trustee_open(struct inode *inode, struct file *filp)
{
	if (inode->i_ino != 1) return -ENODEV; // wtf...
	return 0;
}

#define TMPSIZE 20
/*
 * Read the file... Right now it just needs to be empty...
 */
static ssize_t trustee_read_file(struct file *filp, char *buf, 
                             size_t count, loff_t *offset)
{
	char x;
	
	if (copy_to_user(buf, &x, 0))
		return -EFAULT;
	
	return 0;
}
	
static ssize_t trustee_write_file(struct file *filp, const char *buf,
   size_t count, loff_t *offset)
{
	return 0;
}

/* 
 * file ops struct
 */


static int trustee_fill_super (struct super_block *sb, void *data, int silent)
{
	return simple_fill_super(sb, TRUSTEE_MAGIC, trustee_files);
}

static struct super_block *trustee_get_super(struct file_system_type *fst,
  int flags, const char *devname, void *data)
{
	return get_sb_single(fst, flags, data, trustee_fill_super);
}


static int __init trustee_init(void)
{
	return register_filesystem(&trustee_type);
}

static void __exit trustee_exit(void)
{
	unregister_filesystem(&trustee_type);
}

module_init(trustee_init);
module_exit(trustee_exit);
	

