#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/capability.h>

#include "security.h"
#include "fs.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Trustees ACL System");
MODULE_AUTHOR("Andrew E. Ruder <aeruder@ksu.edu>");

static int __init trustees_init(void)
{
	if (trustees_init_security() != 0) {
		return -EINVAL;
	}

	if (trustees_init_fs() != 0) {
		trustees_deinit_security();
		return -EINVAL;
	}

#ifdef TRUSTEES_DEBUG
	printk(KERN_ALERT "Hello world\n");
#endif

	return 0;
}

static void __exit trustees_exit(void)
{
	trustees_deinit_fs();
	trustees_deinit_security();
#ifdef TRUSTEES_DEBUG	
	printk(KERN_ALERT "Goodbye cruel world!\n");
#endif
}

security_initcall(trustees_init);
module_exit(trustees_exit);
