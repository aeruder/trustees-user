#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/capability.h>

#include "ts_security.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Trustees ACL System");
MODULE_AUTHOR("Andrew E. Ruder <aeruder@ksu.edu>");

static int trustees_capable(struct task_struct *, int);

static struct security_operations trustees_security_ops = {
	.capable = trustees_capable,
};

static int trustees_capable(struct task_struct *tsk, int cap)
{
	if (cap == CAP_DAC_OVERRIDE)
		return 0;

	if (cap_is_fs_cap (cap) ? tsk->fsuid == 0 : tsk->euid == 0)
		return 0;

	return -EPERM;
}

static int __init trustees_init(void)
{
	/* FIXME: add in secondary module register
	 * not worry about it now since I have better
	 * things to worry about. Comprende?
	 */
	if (register_security (&trustees_security_ops)) {
		printk (KERN_INFO "Could not register\n");
		return -EINVAL;
	}
#ifdef TRUSTEE_DEBUG
	printk(KERN_ALERT "Hello world\n");
#endif
	return 0;
}

static void __exit trustees_exit(void)
{
	if (unregister_security (&trustees_security_ops)) {
		printk (KERN_ALERT "Failure unregistering...\n");
	}
#ifdef TRUSTEE_DEBUG	
	printk(KERN_ALERT "Goodbye cruel world!\n");
#endif
}

security_initcall(trustees_init);
module_exit(trustees_exit);
