#include <linux/security.h>
#include <linux/capability.h>

static int trustees_capable(struct task_struct *tsk, int cap);

struct security_operations trustees_security_ops = {
	.capable = trustees_capable,
};

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
	if (register_security (&trustees_security_ops)) {
		printk (KERN_INFO "Could not register security component\n");
		return -EINVAL;
	}
	return 0;
}

void trustees_deinit_security(void)
{
	if (unregister_security (&trustees_security_ops)) {
		printk (KERN_ALERT "Failure unregistering security component...\n");
	}
}
