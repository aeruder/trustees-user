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
 * Module initialization and cleanup 
 *
 * History:
 *  2002-12-16 trustees 2.10 released by Vyacheslav Zavadsky
 * 
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/capability.h>

#include "security.h"
#include "fs.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Trustees ACL System");
MODULE_AUTHOR("Vyacheslav Zavadsky and Andrew E. Ruder <aeruder@ksu.edu>");

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
