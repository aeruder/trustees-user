/*
 * Trustees ACL Project 
 *
 * Copyright (c) 2004 Andrew Ruder (aeruder@ksu.edu) 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2.
 *
 * Shared components of the fs
 *
 * History:
 * 
 */

/*
 * Magic number!
 * 
 * FIXME: Do I just make this up or is there some system for coming
 * up with magic numbers?
 */
#define TRUSTEES_MAGIC 0x32236975

int trustees_init_fs(void);
void trustees_deinit_fs(void);
