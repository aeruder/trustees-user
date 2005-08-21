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
 * This code contains the functions for handling the actual trustees data 
 * and returning the permissions for a given file, etc.
 *
 * 
 */

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/limits.h>
#include <linux/list.h>

#include "trustees.h"
#include "trustees_private.h"

/*
 * This is a hash of all the trustee_names currently added.  These values
 * are hashed on a combination of device/filename.  Before reading/writing
 * be sure to take care of the locking of trustee_hash_lock.
 */
static rwlock_t trustee_hash_lock = RW_LOCK_UNLOCKED;
DECLARE_MUTEX(trustee_rebuild_hash_sem);
static struct trustee_hash_element *trustee_hash = NULL;
static int trustee_hash_size = 0, trustee_hash_used =
    0, trustee_hash_deleted = 0;

/*
 * This is the deepest level trustee.  When calculating filenames, we can
 * skip several of the levels in many case since we know it won't be any
 * deeper than this.
 *
 * /           => 0
 * /test       => 1
 * /test/blah  => 2
 */
static int deepest_level = 0;

/* 
 * A list of filesystems that need to have their case
 * ignored.
 */
static rwlock_t trustee_ic_lock = RW_LOCK_UNLOCKED;
static LIST_HEAD(trustee_ic_list);


/* The calling method needs to free the buffer created by this function
 * This method returns the filename for a dentry.  This is, of course, 
 * relative to the device.  The filename can be truncated to be as deep as
 * the deepest trustee.  The depth returned in d will always be the true
 * depth, however.
 *
 * Args:
 *   dentry: The dentry we are interested in.
 *   d: a pointer to the place where the depth can be stored.
 *   trunc: ok to truncate the name to the longest that needs to be figured out.
 */

#define FN_CHUNK_SIZE 64
char *trustees_filename_for_dentry(struct dentry *dentry, int *d, int trunc)
{
	char *buffer = NULL, *tmpbuf = NULL;
	int bufsize = FN_CHUNK_SIZE;
	char c;
	int i, j, k;
	int depth = 0;
	struct dentry *temp_dentry;

	if (dentry->d_parent == NULL) {
		TS_DEBUG_MSG("d_parent is null\n");
		return NULL;
	}

	if (dentry->d_name.name == NULL) {
		TS_DEBUG_MSG("name is null\n");
		return NULL;
	}

	buffer = kmalloc(FN_CHUNK_SIZE, GFP_KERNEL);
	if (!buffer) {
		TS_DEBUG_MSG("could not allocate filename buffer\n");
		return NULL;
	}

	buffer[0] = '/';
	buffer[i = 1] = '\0';
	for (temp_dentry = dentry; !IS_ROOT(temp_dentry); temp_dentry = temp_dentry->d_parent)
		depth++;
	if (d) *d = depth;
	if (deepest_level <= 0) return buffer;

	for (;;) {
		if (IS_ROOT(dentry))
			break;
		if (depth-- > deepest_level) continue;

		j = i + strlen(dentry->d_name.name);
		if ((j + 2) > bufsize) {	/* reallocate - won't fit */
			bufsize = (((j + 2) / FN_CHUNK_SIZE) + 1) * FN_CHUNK_SIZE;
			tmpbuf = kmalloc(bufsize, GFP_KERNEL);
			if (!tmpbuf) {
				kfree(buffer);
				TS_DEBUG_MSG
				    ("Out of memory allocating tmpbuf\n");
				return NULL;
			}
			memcpy(tmpbuf, buffer, i);
			kfree(buffer);
			buffer = tmpbuf;
		}
		/* Throw the name in there backward */
		for (k = 0; dentry->d_name.name[k]; k++) {
			buffer[j - 1 - k] = dentry->d_name.name[k];
		}
		i = j;
		buffer[i++] = '/';
		dentry = dentry->d_parent;
	}
	buffer[i] = 0;

	/* buffer is backwards, reverse it */
	for (j = 0; j < (i / 2); ++j) {
		c = buffer[j];
		buffer[j] = buffer[i - j - 1];
		buffer[i - j - 1] = c;
	}

	return buffer;
}

/*
 * Add a filesystem as a ignored-case dev.
 */
static inline void add_ic_dev(dev_t dev, char __user *devname)
{
	char *devname2;
	struct trustee_ic *ic;
	long dev_len = 0;

	if (devname)
		dev_len = strnlen_user(devname, PATH_MAX);

	if (dev_len > PATH_MAX) {
		TS_DEBUG_MSG("devname bad, add_ic_dev ignored.\n");
		return;
	}

	if (!dev_len) {
		TS_DEBUG_MSG("No devname specified in add_ic_dev.\n");
		return;
	}
	devname2 = kmalloc(dev_len + 1, GFP_KERNEL);
	if (!devname2) {
		TS_DEBUG_MSG
		    ("Seems that we have ran out of memory adding ic dev!\n");
		return;
	}
	if (strncpy_from_user(devname2, devname, dev_len) < 0) {
		TS_DEBUG_MSG
		  ("Something funky with devname in add_ic_dev\n");
		kfree(devname2);
		return;
	}

	ic = kmalloc(sizeof(struct trustee_ic), GFP_KERNEL);
	if (!ic) {
		TS_DEBUG_MSG
		    ("Seems that we ran out of memory allocating ic!");
		return;
	}

	ic->dev = dev;
	ic->devname = devname2;

	write_lock(&trustee_ic_lock);
	list_add(&ic->ic_list, &trustee_ic_list);
	write_unlock(&trustee_ic_lock);
}

/* 
 * Remove all ignored-case filesystems.
 */
static inline void remove_ic_devs(void)
{
	struct trustee_ic *ic, *temp_ic;
	struct list_head temp_ic_list;

	write_lock(&trustee_ic_lock);
	INIT_LIST_HEAD(&temp_ic_list);
	list_splice(&trustee_ic_list, &temp_ic_list);
	INIT_LIST_HEAD(&trustee_ic_list);
	write_unlock(&trustee_ic_lock);

	list_for_each_entry_safe(ic, temp_ic, &temp_ic_list, ic_list) {
		kfree(ic->devname);
		kfree(ic);
	}
}

/* 
 * This frees all the capsules in a trustee element.
 */
static inline void free_hash_element_list(struct trustee_hash_element *e)
{
	struct trustee_permission_capsule *capsule, *temp;

	list_for_each_entry_safe(capsule, temp, &e->perm_list, perm_list) {
		list_del(&capsule->perm_list);
		kfree(capsule);
	}
}

/*
 * Free a trustee name.  This frees the devname and the filename
 */
static inline void free_trustee_name(struct trustee_name *name)
{
	kfree(name->filename);
	kfree(name->devname);
}

/*
 * Frees the capsules, and the filenames for a trustee hash element.
 * Also marks it as unused in the hash.
 */
static inline void free_hash_element(struct trustee_hash_element *e)
{
	e->usage = TRUSTEE_HASH_ELEMENT_DELETED;
	free_hash_element_list(e);
	free_trustee_name(&e->name);
}


/* 
 * hashing function researched by Karl Nelson <kenelson @ ece ucdavis edu> 
 * and is used in glib. 
 */
static inline unsigned int hash_string(const char *s)
{
	unsigned int v = 0;

	while (*s) {
		v = (v << 5) - v + *s;
		s++;
	}

	return v;
}

/*
 * Return the hash for a device.
 */
static inline unsigned int hash_device(const char *name, dev_t device)
{
	if (MAJOR(device) == 0) {
		return hash_string(name);
	}
	
	return new_encode_dev(device);
}

/*
 * Return the hash for a file.  This is a combination of the
 * hash of the filename and the hash for the device.
 */
static inline unsigned int hash(const struct trustee_name *name)
{
	return hash_string(name->filename) ^ 
	       hash_device(name->devname, name->dev);
}

/*
 * Compare two devices.  Return 1 if they are equal otherwise return 0
 */
static inline int trustee_dev_cmp(dev_t dev1, dev_t dev2, char *devname1,
				  char *devname2)
{
	if ((MAJOR(dev1) == 0) && (MAJOR(dev2) == 0))
		return (strcmp(devname1, devname2) == 0);
	else if ((MAJOR(dev1) != 0) && (MAJOR(dev2) != 0))
		return (dev1 == dev2);
	return 0;
}

/*
 * Add a permission capsule to a trustee
 */
static inline void add_capsule_to_trustee(struct trustee_hash_element *e, 
					  struct trustee_permission acl)
{
	struct trustee_permission_capsule *capsule;
	capsule =
	    kmalloc(sizeof(struct trustee_permission_capsule),
		    GFP_KERNEL);
	if (!capsule) {
		TS_DEBUG_MSG
		    ("Can not allocate memory for trustee capsule\n");
		return;
	}

	capsule->permission = acl;

	write_lock(&trustee_hash_lock);
	list_add(&capsule->perm_list, &e->perm_list);
	write_unlock(&trustee_hash_lock);
}

  
/* 
 * Compare two trustee_name's.  Returns 1 if they are are equal
 * otherwise return 0
 */
static inline int trustee_name_cmp(const struct trustee_name *n1,
				   const struct trustee_name *n2)
{
	if (trustee_dev_cmp(n1->dev, n2->dev, n1->devname, n2->devname))
		return (strcmp(n1->filename, n2->filename) == 0);
	return 0;
}

/* 
 * Return the trustee element for a name.
 */
static struct trustee_hash_element *get_trustee_for_name(const struct
							 trustee_name
							 *name)
{

	unsigned int i;

	if (trustee_hash == NULL)
		return NULL;

	read_lock(&trustee_hash_lock);

	for (i = hash(name) % trustee_hash_size; trustee_hash[i].usage;
	     i = (i + 1) % trustee_hash_size) {
		if (trustee_hash[i].usage == 1)
			continue;
		if (trustee_name_cmp(&trustee_hash[i].name, name)) {
			read_unlock(&trustee_hash_lock);
			return trustee_hash + i;
		}
	}

	read_unlock(&trustee_hash_lock);

	return NULL;

}

/*
 * Calculate the deepest level.
 */
static inline void calculate_deepest_level(const struct trustee_name *name)
{
	char *fn = name->filename;
	char *x;
	int level = 0;

	for (x = fn; *x; ++x) {
		if (*x == '/')
			++level;
	}

	/* If it is the root, it should have
	 * a level of 0.
	 */
	if (x == (fn + 1)) level = 0;

	if (level > deepest_level) deepest_level = level;
}

/* This function does not allocate memory for filename and devname. 
 * It should be allocated at calling level 
 *
 * Return the trustee element for a name if it exists, otherwise
 * allocate a new element and add to the hash and return that.
 */
static struct trustee_hash_element *getallocate_trustee_for_name
    (const struct trustee_name *name, int *should_free) {
	struct trustee_hash_element *r, *n;
	unsigned int i, j, newsize;

	*should_free = 1;
	r = get_trustee_for_name(name);
	if (r != NULL)
		return r;

	if (trustee_hash == NULL) {
		TS_DEBUG_MSG("Building new trustee hash\n");

		down(&trustee_rebuild_hash_sem);
		n = kmalloc(sizeof(struct trustee_hash_element) *
		       TRUSTEE_INITIAL_HASH_SIZE, GFP_KERNEL);
		if (n == NULL) {

			TS_DEBUG_MSG
			    ("Can not allocate memory for trustee hash\n");

			up(&trustee_rebuild_hash_sem);
			return r;
		}
		write_lock(&trustee_hash_lock);
		trustee_hash = n;
		trustee_hash_size = TRUSTEE_INITIAL_HASH_SIZE;
		trustee_hash_used = 0;
		trustee_hash_deleted = 0;
		for (i = 0; i < trustee_hash_size; i++)
			trustee_hash[i].usage = TRUSTEE_HASH_ELEMENT_NOTUSED;
		write_unlock(&trustee_hash_lock);
		up(&trustee_rebuild_hash_sem);
	} else if ((trustee_hash_size * 3 / 4 < trustee_hash_used) || (trustee_hash_size - 2 < trustee_hash_used)) {	/*hash needed to be rebuilt, rebuilding hash */
		down(&trustee_rebuild_hash_sem);
		newsize =
		    (trustee_hash_deleted * 3) >
		    trustee_hash_size ? trustee_hash_size :
		    trustee_hash_size * 2;

		TS_DEBUG_MSG
		    ("Rebuilding trustee hash, oldsize: %d, newsize %d, deleted %d\n",
		     trustee_hash_size, newsize, trustee_hash_deleted);

		n = kmalloc(sizeof(struct trustee_hash_element) * newsize,
			    GFP_KERNEL);
		if (n == NULL) {

			TS_DEBUG_MSG
			    ("Can not allocate memory for trustee hash\n");
			up(&trustee_rebuild_hash_sem);
			return r;
		}
		for (i = 0; i < newsize; i++)
			n[i].usage = TRUSTEE_HASH_ELEMENT_NOTUSED;
		write_lock(&trustee_hash_lock);
		trustee_hash_used = 0;
		for (i = 0; i < trustee_hash_size; i++) {
			if (trustee_hash[i].usage == TRUSTEE_HASH_ELEMENT_USED) {
				for (j =
				     hash(&trustee_hash[i].name) % newsize;
				     n[j].usage; j = (j + 1) % newsize);
				n[j] = trustee_hash[i];
				trustee_hash_used++;
			}
		}
		kfree(trustee_hash);
		trustee_hash = n;
		trustee_hash_size = newsize;
		trustee_hash_deleted = 0;
		write_unlock(&trustee_hash_lock);
		up(&trustee_rebuild_hash_sem);
	}

	write_lock(&trustee_hash_lock);

	for (j = hash(name) % trustee_hash_size;
	     trustee_hash[j].usage == TRUSTEE_HASH_ELEMENT_USED; j = (j + 1) % trustee_hash_size);
	trustee_hash[j].name = *name;

	*should_free = 0;
	r = trustee_hash + j;
	INIT_LIST_HEAD(&r->perm_list);
	r->usage = TRUSTEE_HASH_ELEMENT_USED;
	calculate_deepest_level(name);

	trustee_hash_used++;

	write_unlock(&trustee_hash_lock);

	TS_DEBUG_MSG("Added element to trustee hash: j %d, name : %s\n", j,
		     r->name.filename);

	return r;
}

/*
 * Get the mask for a trustee name.
 */ 
static int get_trustee_mask_for_name(struct trustee_name *name,
				     int oldmask, int height, 
				     struct trustee_hash_element **element)
{
	struct trustee_hash_element *e;
	int m;
	struct trustee_permission_capsule *l;
	int appl;
	e = get_trustee_for_name(name);
	if (!e) {
		return oldmask;
	}
	list_for_each_entry(l, &e->perm_list, perm_list) {
		if ((height < 0)
		    && (l->permission.mask & TRUSTEE_ONE_LEVEL_MASK))
			continue;
		if (element) { 
			*element = e;
			element = NULL;
		}
		appl = ((!(l->permission.mask & TRUSTEE_IS_GROUP_MASK))
			&& (current->fsuid == l->permission.u.uid))
		    || (((l->permission.mask & TRUSTEE_IS_GROUP_MASK))
			&& (in_group_p(l->permission.u.gid)))
		    || (l->permission.mask & TRUSTEE_ALL_MASK);
		if (l->permission.mask & TRUSTEE_NOT_MASK)
			appl = !appl;

		if (!appl)
			continue;

		m = l->permission.mask & TRUSTEE_ACL_MASK;

		if (l->permission.mask & TRUSTEE_ALLOW_DENY_MASK)
			m <<= TRUSTEE_NUM_ACL_BITS;

		oldmask =
		    l->permission.
		    mask & TRUSTEE_CLEAR_SET_MASK ? (oldmask & (~m))
		    : (oldmask | m);
	}

	return oldmask;
}

/* 
 * Convert a string to lowercase for ignored-case devices
 */
static inline void str_to_lower(char *string)
{
	for (; *string; ++string) {
		if ((*string >= 'A') && (*string <= 'Z'))
			(*string) += 'a' - 'A';
	}
}

/* 
 * Return the mask for a file.
 */
int trustee_perm(struct dentry *dentry, struct vfsmount *mnt,
		 char *file_name, int unix_ret, int depth, int is_dir,
		 struct trustee_hash_element **deepest)
{
	static char dbl_nul_slash[3] = { '/', '\0', '\0' };
	int oldmask = trustee_default_acl;
	int height = 0;
	char *filecount;
	char c;
	struct trustee_name trustee_name;
	struct trustee_ic *iter;

	trustee_name.dev = mnt->mnt_sb->s_dev;
	trustee_name.devname = mnt->mnt_devname;
	trustee_name.filename = file_name;

	read_lock(&trustee_ic_lock);
	list_for_each_entry(iter, &trustee_ic_list, ic_list) {
		if (trustee_dev_cmp
		    (iter->dev, trustee_name.dev, iter->devname,
		     trustee_name.devname)) {
			str_to_lower(file_name);
			break;
		}
	}
	read_unlock(&trustee_ic_lock);

	if (deepest) *deepest = NULL;

	filecount = file_name + 1;
	/* Try to handle the unlikely case where the string will be '/' 
	 * out here to simplify the logic inside the loop.  We do this
	 * by giving it a string with two nul byte terminators so that it
	 * will gracefully (and safely) make it through the loop below.
	 */
	if (*filecount == '\0') {
		file_name = dbl_nul_slash;
		filecount = file_name + 1;
	}
	do {
		c = *filecount;
		*filecount = 0;
		oldmask =
		    get_trustee_mask_for_name(&trustee_name, oldmask,
					      height - depth + !is_dir, 
					      deepest);
		height++;
		*filecount = c;
		++filecount;
		while ((*filecount) && (*filecount != '/')) filecount++;

	} while(*filecount);

	return oldmask;
}

/* Clear out the hash of trustees and release the hash itself.
 * Also gets rid of the ignore-case list
 */
static void trustees_clear_all(void)
{
	int i;
	if (trustee_hash) {
		write_lock(&trustee_hash_lock);
		for (i = 0; i < trustee_hash_size; i++) {
			if (trustee_hash[i].usage == TRUSTEE_HASH_ELEMENT_USED)
				free_hash_element(&trustee_hash[i]);
		}
		kfree(trustee_hash);
		trustee_hash = NULL;
		deepest_level = 0;
		write_unlock(&trustee_hash_lock);
	}

	remove_ic_devs();
}

/*
 * Initialize globals
 */
int trustees_funcs_init_globals(void)
{
	trustees_clear_all();
	return 0;
}

/*
 * Clear globals
 */
int trustees_funcs_cleanup_globals(void)
{
	trustees_clear_all();
	return 0;
}

/*
 * Prepare a trustee name from a passed in trustee name.
 */
static int prepare_trustee_name(const struct trustee_command *command,
				struct trustee_name *name)
{
	long devl, filel;
	char *devb = NULL, *fileb = NULL;

	if ((!name) || (!command))
		return 0;

	filel = 0;
	if (command->filename)
		filel = strnlen_user(command->filename, PATH_MAX);

	devl = 0;
	if (command->devname)
		devl = strnlen_user(command->devname, PATH_MAX);

	if (devl > PATH_MAX) {
		TS_DEBUG_MSG("device name bad, command ignored.\n");
		return 0;
	}
	if (filel > PATH_MAX) {
		TS_DEBUG_MSG("file name bad, command ignored.\n");
		return 0;
	}

	if (devl) {
		devb = kmalloc(devl, GFP_KERNEL);
		if (!devb) {
			TS_DEBUG_MSG("Couldn't allocate mem for devb.\n");
			return 0;
		}

		if (strncpy_from_user(devb, command->devname, devl) < 0) {
			TS_DEBUG_MSG("garbled c.devname\n");
			kfree(devb);
			return 0;
		}
	}

	if (filel) {
		fileb = kmalloc(filel * sizeof(char), GFP_KERNEL);
		if (!fileb) {
			TS_DEBUG_MSG("Couldn't allocate mem for fileb.\n");
			kfree(devb);
			return 0;
		}

		if (strncpy_from_user(fileb, command->filename, filel) < 0) {
			TS_DEBUG_MSG("garbled c.filename\n");
			kfree(devb);
			kfree(fileb);
			return 0;
		}
	}

	name->devname = devb;
	name->filename = fileb;

	name->dev = new_decode_dev((u32) command->dev);

	return 1;
}

/* 
 * Process a user command
 */
int trustees_process_command(const struct trustee_command __user * command)
{
	int r = -ENOSYS;
	struct trustee_name name;
	struct trustee_hash_element *e;
	int should_free;
	struct trustee_command c;

	if (copy_from_user(&c, command, sizeof(struct trustee_command))) {
		r = -EIO;
		goto unlk;
	}

	if ((current->euid != 0) && !capable(CAP_SYS_ADMIN)) {
		r = -EACCES;
		goto unlk;
	}
	switch (c.command) {
	case TRUSTEE_COMMAND_MAKE_IC:
		r = 0;
		add_ic_dev(c.dev, c.devname);
		goto unlk;
	case TRUSTEE_COMMAND_REMOVE_ALL:
		r = 0;
		trustees_clear_all();
		goto unlk;
	case TRUSTEE_COMMAND_ADD:
		if (!prepare_trustee_name(&c, &name)) {
			r = -ENOMEM;
			goto unlk;
		}
		e = getallocate_trustee_for_name(&name, &should_free);
		if (e == NULL) {
			r = -ENOMEM;
			if (should_free)
				free_trustee_name(&name);
			goto unlk;
		}
		add_capsule_to_trustee(e, c.permission);

		r = 0;
		if (should_free)
			free_trustee_name(&name);
		goto unlk;

	}
      unlk:

	return r;
}
