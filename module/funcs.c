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

#include "trustees.h"
#include "trustees_private.h"

DECLARE_RWSEM(trustees_hash_sem);

struct permission_capsule {
	struct pemission_capsule * next;
	struct trustee_permission permission;
};
struct trustee_hash_element {
	int usage; /* 0 -unused, 1- deleted, 2 - used */
	struct trustee_name  name;
	struct permission_capsule * list;
};

static struct trustee_hash_element *trustee_hash = NULL;
static int trustee_hash_size = 0, trustee_hash_used = 0, trustee_hash_deleted = 0;


#define FN_CHUNK_SIZE 50

#define FN_DEBUG(_x) 
#ifdef TRUSTEES_DEBUG
#undef FN_DEBUG
#define FN_DEBUG(_x) printk(KERN_DEBUG _x);
#endif

// The calling method needs to free the buffer created by this function
// This method returns the filename for a dentry.  This is, of course, 
// relative to the device.
char *trustees_filename_for_dentry(struct dentry *dentry, int *d) {
	char *buffer = NULL, *tmpbuf = NULL;
	int bufsize = FN_CHUNK_SIZE;
	char c;
	int i, j, k;
	int depth = 0;

	if (!dentry) {
		FN_DEBUG("dentry nil\n");
		return NULL;
	}

	if (dentry->d_parent==NULL) {
		FN_DEBUG("d_parent is null\n");
		return NULL;
	}
	
	if (dentry->d_name.name==NULL) {
		FN_DEBUG("name is null\n");
		return NULL;
	}

	buffer = kmalloc(FN_CHUNK_SIZE, GFP_KERNEL);
	if (!buffer) {
		FN_DEBUG("could not allocate filename buffer\n");
		return NULL;
	}

	buffer[0] = '/';
	buffer[i = 1] = '\0';
	
	for (;;) {
		if (IS_ROOT(dentry)) break;
		
		j = i + strlen(dentry->d_name.name);
		if ((j + 1) >= bufsize) { /* reallocate - won't fit */
			bufsize = (j + 1) + FN_CHUNK_SIZE;
			tmpbuf = kmalloc(bufsize, GFP_KERNEL);
			if (!tmpbuf) {
				kfree(buffer);
				FN_DEBUG("Out of memory allocating tmpbuf\n");
				return NULL;
			}
			strcpy(tmpbuf, buffer);
			kfree(buffer);
			buffer = tmpbuf;
		}

		// Throw the name in there backward
		for (k = 0; dentry->d_name.name[k]; k++) {
			buffer[j - 1 - k] = dentry->d_name.name[k];
		}
		i = j;
		depth++;
		buffer[i++] = '/';
		dentry = dentry->d_parent;
	}
  	buffer[i]=0;

	// buffer is backwards, reverse it
	for (j = 0; j < (i / 2); j++) {
		c = buffer[j];
		buffer[j] = buffer[i - j - 1];
		buffer[i - j - 1] = c;
	}

	if (d) *d = depth;
	
	return buffer;
}


static inline void free_hash_element_list(struct trustee_hash_element e) {
	struct permission_capsule *l1, *l2;
	l1 = e.list;
	while (l1 != NULL) {
		l2 = l1;
		l1 = (void *)l1->next;
		kfree(l2);
	}
	e.list = NULL;
}

static inline void free_trustee_name(struct trustee_name *name) {
	kfree(name->filename);
	if (TRUSTEES_HASDEVNAME(*name)) {
		kfree(name->devname);
	}
} 

static inline void free_hash_element(struct trustee_hash_element e) {
	e.usage = 1;
	free_hash_element_list(e);
	free_trustee_name(&e.name);
}


/* hashing function researched by Karl Nelson <kenelson @ ece ucdavis edu> 
 * and is used in glib. */
static inline unsigned int hash_string(const char *s) {
	unsigned int v = 0;
	
	while (*s) {
		v = (v << 5) - v + *s;
	}

	return v;
}

static inline unsigned int hash(const struct trustee_name *name) {
	unsigned int v = hash_string(name->filename);
	
	if (TRUSTEES_HASDEVNAME(*name)) {
		v ^= hash_string(name->devname);
	} else {
		v^= new_encode_dev(name->dev);
	}

	return v;
} 

static inline int trustee_name_cmp(const struct trustee_name *n1, 
                                   const struct trustee_name *n2) {
	if (TRUSTEES_HASDEVNAME(*n1) && TRUSTEES_HASDEVNAME(*n2)) 
		return ((strcmp(n1->devname, n2->devname) == 0) && 
		       (strcmp(n1->filename, n2->filename) == 0));
	else if ((!TRUSTEES_HASDEVNAME(*n1)) && (!TRUSTEES_HASDEVNAME(*n2))) 
		return ((new_encode_dev(n1->dev) == new_encode_dev(n2->dev)) && 
		       (strcmp(n1->filename, n2->filename) == 0));
	return 0;
}

static struct trustee_hash_element *get_trustee_for_name(
    const struct trustee_name *name) {

	unsigned int i;

	if (trustee_hash == NULL) return NULL;

	down_read(&trustees_hash_sem);

	for (i = hash(name) % trustee_hash_size; trustee_hash[i].usage; i = (i + 1) % trustee_hash_size) {
		if (trustee_hash[i].usage == 1) continue;
		if (trustee_name_cmp(&trustee_hash[i].name, name)) {
			up_read(&trustees_hash_sem);
			return trustee_hash + i;
		}
	}

	up_read(&trustees_hash_sem);

	return NULL;

}

/* This function does not allocate memory for filename and devname. It should be allocated at calling level */
static struct trustee_hash_element *getallocate_trustee_for_name
   (const struct trustee_name  * name, int * should_free) {
	struct trustee_hash_element  * r,*n;
	unsigned int i,j,newsize;

	*should_free=1;
	r = get_trustee_for_name(name);
	if (r!=NULL) return r;

	if (trustee_hash==NULL){
#ifdef TRUSTEES_DEBUG
		printk("Building new trustee hash\n");
#endif
		down_write(&trustees_hash_sem);
		trustee_hash=kmalloc(sizeof(struct trustee_hash_element)*TRUSTEES_INITIAL_HASH_SIZE, GFP_KERNEL);
		if (trustee_hash==NULL) {
#ifdef TRUSTEES_DEBUG
			printk("Can not allocate memory for trustee hash\n");
#endif
			up_write(&trustees_hash_sem);
			return r;
		}
		trustee_hash_size=TRUSTEES_INITIAL_HASH_SIZE;
		trustee_hash_used=0;
		trustee_hash_deleted=0;
		printk("Blah2\n");
		for (i=0;i<trustee_hash_size;i++) trustee_hash[i].usage=0;
		printk("Blah3\n");
		up_write(&trustees_hash_sem);
	}
	else if ((trustee_hash_size*3/4<trustee_hash_used) || (trustee_hash_size-2<trustee_hash_used)) { /*hash needed to be rebuilt, rebuilding hash */
		down_write(&trustees_hash_sem);
		newsize=(trustee_hash_deleted*3)>trustee_hash_size?trustee_hash_size:trustee_hash_size*2;
#ifdef TRUSTEES_DEBUG
		printk("Rebuilding trustee hash, oldsize: %d, newsize %d, deleted %d\n",trustee_hash_size,newsize, trustee_hash_deleted);
#endif
		n=kmalloc(sizeof(struct trustee_hash_element)*newsize, GFP_KERNEL);
		if (n==NULL) {
#ifdef TRUSTEES_DEBUG
			printk("Can not allocate memory for trustee hash\n");
#endif
			up_write(&trustees_hash_sem);
			return r;
		}
		for (i=0;i<newsize;i++) n[i].usage=0;
		trustee_hash_used=0;
		for (i=0;i<trustee_hash_size;i++) {
			if (trustee_hash[i].usage==2) {
				for (j=hash(&trustee_hash[i].name)%newsize;n[j].usage;j=(j+1)%newsize);
				n[j]=trustee_hash[i];
				trustee_hash_used++;
			}
		}
		kfree(trustee_hash);
		trustee_hash=n;
		trustee_hash_size=newsize;
		trustee_hash_deleted=0;
		up_write(&trustees_hash_sem);
	}
	printk("Blah1\n");
	down_read(&trustees_hash_sem);
	printk("Blah1.1\n");

	for (j=hash(name)%trustee_hash_size;trustee_hash[j].usage==2;j=(j+1)%trustee_hash_size);
	printk("Blah1.2\n");
	trustee_hash[j].name=*name;
	*should_free=0;
	r=trustee_hash+j;
	r->list=NULL;
	r->usage=2;
#ifdef TRUSTEES_DEBUG
	printk("Added element to trustee hash: j %d, name : %s\n",j,r->name.filename);
#endif
	trustee_hash_used++;
	up_read(&trustees_hash_sem);
	
	return r;
}

int get_trustee_mask_for_name(struct trustee_name *name, int oldmask, int height) {
	struct trustee_hash_element *e;
	int m;
	struct permission_capsule *l;
	int appl;
	e = get_trustee_for_name(name);
	if (!e) {
		return oldmask;
	}
	for (l = e->list; l != NULL; l = (void*)l->next) {
		if ((height < 0) && (l->permission.mask & TRUSTEE_ONE_LEVEL_MASK)) 
			continue;
		appl=((!(l->permission.mask & TRUSTEE_IS_GROUP_MASK)) && (current->fsuid==l->permission.u.uid)) 
		    ||
		    (((l->permission.mask & TRUSTEE_IS_GROUP_MASK)) && (in_group_p(l->permission.u.gid)))
		    ||
		    (l->permission.mask & TRUSTEE_ALL_MASK);
		if (l->permission.mask & TRUSTEE_NOT_MASK) appl = !appl;

		if (!appl) 
			continue;

		m = l->permission.mask & TRUSTEE_ACL_MASK;

		if (l->permission.mask & TRUSTEE_ALLOW_DENY_MASK) m <<= TRUSTEE_NUM_ACL_BITS;

		oldmask = l->permission.mask & TRUSTEE_CLEAR_SET_MASK ? (oldmask & (~m)) : (oldmask | m);
	}

	return oldmask;
}

int trustee_perm(
  struct dentry *dentry, struct vfsmount *mnt,
  char *file_name, int unix_ret, int depth, int is_dir) {
	int oldmask = trustee_default_acl;
	int height = 0;
	char *filecount;
	struct trustee_name trustee_name;

	trustee_name.dev = mnt->mnt_sb->s_dev;
	trustee_name.devname = mnt->mnt_devname;
	trustee_name.filename = file_name;

	filecount = file_name + 1;
	for (;;) {
		*filecount = 0;
		oldmask = 
		   get_trustee_mask_for_name(&trustee_name, oldmask, height - depth + !is_dir);
		height++;
		*filecount = '/';
		for (filecount++;  *filecount && (*filecount != '/'); *filecount++);
		if (!*filecount) break;
	}

	return oldmask;
}
	
	
	
static int prepare_trustee_name(const struct trustee_command * c, struct trustee_name * name) {
	 name->dev=c->dev;
	 name->filename=kmalloc((strlen(c->filename)+1)*sizeof(char),GFP_KERNEL);
		if (!name->filename) {
			printk("No memory to allocate for temporary name buffer");
			return 0;
		}
	 copy_from_user(name->filename,c->filename,(strlen(c->filename)+1)*sizeof(char));
		
	 if (TRUSTEES_HASDEVNAME(*name)) {
		 name->devname=kmalloc((strlen(c->devname)+1)*sizeof(char),GFP_KERNEL);
		 if (!name->devname) {
			printk("No memory to allocate for temporary device buffer");
			kfree(name->filename);

			return 0;
		}
		copy_from_user(name->devname,c->devname,(strlen(c->devname)+1)*sizeof(char)); 
	 }
	 return 1;
}

int trustees_process_command(const struct trustee_command * command) {
	int r=-ENOSYS, i;
	struct trustee_name name;
	struct trustee_hash_element * e;
	struct permission_capsule * capsule;
	int should_free;
	struct trustee_command c;
	copy_from_user(&c,command,sizeof(c));
#ifdef TRUSTEES_DEBUG
	printk("set trustee called, command %d\n", c.command);
#endif
	if ((current->euid!=0) && !capable(CAP_SYS_ADMIN)) return -EACCES;
	switch (c.command) {
	case TRUSTEE_COMMAND_REMOVE_ALL :
		r=0;
		if (trustee_hash==NULL) goto unlk;
		down_write(&trustees_hash_sem);
		for (i=0;i<trustee_hash_size;i++) {
			if (trustee_hash[i].usage==2) free_hash_element(trustee_hash[i]);
		}
		kfree(trustee_hash);
		trustee_hash=NULL;
		up_write(&trustees_hash_sem);
		goto unlk;
	case TRUSTEE_COMMAND_REMOVE:
		if (!prepare_trustee_name(&c,&name)) {
		  r=-ENOMEM;
		  goto unlk;
		}
		e=get_trustee_for_name(&name);
		if (e==NULL) {
			r=-ENOENT;
			free_trustee_name(&name);
			goto unlk;
		}
		free_hash_element(*e);
		trustee_hash_deleted++;
		free_trustee_name(&name);
		r=0;
		goto unlk;
	case TRUSTEE_COMMAND_REPLACE:
		if (!prepare_trustee_name(&c,&name)) {
		  r=-ENOMEM;
		  goto unlk;
		}
			
		e=getallocate_trustee_for_name(&name,&should_free);
		if (e==NULL) {
			r=-ENOMEM;
			if (should_free) free_trustee_name(&name);
			goto unlk;
		}
		free_hash_element_list(*e);
		capsule=kmalloc(sizeof(struct permission_capsule),GFP_KERNEL);
		capsule->permission=c.permission;
		capsule->next=(void*)e->list;
		e->list=capsule;
		r=0;
		if (should_free) free_trustee_name(&name);
		     
		goto unlk;
		
	case TRUSTEE_COMMAND_ADD:
		printk("Blah7\n");
		if (!prepare_trustee_name(&c,&name)) {
		  r=-ENOMEM;
		  goto unlk;
		}
		e=getallocate_trustee_for_name(&name,&should_free);
		if (e==NULL) {
			r=-ENOMEM;
			if (should_free) free_trustee_name(&name);
			goto unlk;
		}
		
		capsule=kmalloc(sizeof(struct permission_capsule),GFP_KERNEL);
		capsule->permission=c.permission;
		capsule->next=(void*)e->list;
		e->list=capsule;
		r=0;
		if (should_free) free_trustee_name(&name);
		goto unlk;
		
		
	}	
 unlk:

	printk("Returning %d from set trustee func\n", r);
	return r;
}





