/* 
 *  (c) 1999-2000 Vyacheslav Zavadsky
 */

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/trustee.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/limits.h>

struct permission_capsule {
	struct pemission_capsule * next;
	struct trustee_permission permission;
};
struct trustee_hash_element {
	int usage; /* 0 -unused, 1- deleted, 2 - used */
	struct trustee_name  name;
	struct permission_capsule * list;

};
static struct trustee_hash_element * trustee_hash=NULL;
static int trustee_hash_size=0, trustee_hash_used=0, trustee_hash_deleted=0;


static inline void free_hash_element_list(struct trustee_hash_element  e) {
	struct permission_capsule * l1, *l2;
	l1=e.list;
	while (l1!=NULL) {
		l2=l1;
		l1=(void*) l1->next;
		kfree(l2);
	}
	e.list=NULL;
       
}


static inline void free_trustee_name(struct trustee_name * name) {
        kfree(name->filename);
	if (TRUSTEE_HASDEVNAME(*name)) {
	  kfree(name->devname);
	}

} 



static inline void free_hash_element(struct trustee_hash_element  e) {
	e.usage=1;
	free_hash_element_list(e);
	free_trustee_name(&e.name);
	
       
}

static inline unsigned int hash_string(const char * s) {
	unsigned int v=1;
        while (*s) {
 
		v = (v << 2) | (v >> (4*sizeof(v)-2));
		v = (v+(*s))^(*s);
		s++;
	}
	return v;

}

static inline unsigned int hash(const struct trustee_name * name ) {
         unsigned int v=hash_string(name->filename);
	 if (TRUSTEE_HASDEVNAME(*name)) {
  	       v^=hash_string(name->devname);
	 } else {
	   v^= kdev_val(to_kdev_t(name->dev));
	 }

	 return v;
} 

static inline int trustee_name_cmp(const struct  trustee_name * n1, const struct  trustee_name * n2) {
       if (TRUSTEE_HASDEVNAME(*n1) && TRUSTEE_HASDEVNAME(*n2)) 
	 return (strcmp(n1->devname,n2->devname)==0) &&  (strcmp(n1->filename,n2->filename)==0);
       else  if ((!TRUSTEE_HASDEVNAME(*n1)) && (!TRUSTEE_HASDEVNAME(*n2))) 
	 return (( kdev_val (to_kdev_t(n1->dev))== kdev_val(to_kdev_t(n2->dev))) && (strcmp(n1->filename,n2->filename)==0));
       return 0;

}


static struct trustee_hash_element  * get_trustee_for_name(const struct trustee_name  * name) {
	unsigned int i;
	if (trustee_hash==NULL) return NULL;
	for (i=hash(name)%trustee_hash_size;trustee_hash[i].usage;i=(i+1)%trustee_hash_size) {
		if (trustee_hash[i].usage==1) continue;
		#ifdef TRUSTEE_DEBUG
		printk("Comparing in  get_trustee_for_name %s, dev %x i is %d", name->filename,(int)name->dev,i);
		printk(" to %s\n",to_kdev_t(trustee_hash[i].name).filename);
		#endif
		if (trustee_name_cmp(&trustee_hash[i].name,name)) return trustee_hash+i;
	}
	return NULL;

}

/* This function does not allocate memory for filename and devname. It should be allocated at calling level */
static struct trustee_hash_element  * getallocate_trustee_for_name(const struct trustee_name  * name, int * should_free) {

	struct trustee_hash_element  * r,*n;
	unsigned int i,j,newsize;
	

	lock_kernel();
	*should_free=1;
	r=get_trustee_for_name(name);
	if (r!=NULL) goto unlock_exit;

	if (trustee_hash==NULL){
#ifdef TRUSTEE_DEBUG
		printk("Building new trustee hash\n");
#endif
		trustee_hash=kmalloc(sizeof(struct trustee_hash_element)*TRUSTEE_INITIAL_HASH_SIZE, GFP_KERNEL);
		if (trustee_hash==NULL) {
#ifdef TRUSTEE_DEBUG
			printk("Can not allocate memory for trustee hash\n");
#endif
			goto unlock_exit;
		}
		trustee_hash_size=TRUSTEE_INITIAL_HASH_SIZE;
		trustee_hash_used=0;
		trustee_hash_deleted=0;
		for (i=0;i<trustee_hash_size;i++) trustee_hash[i].usage=0;
	}
	
	if ((trustee_hash_size*3/4<trustee_hash_used) || (trustee_hash_size-2<trustee_hash_used)) { /*hash needed to be rebuilt, rebuilding hash */
		newsize=(trustee_hash_deleted*3)>trustee_hash_size?trustee_hash_size:trustee_hash_size*2;
#ifdef TRUSTEE_DEBUG
		printk("Rebuilding trustee hash, oldsize: %d, newsize %d, deleted %d\n",trustee_hash_size,newsize, trustee_hash_deleted);
#endif
		n=kmalloc(sizeof(struct trustee_hash_element)*newsize, GFP_KERNEL);
		if (n==NULL) {
#ifdef TRUSTEE_DEBUG
			printk("Can not allocate memory for trustee hash\n");
#endif
			goto unlock_exit;
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
				
		
			
	}
	for (j=hash(name)%trustee_hash_size;trustee_hash[j].usage==2;j=(j+1)%trustee_hash_size);
	trustee_hash[j].name=*name;
	*should_free=0;
	r=trustee_hash+j;
	r->list=NULL;
	r->usage=2;
#ifdef TRUSTEE_DEBUG
	printk("Added element to trustee hash: j %d, name : %s\n",j,r->name.filename);
#endif
	trustee_hash_used++;
	
	
 unlock_exit:
	unlock_kernel();
	return r;
	

}

int  get_trustee_mask_for_name( const struct trustee_name * name,uid_t user,int oldmask,int height)
{
	struct trustee_hash_element * e;
	int m;
	struct permission_capsule * l;
	int appl;
#ifdef TRUSTEE_DEBUG
	printk("getting trustee mask for %s ", name->filename);
#endif
	e=get_trustee_for_name(name);
	if (e==NULL) {
#ifdef TRUSTEE_DEBUG
		printk("Not found, returning old trustee, %x\n",oldmask);
#endif
		return oldmask;
	}
	for (l=e->list;l!=NULL;l=(void*) l->next) {
		if ((height<0) && (l->permission.mask & TRUSTEE_ONE_LEVEL_MASK)) continue;
		appl=((!(l->permission.mask & TRUSTEE_IS_GROUP_MASK)) && (current->fsuid==l->permission.u.uid)) 
		    ||
		    (((l->permission.mask & TRUSTEE_IS_GROUP_MASK)) && (in_group_p(l->permission.u.gid)))
		    ||
		    (l->permission.mask & TRUSTEE_ALL_MASK);
		if (l->permission.mask & TRUSTEE_NOT_MASK) appl=!appl;
		if (!appl) continue;
		m=l->permission.mask & TRUSTEE_ACL_MASK;
#ifdef TRUSTEE_DEBUG
		printk("Found a suitable trustee, mask %x",l->permission.mask);
#endif
		if (l->permission.mask & TRUSTEE_ALLOW_DENY_MASK) m <<= TRUSTEE_NUM_ACL_BITS;
		oldmask=l->permission.mask & TRUSTEE_CLEAR_SET_MASK? oldmask & (~m):oldmask | m;

	}
#ifdef TRUSTEE_DEBUG
	printk("The new trustee mask is %x\n",oldmask);
#endif
	return oldmask;
	
}

int get_trustee_mask_for_dentry(struct dentry * dentry,uid_t user) {
  int oldmask=trustee_default_acl;
  char * namebuffer, * buf2;
  int i,j,k;
  char c;
  int   bufsize;
  int   slashes=1;
  int   slash=1;
  struct trustee_name name;
  int isdir=S_ISDIR(dentry->d_inode->i_mode);
#ifdef  TRUSTEE_DEBUG
  if (user!= TRUSTEE_DEBUG_USER) return trustee_default_acl;
#endif
  /* debug */ if (dentry->d_parent==NULL) {
#ifdef TRUSTEE_DEBUG
    printk("d_parent  is null");
#endif
    return trustee_default_acl;
  }
  /* debug */ if (dentry->d_name.name==NULL) {
#ifdef TRUSTEE_DEBUG
    printk("name is null");
#endif
    return trustee_default_acl;
  }
  namebuffer=kmalloc(TRUSTEE_INITIAL_NAME_BUFFER,GFP_KERNEL);
  if (!namebuffer) return trustee_default_acl;
  bufsize=TRUSTEE_INITIAL_NAME_BUFFER;
  *namebuffer='/';
  namebuffer[1]=0;
  i=1;
  for (;;) {
    if (IS_ROOT(dentry)) break;
    j=i+strlen(dentry->d_name.name);
    if (j+1>=bufsize) { /*reallocating the buffer*/
      while  (j+1>=bufsize) bufsize*=2;
      buf2=kmalloc(bufsize,GFP_KERNEL);
      if (!buf2) {
        kfree(namebuffer);
        return trustee_default_acl;
      }
      strcpy(buf2,namebuffer);
      kfree(namebuffer);
	    namebuffer=buf2;
	
    }
    for (k=0;dentry->d_name.name[k];k++) 
      namebuffer[j-1-k]=dentry->d_name.name[k];
    i=j;
    namebuffer[i++]='/';
    slashes++;
    dentry=dentry->d_parent;
  }
  namebuffer[i]=0;
  //
  // The path is found, reversing the buffer
  //
  for (j=0;j<i/2;j++) {
    c=namebuffer[j];
    namebuffer[j]=namebuffer[i-j-1];
	  namebuffer[i-j-1]=c;
  }

  name.filename=namebuffer;
  name.dev=dentry->d_sb->s_dev;
  name.devname=NULL;
  
  j=1;
  for (;;) {
    c=namebuffer[j];
    namebuffer[j]=0;
    if (TRUSTEE_HASDEVNAME(name)) {
	     name.devname=dentry->d_sb->dev_name;
	     oldmask=get_trustee_mask_for_name(&name,user,oldmask,slash-slashes+!isdir);
    } else 
      oldmask=get_trustee_mask_for_name(&name,user,oldmask,slash-slashes+!isdir);
    slash++;
    namebuffer[j]=c;
    for (j++;(j<i) && (namebuffer[j]!='/');j++) ;
    if (j>=i) break;
  }
  kfree(namebuffer);   
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
		
	 if (TRUSTEE_HASDEVNAME(*name)) {
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
asmlinkage int sys_set_trustee(const struct trustee_command * command) {
	int r=-ENOSYS, i;
	struct trustee_name name;
	struct trustee_hash_element * e;
	struct permission_capsule * capsule;
	int should_free;
        struct trustee_command c;
	copy_from_user(&c,command,sizeof(c));
#ifdef TRUSTEE_DEBUG
	printk("set trustee called, command %d", c.command);
#endif
	if ((current->euid!=0) && !capable(CAP_SYS_ADMIN)) return -EACCES;
	lock_kernel();
	switch (c.command) {
	case TRUSTEE_COMMAND_REMOVE_ALL :
		r=0;
		if (trustee_hash==NULL) goto unlk;
		for (i=0;i<trustee_hash_size;i++) {
			if (trustee_hash[i].usage==2) free_hash_element(trustee_hash[i]);
		}
		kfree(trustee_hash);
		trustee_hash=NULL;
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
	unlock_kernel();
	return r;
}



















