/* 
 *  (c) 1999-2000 Vyacheslav Zavadsky
 *  GPLed
 */

#ifndef _LINUX_TRUSTEE_H
#define _LINUX_TRUSTEE_H
#include <linux/config.h>
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/trustee_struct.h>
#include <linux/kdev_t.h>







/* this function evaluates the trustee mask applicable to given name for given user. it is does not checks the trustees for parent and higher levels 

result & TRUSTEE_ACL_MASK - allow mask
(result >> TRUSTEE_NUM_ACL_BITS) & TRUSTEE_ACL_MASK - deny mask
old_mask - the same mask for higher level
*/
#define TRUSTEE_DEFAULT_MASK TRUSTEE_USE_UNIX_MASK


struct trustee_name {
  dev_t dev;
  char * filename;
  char * devname; /* ONLY if MAJOR(dev)==0 */
      


};


extern int  get_trustee_mask_for_name(const struct trustee_name * name,uid_t user,int oldmask,int height); 

extern int get_trustee_mask_for_dentry(struct dentry * dentry,uid_t user);

#define TRUSTEE_INITIAL_HASH_SIZE 4
#define TRUSTEE_INITIAL_NAME_BUFFER 256
#define TRUSTEE_HASDEVNAME(TNAME)  (major(to_kdev_t((TNAME).dev))==0)


/* name & permission are ignored if command=TRUSTEE_COMMAND_REMOVE_ALL */ 
/*  permission is ignored if command=TRUSTEE_COMMAND_REMOVE */ 



extern int sys_set_trustee(const struct trustee_command * c); 

/*#define TRUSTEE_DEBUG 1*/
#define TRUSTEE_DEBUG_USER 500
#endif















