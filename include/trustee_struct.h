/* 
 *  (c) 1999-2000 Vyacheslav Zavadsky
 */

#ifndef _LINUX_TRUSTEE_STRUCT_H

#define _LINUX_TRUSTEE_STRUCT_H
#include <linux/types.h>



#define TRUSTEE_EXECUTE_BIT 0
#define TRUSTEE_READ_BIT 1
#define TRUSTEE_WRITE_BIT 2
#define TRUSTEE_BROWSE_BIT 3
#define TRUSTEE_READ_DIR_BIT 4
#define TRUSTEE_USE_UNIX_BIT 5
#define TRUSTEE_NUM_ACL_BITS (TRUSTEE_USE_UNIX_BIT+1)
#define TRUSTEE_EXECUTE_MASK (1 <<  TRUSTEE_EXECUTE_BIT)
#define TRUSTEE_READ_MASK (1 <<  TRUSTEE_READ_BIT)
#define TRUSTEE_WRITE_MASK (1 <<  TRUSTEE_WRITE_BIT)
#define TRUSTEE_BROWSE_MASK (1 <<  TRUSTEE_BROWSE_BIT)
#define TRUSTEE_READ_DIR_MASK (1 <<  TRUSTEE_READ_DIR_BIT)
#define TRUSTEE_USE_UNIX_MASK (1 <<  TRUSTEE_USE_UNIX_BIT)
#define TRUSTEE_ACL_MASK ((1 << TRUSTEE_NUM_ACL_BITS)-1)

#define TRUSTEE_ALLOW_DENY_BIT 7
#define TRUSTEE_IS_GROUP_BIT 6
#define TRUSTEE_CLEAR_SET_BIT 8
#define TRUSTEE_ONE_LEVEL_BIT 9
#define TRUSTEE_NOT_BIT 10
#define TRUSTEE_ALL_BIT 11
#define TRUSTEE_ALLOW_DENY_MASK (1 <<  TRUSTEE_ALLOW_DENY_BIT) /* set if deny */
#define TRUSTEE_IS_GROUP_MASK (1 <<  TRUSTEE_IS_GROUP_BIT)
#define TRUSTEE_CLEAR_SET_MASK (1 <<  TRUSTEE_CLEAR_SET_BIT) /* set if clear */
#define TRUSTEE_ONE_LEVEL_MASK (1 <<  TRUSTEE_ONE_LEVEL_BIT) 
#define TRUSTEE_NOT_MASK (1 <<  TRUSTEE_NOT_BIT)
#define TRUSTEE_ALL_MASK (1 <<  TRUSTEE_ALL_BIT)

#define trustee_acl __u16
#define trustee_default_acl TRUSTEE_USE_UNIX_MASK 




struct trustee_permission {
  	trustee_acl mask;
	union {
		__kernel_uid_t uid;
		__kernel_gid_t gid;
	}  u;
};



struct trustee_command {
  int command;
  struct trustee_permission  permission;
  int dev;
  char * filename;
  char * devname;
};




#define TRUSTEE_COMMAND_ADD 1
#define TRUSTEE_COMMAND_REPLACE 2
#define TRUSTEE_COMMAND_REMOVE_ALL 3
#define TRUSTEE_COMMAND_REMOVE 4

#endif













