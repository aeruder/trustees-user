#include <syscall.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <linux/trustee_struct.h> 
#include <linux/limits.h>
#include <grp.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <fcntl.h>

int syscall_number;
int set_trustee(const struct trustee_command * command)
{
    int procfd;
    if (syscall_number) return syscall(syscall_number,command);
    /* syscall_number==0 means to use /proc/trustee/syscall for write */
    procfd = open ("/proc/trustee/syscall",O_WRONLY);
    if (procfd < 0) return errno;
    if (write (procfd,command,sizeof(*command)) != sizeof(*command))
      return errno;
    close (procfd);
    return 0;
}
 
void print_exit(void) {

	printf("Usage: settrustee <options>\n");
	printf("Options:\n");
	printf("        -f <trustee info file name> see fromat below. Default /etc/trustee.conf.\n");
	printf("        -s  <syscall> use syscall\n");
	printf("        -D  delete all trustees from the kernel and exit\n");
	printf("        -d  delete all trustees from the kernel before processing the trustees in the file\n");
	printf("        -p prefix to file names\n");
	printf("File format:\n");
	printf("A set of string like:\n");
	printf("[block_device_name]/path/path:user_name:DCRWBE:+group_name:OtherChars\n");
	printf("{network_name}/path/path:user_name:DCRWBE:+group_name:OtherChars\n");
	
	printf("The string is started from the file (or directory) name. Double // is not allowed\n");
	printf("The next field is user name (* means everybody) or + followed by group name\n");
	printf("The next field is trustee mask. Possible chars DCRWBEUX mean:\n");
	printf("      R  - Read files permission\n");
	printf("      W  - Write permission\n");
	printf("      B  - Browse (like execute permission for directories)\n");
	printf("      E  - rEad diriectories\n");
	printf("      X  - eXecute (files, granted only if owner can execute the file\n");
	printf("      U  - use Unix permission system (set as default for /)");
	printf("      D  - deny the permissions in mask\n");
	printf("      C  - clear the permissions in mask\n");
	printf("      O  - only the directory and files in it (not subdirectories) affected by the trustee\n");
	printf("      !  - All except user (group) affected by the trustee\n");

	printf(" The access to a file ( directory) calculated on the following manner: the to masks - the first one for allow permission and the second one for deny. The first initially equals to [U], the second - to []. The path to the file (real path, not symbolic link) is analazied from the root directorry. If applicablee trustee is found, the approciate mask is ORed (or & ~(trustee mask) if C is set) to the mask in trustee. Access: given to superusers. Denied if deny flag set for at least one of the modes requested. Allowed if U flag is set, deny U flag is not set and unix permission is allow the access. Allow if all flags for requested mode are set. Denied otherwise. Known limitations: trustee system do not affect ioctl calls.");
	exit(-1);

	
}
static void do_syscall(const struct trustee_command * command) {
  int r;
  /*  printf("Doing syscall for %s, dev is %x\n",command->filename,command->dev);
      if (!command->dev) {printf("devname is %s\n",command->devname);}*/
	r=set_trustee(command);
	if (r) {
		fprintf(stderr,"Can not do syscall for %s, code %x, reason %s\n",command->filename,r,strerror(errno));
	}
}

int main(int argc, char * argv[])
{
	
	char * filename="/etc/trustee.conf", * prefix="";
	int i,j;
	char c;
	int flush=0;
	int exitafterflush=0;
	FILE * f;
	char name[PATH_MAX+NAME_MAX]="";
	struct trustee_command command;
	char s[32000];
	char  devname[PATH_MAX+NAME_MAX];
	char * olds, *n;
	struct group * g;
	struct passwd * pw; 
	int isstdin=0;
	struct stat st;
  
	command.filename=name;
	command.devname=devname;

	while ((j=getopt(argc,argv,"s:f:dDp:"))!=EOF) {
		switch (j) {
		case '?': 
			print_exit();
		case 'd' : 
			flush=1;
			break;
		case 'D':
			flush=1;
			exitafterflush=1;
			break;
		case 'f':
			filename=strdup(optarg);
			break;
		case 's':
			syscall_number=atoi(optarg);
		case 'p':
			prefix=strdup(optarg);
			break;
		}


	}

	f = fopen("/proc/trustee/syscall","r");

	if (f==NULL)
	{
		if (!syscall_number)
		{
			printf("use -s <syscall> to set trustees syscall number.\n");
			exit(-1);
		}
	} else {
		if (fgets(s,40,f)) syscall_number=atoi(s);
		fclose(f);
	}
	fprintf(stderr,"using syscall no %d\n",syscall_number);

	if (!exitafterflush) {
		isstdin=!strcmp(filename,"-");
		if (isstdin) f=stdin; else {
			f=fopen(filename,"r");
			if (f==NULL) {
				printf("Can not read file %s, reason %s\n", filename, strerror(errno));
				exit(-1);
			}
		}
	}
	
	if (flush) {
	  command.command=TRUSTEE_COMMAND_REMOVE_ALL;
	  do_syscall(&command);
	}
	if (exitafterflush) exit(0);
	i=strlen(prefix);
	if ((i>0) && (prefix[i-1]=='/')) prefix[i-1]=0;
	while (fgets(s,32000,f)!=NULL) {
		i=strlen(s);
		if (i==0) continue;
		if (s[0]=='#') continue;
		if (s[i-1]=='\n') s[i-1]=0;
		if (strlen(s)==0) continue;
		if (*s=='[') {
		  /*block device */;
		  for (olds=s+1;(*olds!=']') && *olds;olds++);
		  if (!*olds) {
		    printf("] expected in %s",s);
		    continue;
		  }
		  *olds=0;
		  if (stat(s+1,&st)) {
		    printf("Can not find device %s",s+1);
		    continue;
		  }
		  if (!S_ISBLK(st.st_mode)) {
		    printf("%s is not a block device, skipped\n",s+1);
		    continue;
		  }
		  command.dev=st.st_rdev;
		} else if (*s=='{') {
		  /*network device */;
		  for (olds=s+1;(*olds!='}') && *olds;olds++);
		  if (!*olds) {
		    printf("} expected in %s",s);
		    continue;
		  }
		  *olds=0;
		  command.dev=0;
		  strcpy(command.devname,s+1);
		} else {
		  printf("Can not recognize line %s\n",s);
		  continue;
		}
		olds++;
		
		if ((n=strsep(&olds,":"))==NULL) {
			fprintf(stderr,"Can not extract file name from string %s",s);
			continue;
		}
		strcpy(name,prefix);
		strcat(name,n); 
		i=strlen(name);
		if ((i>1) && (name[i-1]=='/')) name[i-1]=0;
		while (((n=strsep(&olds,":"))!=NULL)) {
			command.permission.mask=0;
			if (n[0]==0) {
				fprintf(stderr,"Can not extract user name from string %s",s);
				break;
			}
			if (n[0]=='+'){
				command.permission.mask|= TRUSTEE_IS_GROUP_MASK;
				n++;
			}
			if (n[0]==0) {
				fprintf(stderr,"Can not extract user name from string %s",s);
				strsep(&olds,":");
				break;
			}
			if (command.permission.mask & TRUSTEE_IS_GROUP_MASK) {
				if ((g=getgrnam(n))==NULL) {
					fprintf(stderr,"Invalid group %s",n);
					strsep(&olds,":");
					break;
				}
				command.permission.u.gid=g->gr_gid;
			} else {
				if (n[0]=='*') 
				    command.permission.mask|=TRUSTEE_ALL_MASK;
				else if ((pw=getpwnam(n))==NULL) {
					fprintf(stderr,"Invalid user %s",n);
					strsep(&olds,":");
					break;
				} else 
				  command.permission.u.uid=pw->pw_uid;
			}
			if ((n=strsep(&olds,":"))==NULL) {
				fprintf(stderr,"Can not extract mask frm %s",s);
				break;
			}
			
			for (;*n;n++) {
				switch (*n) {
				case 'D' :
					command.permission.mask|=TRUSTEE_ALLOW_DENY_MASK;
					break;
				case 'C' :
					command.permission.mask|=TRUSTEE_CLEAR_SET_MASK;
					break;
				case 'R':
					command.permission.mask|=TRUSTEE_READ_MASK;
					break;
				case 'W':
					command.permission.mask|=TRUSTEE_WRITE_MASK;
					break;
				case 'B':
					command.permission.mask|=TRUSTEE_BROWSE_MASK;
					break;
				case 'E':
				       command.permission.mask|=TRUSTEE_READ_DIR_MASK;
					break;
				case 'U':
					command.permission.mask|=TRUSTEE_USE_UNIX_MASK;
					break;
				case 'X':
					command.permission.mask|=TRUSTEE_EXECUTE_MASK;
					break;
				case '!':
					command.permission.mask|=TRUSTEE_NOT_MASK;
					break;
				case 'O':
					command.permission.mask|=TRUSTEE_ONE_LEVEL_MASK;
					break;
				
				default:
					fprintf(stderr,"Ilegal mask '%c' in string %s",*n,s);
				}
					
			}
			command.command=TRUSTEE_COMMAND_ADD;
			do_syscall(&command);
				
			
		}
	}
	if (!isstdin) fclose(f);
		
	
	return 0; 
  }















