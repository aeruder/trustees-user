#include <syscall.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
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
#include <stdlib.h>

#include "trustees.h" 

char *trustee_device = NULL;
char *trustee_config = "/etc/trustees.conf";

int set_trustee(const struct trustee_command * command)
{
	int fd;
	int ret;

	fd = open (trustee_device, O_WRONLY);

	if (fd < 0) return errno;

	ret = write(fd, command, sizeof(struct trustee_command));
	if (ret != sizeof(struct trustee_command)) return errno;

	close (fd);

	return 0;
}
 
char *determine_trustees_mount(void) {
	FILE *file;
	char x[10000];
	char *device;
	char *mount;
	char *fstype;
	char *options;
	char *num1;
	char *num2;

	file = fopen("/etc/mtab", "r");

	if (!file) return NULL;

	x[9999] = '\0';
	while (fgets(x, 9999, file)) {
		if (strlen(x) == 9999) {
			fprintf(stderr, "Error parsing mtab, line too long!\n");
			return NULL;
		}
		
		device = strtok(x, " ");
		mount = strtok(NULL, " ");
		fstype = strtok(NULL, " ");
		options = strtok(NULL, " ");
		num1 = strtok(NULL, " ");
		num2 = strtok(NULL, " ");

		if (!device || !mount || !fstype || !options || !num1 || !num2) {
			fprintf(stderr, "Error parsing mtab, not enough fields!\n");
			return NULL;
		}

		if (strcmp(fstype, "trusteesfs") == 0) {
			return strdup(mount);
		}
	}

	return NULL;
}
		
void print_exit(void) {
	printf("Usage: settrustees <options>\n");
	printf("Options:\n");
	printf("\n");
	printf("    -f <config>\n");
	printf("       Specify the trustees config file to use.\n");
	printf("       Default: %s\n", trustee_config);
	printf("    -D\n");
	printf("       delete all trustees from the kernel and exit\n");
	printf("    -d\n");
	printf("       delete all trustees from the kernel before processing the trustees in\n");
	printf("       the file\n");
	printf("    -t <trustees device file>\n");
	printf("       Specify the 'trustees' file from the mounted trusteefs fs\n");
	printf("       This can often be automatically detected: %s\n", trustee_device);
	printf("    -p <prefix>\n");
	printf("       prefix to file names\n");
	printf("\n");
	printf("Description of the trustees config file format:\n");
	printf("One path per line in this format:\n");
	printf("    [block_device_name]/path/path:user_name:DCRWBE:+group_name:OtherChars\n");
	printf("    {network_name}/path/path:user_name:DCRWBE:+group_name:OtherChars\n");
	printf("A description of the various flags available:\n");
	printf("    R - Read files permission\n");
	printf("    W - Write permission\n");
	printf("    B - Browse (like execute permission for directories)\n");
	printf("    E - rEad diriectories\n");
	printf("    X - eXecute (files, granted only if owner can execute the file\n");
	printf("    U - use Unix permission system (set as default for /)\n");
	printf("    D - deny the permissions in mask\n");
	printf("    C - clear the permissions in mask\n");
	printf("    O - only the directory and files in it (not subdirectories) affected by the\n");
	printf("        trustee\n");
	printf("    ! - All except user (group) affected by the trustee\n");
	printf("The access to a file ( directory) calculated on the following manner: There are\n");
	printf("two sets of masks: the deny masks and the allow masks.  Before the path\n");
	printf("transversal begins, the deny mask is [] and the allow mask [U]. The path to a\n");
	printf("file is transversed starting at the root of the partition.  At any point in the\n");
	printf("transversal, if an applicable trustee is found, the bits in that mask are or'd\n");
	printf("to the current mask.  If the 'C' flag is set, the bits are cleared instead of\n");
	printf("set.  When the full path has been transversed and the masks have been\n");
	printf("calculated if the mode requested is in the deny mask, the request will be\n");
	printf("denied.  If the 'U' flag is set in the allow mask then next unix permissions\n");
	printf("will be checked and possibly allowed access.  Next, if all flags for the\n");
	printf("requested mode are in the allow mask, then the request will be granted.  If not\n");
	printf("granted this point, the request will be denied.\n");
	printf("\n");
	printf("Limitations, notes and caveats:\n");
	printf("Superuser will always be allowed access.\n");
	printf("Hard links are partially disabled while trustees is loaded since it poses a\n");
	printf("major security risk.  Hard links will be allowed into the current directory\n");
	printf("only.  If someone manages to make hard links while the trustees module is not\n");
	printf("loaded into different directories, then it is possible that a user could use it\n");
	printf("to gain additional rights to a file since the trustees module has no way to\n");
	printf("check all locations that a file exists on a disk.\n");
	exit(-1);
}

int main(int argc, char * argv[])
{
	char *prefix = "";
	int i, j, r;
	int flush = 0, exitafterflush = 0;
	FILE *f;
	char name[PATH_MAX + NAME_MAX] = "";
	char  devname[PATH_MAX+NAME_MAX];
	struct trustee_command command;
	char s[32000];
	char *olds, *n;
	struct group *g;
	struct passwd *pw; 
	struct stat st;
	int line;
  
	command.filename = name;
	command.devname = devname;

	trustee_device = determine_trustees_mount();
	if (trustee_device) {
		char *new;
		new = realloc(trustee_device, strlen(trustee_device) + 100);
		if (!new) {
			fprintf(stderr, "It seems we ran out of memory... bailing...\n");
			exit(-1);
		}
		trustee_device = new;
		strcat(trustee_device, "/trustees");
	} 

	while ((j = getopt(argc,argv,"t:f:dhDp:"))!=EOF) {
		switch (j) {
		case 'h':
		case '?': 
			print_exit();
		case 'd' : 
			flush = 1;
			break;
		case 'D':
			flush = 1;
			exitafterflush = 1;
			break;
		case 'f':
			trustee_config = strdup(optarg);
			break;
		case 't':
			trustee_device = strdup(optarg);
			break;
		case 'p':
			prefix = strdup(optarg);
			break;
		}
	}

	if (!trustee_device) {
		fprintf(stderr, "Couldn't determine where the trusteesfs was mounted.  You need to\n");
		fprintf(stderr, "do something like 'mount -t trusteesfs none /place/to/mount' and\n");
		fprintf(stderr, "run again.  It is possible the mount point could just not be determined\n");
		fprintf(stderr, "in which case you should specify it with the -t option.\n");
		exit (-1);
	}
		

	f = fopen(trustee_device, "w");
	if (f == NULL)
	{
		fprintf(stderr, "Could not open the trustees device for opening: %s\n", 
		  trustee_device);
		fprintf(stderr, "The error was %s\n", strerror(errno));
		exit (-1);
	}

	if (!exitafterflush) {
		if (strcmp(trustee_config, "-") == 0) { 
			f = stdin;
		} else {
			f = fopen(trustee_config, "r");
			if (!f) {
				fprintf(stderr, "Could not read config file %s, reason %s\n", 
				  trustee_config, strerror(errno));
				exit(-1);
			}
		}
	}
	
	if (flush) {
		command.command = TRUSTEE_COMMAND_REMOVE_ALL;
		r = set_trustee(&command);
		if (r) {
			fprintf(stderr, "Can't set trustee for %s, reason: %s\n",
			  command.filename, strerror(r));
			exit(-1);
		}
	}

	if (exitafterflush) exit(0);

	i = strlen(prefix);
	
	if ((i > 0) && (prefix[i - 1] == '/')) 
		prefix[i - 1] = 0;
	
	
	s[31999] = '\0';
	line = 0;
	while (fgets(s, 31999, f) != NULL) {
		line++;
		i = strlen(s);
		if (i == 31999) { /* handle lines longer than 31999 characters */
			fprintf(stderr, "Warning skipping line longer than 31999 characters!\n");
			while (((j = fgetc(f)) != '\n') && (j != EOF));
			continue;
		}
		if (i == 0) continue;
		if (s[0] == '#') continue;
		if (s[i - 1] == '\n') s[i - 1] = 0;
		if (strlen(s) == 0) continue;
/*handle block device */;
		if (*s == '[') {
			for (olds = s + 1; (*olds != ']') && *olds; olds++);
			if (!*olds) {
				fprintf(stderr, "] expected on line %d\n", line);
				continue;
			}
			*olds = 0;
			if (stat(s + 1, &st)) {
				fprintf(stderr, "Can not find device %s\n", s + 1);
				continue;
			}
			if (!S_ISBLK(st.st_mode)) {
				fprintf(stderr, "%s is not a block device, skipped\n", 
				  s + 1);
				continue;
			}
			command.dev=st.st_rdev;
/*handle network device */;
		} else if (*s == '{') {
			for (olds = s + 1; (*olds != '}') && *olds; olds++);
			if (!*olds) {
				fprintf(stderr, "} expected on line %d\n", line);
				continue;
			}
			*olds = 0;
			command.dev = 0;
			strcpy(command.devname, s+1);
		} else {
			fprintf(stderr, "Can not recognize line %s (line %d)\n", s, line);
			continue;
		}
		olds++;

/* pull in the filename */
		if ((n = strsep(&olds,":"))==NULL) {
			fprintf(stderr, "Can not extract file name from line %d\n", line);
			continue;
		}

		strcpy(name, prefix);
		strcat(name, n); 
		i = strlen(name);
		if ((i > 1) && (name[i-1] == '/')) 
			name[i-1]=0;
		while (((n = strsep(&olds, ":")) != NULL)) {
			command.permission.mask=0;
			if (n[0] == 0) {
				fprintf(stderr, "Can not extract user name from line %d\n", line);
				break;
			}
			if (n[0] == '+') {
				command.permission.mask |= TRUSTEE_IS_GROUP_MASK;
				n++;
			}
			if (n[0] == 0) {
				fprintf(stderr, "Can not extract user name from line %d\n", line);
				strsep(&olds,":");
				break;
			}
			if (command.permission.mask & TRUSTEE_IS_GROUP_MASK) {
				if ((g = getgrnam(n)) == NULL) {
					fprintf(stderr, "Invalid group %s on line %d\n", n, line);
					strsep(&olds, ":");
					break;
				}
				command.permission.u.gid=g->gr_gid;
			} else {
				if (n[0] == '*') 
					command.permission.mask |= TRUSTEE_ALL_MASK;
				else if ((pw = getpwnam(n)) == NULL) {
					fprintf(stderr, "Invalid user %s on line %d\n", n, line);
					strsep(&olds, ":");		
					break;
				} else {
					command.permission.u.uid = pw->pw_uid;
				}
			}

			if ((n = strsep(&olds, ":")) == NULL) {
				fprintf(stderr, "Can not extract mask from line %d\n", line);
				break;
			}

			for (; *n; n++) {
				switch(*n) {
					case 'D' :
						command.permission.mask |= TRUSTEE_ALLOW_DENY_MASK;
						break;
					case 'C' :
						command.permission.mask |= TRUSTEE_CLEAR_SET_MASK;
						break;
					case 'R':
						command.permission.mask |= TRUSTEE_READ_MASK;
						break;
					case 'W':
						command.permission.mask |= TRUSTEE_WRITE_MASK;
						break;
					case 'B':
						command.permission.mask |= TRUSTEE_BROWSE_MASK;
						break;
					case 'E':
						command.permission.mask |= TRUSTEE_READ_DIR_MASK;
						break;
					case 'U':
						command.permission.mask |= TRUSTEE_USE_UNIX_MASK;
						break;
					case 'X':
						command.permission.mask |= TRUSTEE_EXECUTE_MASK;
						break;
					case '!':
						command.permission.mask |= TRUSTEE_NOT_MASK;
						break;
					case 'O':
						command.permission.mask |= TRUSTEE_ONE_LEVEL_MASK;
						break;
					default:
						fprintf(stderr, "Ilegal mask '%c' on line %d\n", *n, line);
				}
			}
			command.command = TRUSTEE_COMMAND_ADD;
			r = set_trustee(&command);
			if (r) {
				fprintf(stderr, "Can't set trustee for %s, reason: %s\n",
				  command.filename, strerror(r));
			}
		}
	}
	fclose(f);
		
	return 0; 
}

