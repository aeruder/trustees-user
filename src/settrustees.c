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
char *trustee_config = "/etc/trustee.conf";

struct dev_desc {
	char *devname;
	dev_t dev;
	struct dev_desc *next;
};

struct dev_desc *ic_list = NULL;

int compare_devs(struct dev_desc *dev1, struct dev_desc *dev2)
{
	if (dev1->dev && dev2->dev)
		return (dev1 == dev2);

	if (!dev1->dev && !dev2->dev)
		return (strcmp(dev1->devname, dev2->devname) == 0);

	return 0;
}

void add_ic_dev(struct dev_desc *dev1)
{
	struct dev_desc *newdev;

	newdev = malloc(sizeof(struct dev_desc));
	if (!newdev) {
		printf("Couldn't malloc in add_ic_dev: %s\n",
		       strerror(errno));
		exit(-1);
	}

	newdev->devname = strdup(dev1->devname);
	newdev->dev = dev1->dev;
	newdev->next = ic_list;
	ic_list = newdev;
}

int is_ic_dev(struct dev_desc *dev1)
{
	struct dev_desc *iter;

	for (iter = ic_list; (iter); iter = iter->next) {
		if (compare_devs(iter, dev1))
			return 1;
	}

	return 0;
}

char *extract_to_delimiter(char *s, char end, char **result)
{
	char *res;
	char *origs = s;

	for (; *s && *s != end; s++);

	res = malloc(s - origs + 1);
	if (!res) {
		printf
		    ("Problem mallocing mem in extract_between_delimiters: %s\n",
		     strerror(errno));
		exit(-1);
	}
	res[s - origs] = '\0';

	strncpy(res, origs, (s - origs));

	if (result)
		*result = res;

	printf("%s\n", res);

	return (*s) ? (s + 1) : NULL;
}

char *extract_dev(char *s, struct dev_desc *desc)
{
	char *device;

	if (!desc)
		return NULL;

	desc->next = NULL;

	if (*s == '[') {
		s = extract_to_delimiter(s + 1, ']', &device);
		desc->devname = device;

		if (s) {
			struct stat st;

			if (stat(device, &st)) {
				printf("Could not find device %s\n",
				       device);
				return NULL;
			}
			if (!S_ISBLK(st.st_mode)) {
				printf
				    ("%s is not a block device, skipped\n",
				     device);
				return NULL;
			}
			desc->dev = st.st_rdev;
		}
	} else if (*s == '{') {
		s = extract_to_delimiter(s + 1, '}', &device);
		desc->devname = device;

		if (s) {
			desc->dev = 0;
		}
	} else {
		desc->devname = NULL;
	}

	return s;
}


int set_trustee(const struct trustee_command *command)
{
	int fd;
	int ret;

	fd = open(trustee_device, O_WRONLY);

	if (fd < 0)
		return errno;

	ret = write(fd, command, sizeof(struct trustee_command));
	if (ret != sizeof(struct trustee_command))
		return errno;

	close(fd);

	return 0;
}

char *determine_trustees_mount(void)
{
	FILE *file;
	char x[10000];
	char *device;
	char *mount;
	char *fstype;
	char *options;
	char *num1;
	char *num2;

	file = fopen("/etc/mtab", "r");

	if (!file)
		return NULL;

	x[9999] = '\0';
	while (fgets(x, 9999, file)) {
		if (strlen(x) == 9999) {
			int j;
			fprintf(stderr,
				"Error parsing mtab, line too long!\n");
			while (((j = fgetc(file)) != '\n')
			       && (j != EOF));
			continue;
		}

		device = strtok(x, " ");
		mount = strtok(NULL, " ");
		fstype = strtok(NULL, " ");
		options = strtok(NULL, " ");
		num1 = strtok(NULL, " ");
		num2 = strtok(NULL, " ");

		if (!device || !mount || !fstype || !options || !num1
		    || !num2) {
			continue;
		}

		if (strcmp(fstype, "trusteesfs") == 0) {
			return strdup(mount);
		}
	}

	return NULL;
}

void print_exit(void)
{
	printf("Usage: settrustees <options>\n");
	printf("Options:\n");
	printf("\n");
	printf("    -f <config>\n");
	printf("       Specify the trustees config file to use.\n");
	printf("       Default: %s\n", trustee_config);
	printf("    -D\n");
	printf("       delete all trustees from the kernel and exit\n");
	printf("    -d\n");
	printf
	    ("       delete all trustees from the kernel before processing the trustees in\n");
	printf("       the file\n");
	printf("    -t <trustees device file>\n");
	printf
	    ("       Specify the 'trustees' file from the mounted trusteefs fs\n");
	printf("       This can often be automatically detected: %s\n",
	       trustee_device);
	printf("\n");
	exit(-1);
}


void handle_dev_line(char *s, int line)
{
	struct dev_desc dev_desc;
	struct trustee_command command;

	if (*s != '*')
		return;

	s = extract_dev(s + 1, &dev_desc);
	if (!s) {
		printf("Problem parsing dev_line on line no. %d\n", line);
		if (dev_desc.devname)
			free(dev_desc.devname);
		return;
	}

	command.dev = dev_desc.dev;
	command.devname = dev_desc.devname;

	for (; *s; s++) {
		command.command = 0;

		switch (*s) {
		case 'I':
			add_ic_dev(&dev_desc);
			command.command = TRUSTEE_COMMAND_MAKE_IC;
			break;
		default:
			printf
			    ("Unrecognized device flag '%c' on line %d\n",
			     *s, line);
		}

		if (command.command) {
			int r;
			r = set_trustee(&command);
			if (r) {
				printf
				    ("Can't set trustee for %s, reason: %s\n",
				     command.filename, strerror(r));
				exit(-1);
			}
		}
	}

	return;
}

void handle_reg_line(char *s, int line)
{
	int r, isgroup;
	struct trustee_command command;
	char *maskstr, *uidstr, *path;
	int icdev = 0;
	struct dev_desc dev_desc;
	char *iter;

/* Grab the device */
	s = extract_dev(s, &dev_desc);

	if (!s) {
		printf("Problem parsing device on line no. %d\n", line);
		if (dev_desc.devname)
			free(dev_desc.devname);
		return;
	}

	command.devname = dev_desc.devname;
	command.dev = dev_desc.dev;
	icdev = is_ic_dev(&dev_desc);

/* Grab the path */
	s = extract_to_delimiter(s, ':', &path);

	if (!s) {
		printf("Problem parsing path on line no. %d\n", line);
		free(dev_desc.devname);
		free(path);
		return;
	}

	if (icdev) {
		char *t;
		for (t = path; *t; t++) {
			if ((*t >= 'A') && (*t <= 'Z'))
				(*t) += 'a' - 'A';
		}
	}

	command.filename = path;

	while (s && *s) {
		command.permission.mask = 0;
		command.permission.u.uid = command.permission.u.gid = 0;
		command.command = TRUSTEE_COMMAND_ADD;

		uidstr = maskstr = NULL;

		s = extract_to_delimiter(s, ':', &uidstr);
		if (s)
			s = extract_to_delimiter(s, ':', &maskstr);

		if (!s && !maskstr) {
			printf
			    ("Problems parsing name/mask pair on line %d\n",
			     line);
			free(command.filename);
			free(command.devname);
			if (uidstr)
				free(uidstr);
			return;
		}

		isgroup = 0;
		if (uidstr[0] == '+') {
			isgroup = 1;
			memmove(uidstr, uidstr + 1, strlen(uidstr));
		}

		if (isgroup) {
			struct group *grp = getgrnam(uidstr);
			if (!grp) {
				printf("Invalid group %s on line %d\n",
				       uidstr, line);
				continue;
			}
			command.permission.u.gid = grp->gr_gid;
			command.permission.mask |= TRUSTEE_IS_GROUP_MASK;
		} else {
			struct passwd *pwd;
			if (uidstr[0] == '*') {
				command.permission.mask +=
				    TRUSTEE_ALL_MASK;
			} else {
				pwd = getpwnam(uidstr);
				if (!pwd) {
					printf
					    ("Invalid uid %s on line %d, continuing...\n",
					     uidstr, line);
					continue;
				}
				command.permission.u.uid = pwd->pw_uid;
			}
		}

		for (iter = maskstr; *iter; iter++) {
			switch (*iter) {
			case 'D':
				command.permission.mask |=
				    TRUSTEE_ALLOW_DENY_MASK;
				break;
			case 'C':
				command.permission.mask |=
				    TRUSTEE_CLEAR_SET_MASK;
				break;
			case 'R':
				command.permission.mask |=
				    TRUSTEE_READ_MASK;
				break;
			case 'W':
				command.permission.mask |=
				    TRUSTEE_WRITE_MASK;
				break;
			case 'B':
				command.permission.mask |=
				    TRUSTEE_BROWSE_MASK;
				break;
			case 'E':
				command.permission.mask |=
				    TRUSTEE_READ_DIR_MASK;
				break;
			case 'U':
				command.permission.mask |=
				    TRUSTEE_USE_UNIX_MASK;
				break;
			case 'X':
				command.permission.mask |=
				    TRUSTEE_EXECUTE_MASK;
				break;
			case '!':
				command.permission.mask |=
				    TRUSTEE_NOT_MASK;
				break;
			case 'O':
				command.permission.mask |=
				    TRUSTEE_ONE_LEVEL_MASK;
				break;
			default:
				printf("Ilegal mask '%c' on line %d\n",
				       *iter, line);
			}
		}
		r = set_trustee(&command);
		if (r) {
			printf("Can't set trustee for %s, reason: %s\n",
			       command.filename, strerror(r));
			exit(-1);
		}
		free(maskstr);
		free(uidstr);
	}

	free(command.filename);
	free(command.devname);
}

int main(int argc, char *argv[])
{
	int i, j, r;
	int flush = 0, exitafterflush = 0;
	FILE *f;
	char name[PATH_MAX + NAME_MAX] = "";
	char devname[PATH_MAX + NAME_MAX];
	struct trustee_command command;
	char s[32000];
	int line, pass;

	command.filename = name;
	command.devname = devname;

	trustee_device = determine_trustees_mount();
	if (trustee_device) {
		char *new;
		new =
		    realloc(trustee_device, strlen(trustee_device) + 100);
		if (!new) {
			printf
			    ("It seems we ran out of memory... bailing...\n");
			exit(-1);
		}
		trustee_device = new;
		strcat(trustee_device, "/trustees");
	}

	while ((j = getopt(argc, argv, "t:f:dhDp:")) != EOF) {
		switch (j) {
		case 'h':
		case '?':
			print_exit();
		case 'd':
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
		}
	}

	if (!trustee_device) {
		printf
		    ("Couldn't determine where the trusteesfs was mounted.  You need to\n");
		printf
		    ("do something like 'mount -t trusteesfs none /place/to/mount' and\n");
		printf
		    ("run again.  It is possible the mount point could just not be determined\n");
		printf
		    ("in which case you should specify it with the -t option.\n");
		exit(-1);
	}


	f = fopen(trustee_device, "w");
	if (f == NULL) {
		printf
		    ("Could not open the trustees device for opening: %s\n",
		     trustee_device);
		printf("The error was %s\n", strerror(errno));
		exit(-1);
	}

	if (!exitafterflush) {
		if (strcmp(trustee_config, "-") == 0) {
			f = stdin;
		} else {
			f = fopen(trustee_config, "r");
			if (!f) {
				printf
				    ("Could not read config file %s, reason %s\n",
				     trustee_config, strerror(errno));
				exit(-1);
			}
		}
	}

	if (flush) {
		command.command = TRUSTEE_COMMAND_REMOVE_ALL;
		r = set_trustee(&command);
		if (r) {
			printf("Can't set trustee for %s, reason: %s\n",
			       command.filename, strerror(r));
			exit(-1);
		}
	}

	if (exitafterflush)
		exit(0);


	s[31999] = '\0';
	line = 0;
	pass = 0;
	while (pass < 3) {
		while (fgets(s, 31999, f) != NULL) {
			line++;
			i = strlen(s);
			if (i == 31999) {	/* handle lines longer than 31999 characters */
				printf
				    ("Warning skipping line longer than 31999 characters!\n");
				while (((j = fgetc(f)) != '\n')
				       && (j != EOF));
				continue;
			}
			if (i == 0)
				continue;
			if (s[0] == '#')
				continue;
			if (s[i - 1] == '\n')
				s[i - 1] = 0;
			if (strlen(s) == 0)
				continue;
			if (s[0] == '*') {
				if (pass == 1)
					handle_dev_line(s, line);
				continue;
			}
			if ((s[0] == '{') || (s[0] == '[')) {
				if (pass == 2)
					handle_reg_line(s, line);
				continue;
			}

			if (pass == 0) {
				printf("Garbled input on line %d\n", line);
				exit(-1);
			}
		}
		rewind(f);
		pass++;
	}

	fclose(f);

	return 0;
}
