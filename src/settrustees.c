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
#include <errno.h>
#include <stdint.h>

#include <linux/trustees.h>
#include "dynamic_array.h"

char *trustee_device = NULL;
FILE *trustee_file = NULL;
char *trustee_config = "/etc/trustees.conf";

typedef unsigned (*callbackptr)(struct trustee_command *, void **, unsigned *);
struct dev_desc {
	char *devname;
	uint32_t dev;
	struct dev_desc *next;
};

unsigned parse_permission_line(const char *line, callbackptr callback);
unsigned parse_device_characteristic(const char *line, callbackptr callback);
char *extract_to_delimiter(const char *s, char end, char **result);
char *extract_dev(const char *s, struct dev_desc *desc);
char *determine_securityfs_mount(void);
unsigned add_trustee(struct dev_desc *dev, const char *path, const char *perm,
 const char *user, callbackptr callback);
void add_ic_device(struct dev_desc *dev, callbackptr callback);

/* Read a line from file, the return result is only good until the next call to read_line
 */
char *read_line(FILE *file) {
	static char *buffer = NULL;
	static unsigned len  = 0;
	static const unsigned buf_ad = 32000;

	unsigned offset = 0;

	if (!buffer) {
		len = buf_ad;
		buffer = malloc(buf_ad);
	}
	offset = 0;
	do {
		int strl;
		if (!fgets(buffer + offset, len - offset, file)) return NULL;

		strl = strlen(buffer);
		if (buffer[strl - 1] == '\n') {
			buffer[strl - 1] = '\0';
			return buffer;
		} else if (strl == len - 1) {
			offset = len - 1;
			len += buf_ad;
			buffer = realloc(buffer, len);
		} else {
			fprintf(stderr, "I'm confused what just happened in fgets!\n");
			break;
		}
	} while(1);

	return NULL;
}

/* Parse a single line from the file, calling the provided callback with the arguments
 * to print out to the trustees device if anything should succeed.
 *
 * Returns 0 if it was unsuccessful at parsing
 */
unsigned parse_line(FILE *file, callbackptr callback) {
	const char *line;

	line = read_line(file);
	if (!line) return 1;

	switch(line[0]) {
		case '\0':
		case '#':
			return 1;
		case '{':
		case '[':
			return parse_permission_line(line, callback);
		case '*':
			return parse_device_characteristic(line, callback);
		default:
			break;
	}

	return 0;
}

unsigned parse_permission_line(const char *line, callbackptr callback)
{
	struct dev_desc device;
	char *path, *perms, *user;

	// Extract device
	line = extract_dev(line, &device);
	if (!line) return 0;

	// Extract directory/file
	line = extract_to_delimiter(line, ':', &path);
	if (!line) {
		fprintf(stderr, "No user/group and permission pairs\n");
		return 0;
	}

	// Extract user/group and perm pairs
	while (line) {
		line = extract_to_delimiter(line, ':', &user);
		if (!line) {
			fprintf(stderr, "Found user '%s', but no permission mask\n", user);
			return 0;
		}
		line = extract_to_delimiter(line, ':', &perms);
		add_trustee(&device, path, perms, user, callback);
		free(user);
		free(perms);
	}
	free(path);

	if (device.devname) free(device.devname);

	return 1;
}

unsigned parse_device_characteristic(const char *line, callbackptr callback)
{
	struct dev_desc device;

	// Extract device
	line = extract_dev(line+1, &device);
	if (!line) return 0;

	for (; *line; line++) {
		switch(*line) {
			case 'I': {
				add_ic_device(&device, callback);
				break;
			}
			default:
				fprintf(stderr, "Unknown flag '%c'\n", *line);
				return 0;
		}
	}

	if (device.devname) free(device.devname);

	return 1;
}

char *extract_to_delimiter(const char *s, char end, char **result)
{
	char *res;
	const char *origs = s;

	for (; *s && *s != end; s++);

	res = malloc(s - origs + 1);
	if (!res) {
		fprintf
		    (stderr, "Problem mallocing mem in extract_between_delimiters: %s\n",
		     strerror(errno));
		exit(1);
	}
	res[s - origs] = '\0';

	strncpy(res, origs, (s - origs));

	if (result)
		*result = res;

	return (*s) ? (char *)(s + 1) : NULL;
}

char *extract_dev(const char *s, struct dev_desc *desc)
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
				fprintf(stderr, "Could not find device %s\n",
				       device);
				return NULL;
			}
			if (!S_ISBLK(st.st_mode)) {
				fprintf
				    (stderr, "%s is not a block device, skipped\n",
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

	return (char *)s;
}

unsigned determine_trustees_apiversion(const char *mount)
{
	char buffer[strlen(mount) + 50];
	FILE *file;
	char *line = NULL;

	strcpy(buffer, mount);
	strcat(buffer, "/trustees/apiversion");

	file = fopen(buffer, "r");
	if (!file) {
		fprintf(stderr, "Could not open %s (%s)\n", buffer, strerror(errno));
		fprintf(stderr, "Are you sure the trustees module is loaded?\n");
		exit(1);
	} else {
		line = read_line(file);
	}
	if (line)
		return strtol(line, 0, 0);
	return 0;
}

char *determine_securityfs_mount(void)
{
	FILE *file;
	char *line, *device, *mount, *fstype, *options, *num1, *num2;

	file = fopen("/proc/mounts", "r");

	if (!file)
		return NULL;

	while ((line = read_line(file))) {
		device = strtok(line, " ");
		mount = strtok(NULL, " ");
		fstype = strtok(NULL, " ");
		options = strtok(NULL, " ");
		num1 = strtok(NULL, " ");
		num2 = strtok(NULL, " ");

		if (!device || !mount || !fstype || !options || !num1
		    || !num2) {
			continue;
		}

		if (strcmp(fstype, "securityfs") == 0) {
			fclose(file);
			return strdup(mount);
		}
	}
	fclose(file);

	return NULL;
}

void print_help_and_exit(void)
{
	printf("Usage: settrustees <options>\n");
	printf("Options:\n");
	printf("\n");
	printf("    -f <config>\n");
	printf("       Specify the trustees config file to use.\n");
	printf("       Default: %s\n", trustee_config);
	printf("    -D\n");
	printf("       delete all trustees from the kernel and exit\n");
	printf("    -n\n");
	printf
	    ("       do not delete all trustees from the kernel before processing\n");
	printf("       the config file\n");
	printf("\n");
	exit(1);
}

int send_trustees_command(struct trustee_command *comm, void **args, unsigned *lens)
{
	int fd = fileno(trustee_file);
	int x;
	if (!comm) {
		fprintf(stderr, "send_trustees_command: not called correctly!\n");
		return 0;
	}
	if (write(fd, comm, sizeof(struct trustee_command)) == -1) {
		fprintf(stderr, "send_trustees_command: couldn't send command\n");
		return 0;
	}

	for (x = 0; x < comm->numargs; x++) {
		if (write(fd, args[x], lens[x]) == -1) {
			fprintf(stderr, "send_trustees_command: couldn't send argument #%d\n", x);
			return 0;
		}
	}
	return 1;
}

void flush_trustees(void)
{
	struct trustee_command flush = { 
	   .command = TRUSTEE_COMMAND_REMOVE_ALL,
	   .numargs = 0
	};

	if (!send_trustees_command(&flush, 0, 0)) {
		fprintf(stderr, "flush_trustees failed\n");
		exit(1);
	}
}

unsigned callback_ignore_commands(struct trustee_command *comm, void **args, unsigned *lens)
{
	return 1;
}

unsigned callback_only_device_characteristics(struct trustee_command *comm, void **args, unsigned *lens)
{
	if (comm->command != TRUSTEE_COMMAND_MAKE_IC) return 1;

	return send_trustees_command(comm, args, lens);
}

unsigned callback_only_permissions(struct trustee_command *comm, void **args, unsigned *lens)
{
	if (comm->command != TRUSTEE_COMMAND_ADD) return 1;

	return send_trustees_command(comm, args, lens);
}

unsigned add_mask_string(const char *mstr, trustee_acl *mask)
{
	static struct {
		char identifier;
		uint32_t value;
	} mask_table[] = {
		{ 'D', TRUSTEE_ALLOW_DENY_MASK },
		{ 'C', TRUSTEE_CLEAR_SET_MASK },
		{ 'R', TRUSTEE_READ_MASK },
		{ 'W', TRUSTEE_WRITE_MASK },
		{ 'B', TRUSTEE_BROWSE_MASK },
		{ 'E', TRUSTEE_READ_DIR_MASK },
		{ 'U', TRUSTEE_USE_UNIX_MASK },
		{ 'X', TRUSTEE_EXECUTE_MASK },
		{ '!', TRUSTEE_NOT_MASK },
		{ 'O', TRUSTEE_ONE_LEVEL_MASK },
		{ '\0', 0 }
	};
	int j;

	for (; *mstr; mstr++) {
		for (j = 0; mask_table[j].identifier; j++) {
			if (mask_table[j].identifier == *mstr) {
				*mask |= mask_table[j].value;
				break;
			}
		}
		if (!mask_table[j].identifier) {
			fprintf(stderr, "Ilegal mask character '%c'\n", *mstr);
			return 0;
		}
	}
	return 1;
}

unsigned add_trustee(struct dev_desc *dev, const char *path, const char *mstr,
 const char *user, callbackptr callback)
{
	struct trustee_command comm = { 
		.command = TRUSTEE_COMMAND_ADD, 
		.numargs = 4
	};
	struct trustee_permission perm = { 0 };
	dynarray *args = dynarray_init(5);

	if (*user == '+') {
		struct group *grp = getgrnam(user+1);
		if (!grp) {
			fprintf(stderr, "Problem looking up group '%s'\n", user+1);
			return 0;
		}
		perm.u.gid = grp->gr_gid;
		perm.mask |= TRUSTEE_IS_GROUP_MASK;
	} else if (!strcmp(user, "*")) {
		perm.mask |= TRUSTEE_ALL_MASK;
	} else {
		struct passwd *pwd;
		pwd = getpwnam(user);
		if (!pwd) {
			fprintf(stderr, "Problem looking up user '%s'\n", user);
			return 0;
		}
		perm.u.uid = pwd->pw_uid;
	}

	if (!add_mask_string(mstr, &(perm.mask))) return 0;

	dynarray_push(args, path, strlen(path));
	dynarray_push(args, &perm, sizeof(perm));
	dynarray_push(args, dev->devname, strlen(dev->devname));
	dynarray_push(args, &dev->dev, sizeof(dev->dev));

	callback(&comm, args->items, args->lengths);
	dynarray_free(args);

	return 1;
}

void add_ic_device(struct dev_desc *dev, callbackptr callback)
{
	struct trustee_command comm = { 
		.command = TRUSTEE_COMMAND_MAKE_IC, 
		.numargs = 2 
	};
	dynarray *args = dynarray_init(5);

	dynarray_push(args, dev->devname, strlen(dev->devname));
	dynarray_push(args, &dev->dev, sizeof(dev->dev));

	callback(&comm, args->items, args->lengths);
	dynarray_free(args);
}


int main(int argc, char **argv) 
{
	char j;
	int pass;
	unsigned flush = 1, exitafterflush = 0;
	unsigned apiversion;
	FILE *config = NULL;

	trustee_device = determine_securityfs_mount();

	while ((j = getopt(argc, argv, "f:nhDp:")) != EOF) {
		switch (j) {
		case 'h':
		case '?':
			print_help_and_exit();
		case 'n':
			flush = 0;
			break;
		case 'D':
			flush = 1;
			exitafterflush = 1;
			break;
		case 'f':
			trustee_config = strdup(optarg);
			break;
		}
	}

	if (!trustee_device) {
		fprintf
		    (stderr, "Couldn't determine where the securityfs was mounted.  You need to\n");
		fprintf
		    (stderr, "do something like 'mount -t securityfs none /sys/kernel/security' and\n");
		fprintf
		    (stderr, "run again.\n");
		exit(1);
	}

	apiversion = determine_trustees_apiversion(trustee_device);
	fprintf(stderr, "Kernel API version: %u\nsettrustees API version: %u\n", apiversion, TRUSTEES_APIVERSION);

	if (apiversion < TRUSTEES_APIVERSION) {
		fprintf(stderr, "ERROR: You must upgrade your kernel trustees module.\n");
		exit(1);
	} else if (apiversion > TRUSTEES_APIVERSION) {
		fprintf(stderr, "ERROR: You must upgrade your settrustees executable.\n");
		exit(1);
	}	

	trustee_device = realloc(trustee_device, strlen(trustee_device) + 50);
	strcat(trustee_device, "/trustees/device");

	trustee_file = fopen(trustee_device, "w");
	if (!trustee_file) {
		fprintf
		    (stderr, "Could not open the trustees device for opening: %s\n",
		     trustee_device);
		fprintf(stderr, "The error was %s\n", strerror(errno));
		exit(1);
	}

	if (!exitafterflush) {
		if (strcmp(trustee_config, "-") == 0) {
			config = stdin;
		} else {
			config = fopen(trustee_config, "r");
			if (!config) {
				fprintf
				    (stderr, "Could not read config file %s, reason %s\n",
				     trustee_config, strerror(errno));
				exit(1);
			}
		}
	}

	if (flush)
		flush_trustees();

	if (exitafterflush)
		exit(0);

	for (pass = 0; pass < 3; pass++) {
		unsigned line = 0;
		callbackptr callback;

		switch(pass) {
			case 0:
				fprintf(stderr, "Pass 1: Checking for parse errors\n");
				callback = callback_ignore_commands;
				break;
			case 1:
				fprintf(stderr, "Pass 2: Sending device modifiers\n");
				callback = callback_only_device_characteristics;
				break;
			case 2:
				fprintf(stderr, "Pass 3: Sending permissions\n");
				callback = callback_only_permissions;
				break;
		}
		while (!feof(config)) {
			line++;
			if (!parse_line(config, callback)) {
				fprintf(stderr, "Parse error %s:%u\n", trustee_config, line);
				exit(1);
			}
		}
		rewind(config);
	}

	fclose(config);
	fclose(trustee_file);

	return 0;
}

