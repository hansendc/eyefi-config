#include "eyefi-config.h"

#include <unistd.h>
#include <fcntl.h>

static int atoo(char o)
{
	if ((o >= '0') && (o <= '7'))
		return atoh(o);
	return -1;
}

static int octal_esc_to_chr(char *input)
{
	int i=0;
	int ret = 0;
	int len = strlen(input);

	//intf("%s('%s')\n", __func__, input);
	if (input[0] != '\\')
		return -1;
	if (len < 4)
		return -1;

	for (i=1; i < len ; i++) {
		if (i > 3)
			break;
		int tmp = atoo(input[i]);
		//intf("tmp: %d\n", tmp);
		if (tmp < 0)
			return tmp;
		ret <<= 3;
		ret += tmp;
	}
	return ret;
}

static char *replace_escapes(char *str)
{
	int i;
	int output = 0;
	debug_printf(4, "%s(%s)\n", __func__, str);
	for (i=0; i < strlen(str); i++) {
		int esc = octal_esc_to_chr(&str[i]);
		if (esc >= 0) {
			str[output++] = esc;
			i += 3;
			continue;
		}
		str[output++] = str[i];
	}
	str[output] = '\0';
	debug_printf(4, "replaced escapes in: '%s' bytes of output: %d\n", str, output);
	return str;
}

int fd_flush(int fd)
{
	int ret;
	ret = posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
	if (ret)
		perror("posix_fadvise() failed");
	return ret;
}


#define LINEBUFSZ 1024
char *locate_eyefi_mount(void)
{
	static char eyefi_mount[PATHNAME_MAX]; // PATH_MAX anyone?
	char line[LINEBUFSZ];
	FILE *mounts;

	char dev[LINEBUFSZ];
	char mnt[LINEBUFSZ];
	char fs[LINEBUFSZ];
	char opt[LINEBUFSZ];
	int foo;
	int bar;

	if (strlen(eyefi_mount))
		return &eyefi_mount[0];

       	mounts = fopen("/proc/mounts", "r");

	while (fgets(&line[0], 1023, mounts)) {
		int read;
		read = sscanf(&line[0], "%s %s %s %s %d %d",
				&dev[0], &mnt[0], &fs[0], &opt[0],
				&foo, &bar);
		// only look at fat filesystems:
		if (strcmp(fs, "msdos") && strcmp(fs, "vfat")) {
			debug_printf(4, "fs at '%s' is not fat, skipping...\n", mnt);
			continue;
		}
		// Linux's /proc/mounts has spaces like this \040
		replace_escapes(&mnt[0]);
		char *file = eyefi_file_on(REQM, &mnt[0]);
		debug_printf(4, "looking for EyeFi file here: '%s'\n", file);

		struct stat statbuf;
		int statret;
		statret = stat(file, &statbuf);
		free(file);
		if (statret) {
			debug_printf(4, "fs at: %s is not an Eye-Fi card, skipping...\n",
					eyefi_mount);
			continue;
		}
		strcpy(&eyefi_mount[0], &mnt[0]);
		debug_printf(1, "located EyeFi card at: '%s'\n", eyefi_mount);
		break;
	}
	fclose(mounts);

	if (strlen(eyefi_mount))
		return &eyefi_mount[0];

	debug_printf(0, "unable to locate Eye-Fi card\n");
	if (eyefi_debug_level < 5) {
		debug_printf(0, "Please check that your card is inserted and mounted\n");
		debug_printf(0, "If you still have issues, please re-run with the '-d5' option and report the output\n");
	} else {
		debug_printf(0, "----------------------------------------------\n");
		debug_printf(0, "Debug information:\n");
		system("cat /proc/mounts >&2");
	}
	exit(1);
	return NULL;
}
