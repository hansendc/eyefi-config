#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>

#include "eyefi-config.h"

#include <unistd.h>
#include <fcntl.h>

int fd_flush(int fd)
{
	int ret;
	ret = fsync(fd);
	if (ret)
		perror("fsync() failed");
	return ret;
}


#define LINEBUFSZ 1024
char *locate_eyefi_mount(void)
{
	static char eyefi_mount[PATHNAME_MAX]; // PATH_MAX anyone?

	if (strlen(eyefi_mount))
		return &eyefi_mount[0];

	int numfs;
	int bufsize;
	struct statfs * fsbuf;
	int i;

	if ((numfs = getfsstat(NULL, 0, MNT_WAIT)) < 0) {
		debug_printf(2, "unable to obtain the number of file systems\n");
		return(NULL);
	}

	bufsize = (long)numfs *sizeof(struct statfs);
	if ((fsbuf = malloc(bufsize)) == NULL) {
		debug_printf(2, "unable to allocate space for filesystem list\n");
		return(NULL);
	}

	if (getfsstat(fsbuf, bufsize, MNT_WAIT) < 0) {
		debug_printf(2, "unable to get the list of filesystems\n");
		return(NULL);
	}

	for(i = 0; i < numfs; i++) {
		if(fsbuf[i].f_type != 5) continue; // Not MSDOS

		char *file = eyefi_file_on(REQM, fsbuf[i].f_mntonname);
		debug_printf(2, "looking for EyeFi file here: '%s'\n", file);

		struct stat statbuf;
		int statret;
		statret = stat(file, &statbuf);
		free(file);
		if (statret) {
			debug_printf(2, "fs at: %s is not an Eye-Fi card, skipping...\n",
					eyefi_mount);
			continue;
		}

		strcpy(&eyefi_mount[0], fsbuf[i].f_mntonname);
		debug_printf(1, "located EyeFi card at: '%s'\n", eyefi_mount);
		break;
	}

	if (strlen(eyefi_mount))
		return &eyefi_mount[0];

	debug_printf(0, "unable to locate Eye-Fi card\n");
	if (eyefi_debug_level < 5) {
		debug_printf(0, "Please check that your card is inserted and mounted\n");
		debug_printf(0, "If you still have issues, please re-run with the '-d5' option and report the output\n");
	} else {
		debug_printf(0, "----------------------------------------------\n");
		debug_printf(0, "Debug information:\n");
	}
	exit(1);
	return NULL;
}
