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
	fsync(fd);
	fdatasync(fd);
	ret = posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
	if (ret)
		perror("posix_fadvise() failed");
	return ret;
}

// Ubuntu (at least) also uses this as a UUID, although it
// is not very unique among Eye-Fi cards, obviously.
#define EYEFI_VOLUME_ID "AA52-6922";
static char UDEV_BY_UUID_PATH[PATHNAME_MAX] = "/dev/disk/by-uuid/" EYEFI_VOLUME_ID;

// Note: this modifies the original string
char *basename(char *filename)
{
	char *place = filename + strlen(filename) - 1;

	// strip trailing slashes like the basename command
	while (*place == '/') {
		*place = '\0';
		place--;
	}
	while (place >= filename) {
		if (*place == '/')
			return place+1;
		place--;
	}
	return filename;
}

// This is a little backards.  To see if this is an Eye-Fi card,
// we look at a known place where we expect udev to put a symlink
// to the device file: UDEV_BY_UUID_PATH.  We then see whether
// that symlink matches the /dev/$foo from /proc/mounts
int dev_has_eyefi_vol_id(char *dev)
{
	char link_contents[PATHNAME_MAX];
	char *link_dev_name;
	ssize_t ret;

	ret = readlink(UDEV_BY_UUID_PATH, &link_contents[0], PATHNAME_MAX);
	debug_printf(3, "read %ld bytes of link data from '%s': '%s'\n",
			ret, UDEV_BY_UUID_PATH, link_contents);
	if (ret < 0)
		return 0;

	link_dev_name = basename(&link_contents[0]);
	dev = basename(dev);
	debug_printf(3, "basename('%s'): '%s'\n", link_contents, link_dev_name);
	if (strcmp(dev, link_dev_name))
		return 0;
	return 1;
}

int fs_is(char *fs, char *fs_name)
{
	return (strcmp(fs, fs_name) == 0);
}

int zero_file(enum eyefi_file file, char *mnt)
{
	char *fname;
	char *zerobuf[EYEFI_BUF_SIZE];
	int fd;
	int ret;
	
	memset(&zerobuf[0], 0, EYEFI_BUF_SIZE);
	fname = eyefi_file_on(file, mnt);
	debug_printf(1, "creating control file: '%s'\n", fname);
	fd = open(fname, O_WRONLY|O_CREAT);
	ret = fd;
	if (ret < 0)
		goto out;
	ret = write(fd, &zerobuf[0], EYEFI_BUF_SIZE);
	if (ret < 0)
		goto out;
	ret = 0;
	fsync(fd);
	close(fd);
out:
	free(fname);
	if (ret)
		return errno;
	return 0;
}

int create_control_files(char *mnt)
{
	char *control_dir = eyefi_file_on(RDIR, mnt);
	int ret = 0;
	enum eyefi_file file;

	ret = mkdir(control_dir, 0644);
	debug_printf(1, "making control directory: '%s', errno: %d\n", control_dir, errno);
	free(control_dir);
	if ((ret != 0) && (errno != EEXIST)) {
		perror("unable to create Eye-Fi control directory");
		return errno;
	}
	for (file = REQC; file <= RSPM; file++) {
		ret = zero_file(file, mnt);
		debug_printf(2, "trying to create control file: '%s', ret: %d\n",
				eyefi_file_name(file), ret);
		if (ret) {
			perror("unable to create control file");
			goto out;
		}
	}
out:
	return ret;
}

#define LINEBUFSZ 1024
static char *check_mount_line(int line_nr, char *line)
{
	char dev[LINEBUFSZ];
	char mnt[LINEBUFSZ];
	char fs[LINEBUFSZ];
	char opt[LINEBUFSZ];
	int garb1;
	int garb2;
	int read;
	read = sscanf(&line[0], "%s %s %s %s %d %d",
			&dev[0], &mnt[0], &fs[0], &opt[0],
			&garb1, &garb2);
	if (read != 6) {
		debug_printf(2, "Unable to parse mount line: '%s'\n", line);
		return NULL;
	}
	// only look at fat filesystems:
	if (!fs_is(fs, "msdos") && !fs_is(fs, "vfat")) {
		debug_printf(4, "fs[%d] at '%s' is not fat, skipping...\n",
				line_nr, mnt);
		return NULL;
	}
	// Linux's /proc/mounts has spaces like this \040
	replace_escapes(&mnt[0]);
	char *file = eyefi_file_on(REQM, &mnt[0]);

	struct stat statbuf;
	int statret;
	statret = stat(file, &statbuf);
	free(file);
	debug_printf(2, "looking for EyeFi file here: '%s' (statret: %d)\n", file, statret);
	if ((statret == -1) && (errno == ENOENT)
	    && dev_has_eyefi_vol_id(&dev[0])) {
		debug_printf(1, "found mount  '%s' that looks like Eye-Fi, "
				"but has no control files\n", mnt);
		int control_creation = create_control_files(&mnt[0]);
		if (control_creation != 0)
			return NULL;
		statret = stat(file, &statbuf);
	}
	if (statret) {
		debug_printf(3, "fs[%d] at: %s is not an Eye-Fi card, skipping...\n",
				line_nr, &mnt[0]);
		debug_printf(4, "statret: %d/%d\n", statret, errno);
		return NULL;
	}
	return strdup(&mnt[0]);
}

char *locate_eyefi_mount(void)
{
	static char eyefi_mount[PATHNAME_MAX]; // PATH_MAX anyone?
	FILE *mounts;

	char line[LINEBUFSZ];
	int fs_nr = -1;

	if (strlen(eyefi_mount))
		return &eyefi_mount[0];

       	mounts = fopen("/proc/mounts", "r");

	while (fgets(&line[0], 1023, mounts)) {
		char *mnt = check_mount_line(fs_nr++, line);
		if (!mnt)
			continue;
		strcpy(&eyefi_mount[0], mnt);
		free(mnt);
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

void eject_card(void)
{
	char cmd[PATHNAME_MAX];
	sprintf(cmd, "umount '%s'", locate_eyefi_mount());
	debug_printf(1, "ejecting card: '%s'\n", cmd);
	system(cmd);
	exit(0);
}
