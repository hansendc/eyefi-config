/*
 * eyefitest.c
 *
 * Copyright (C) 2008 Dave Hansen <dave@sr71.net>
 *
 * This software may be redistributed and/or modified under the terms of
 * the GNU General Public License ("GPL") version 2 as published by the
 * Free Software Foundation.
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "eyefi-config.h"

int debug_level = 1;
#define debug_printf(level, args...) do {	\
	if ((level) <= debug_level)		\
		fprintf(stderr, ## args);	\
	} while(0)

#define O_DIRECT        00040000        /* direct disk access hint */

enum eyefi_file {
	REQC,
	REQM,
	RSPC,
	RSPM
};
 
#define PATHNAME_MAX 4096
char eyefi_mount[PATHNAME_MAX]; // PATH_MAX anyone?
static char *eyefi_file_name(enum eyefi_file file)
{
	switch (file) {
	case REQC: return "reqc";
	case REQM: return "reqm";
	case RSPC: return "rspc";
	case RSPM: return "rspm";
	}

	return NULL;
}

static char *eyefi_file_on(enum eyefi_file file, char *mnt)
{
	char *filename = eyefi_file_name(file);
	char *full = malloc(PATHNAME_MAX);

	sprintf(&full[0], "%s/EyeFi/%s", mnt, filename);
	debug_printf(4, "eyefile nr: %d on '%s' is: '%s'\n", file, mnt, &full[0]);
	return full;
}


#define BUFSZ 16384
#define EYEFI_BUF_SIZE 16384
char unaligned_buf[BUFSZ*2];
void *buf;

/*
 * Just a few functions so that I can't easily forget about
 * endinness.
 */
struct __be32 {
	u32 val;
} __attribute__((packed));
typedef struct __be32 be32;

/*
 * These two obviously need to get fixed for
 * big endian machines.
 */
u32 be32_to_u32(be32 src)
{
	return swap_bytes(src.val);
}
be32 u32_to_be32(u32 src)
{
	be32 ret;
	ret.val = swap_bytes(src);
	return ret;
}

void dumpbuf(const char *buffer, int bytesToWrite)
{
    int i;
    static char linebuf[500];

    for (i=0; i < bytesToWrite; i += 16) {
        char *tmpbuf = &linebuf[0];
        unsigned long sum = 0;
        int j;
#define lprintf(args...)        do {            \
        tmpbuf += sprintf(tmpbuf, ## args);\
} while (0)

        lprintf("[%03d]: ", i);
        for (j=0; j < 16; j++) {
                u8 c = ((unsigned char *)buffer)[i+j];
                lprintf("%02x ", (unsigned int)c);
                sum += c;
        }
        lprintf(" |");
        for (j=0; j < 16; j++) {
                u8 c = ((unsigned char *)buffer)[i+j];
                if (c >= 'a' && c <= 'z')
                        lprintf("%c", c);
                else if (c >= 'A' && c <= 'Z')
                        lprintf("%c", c);
                else if (c >= '0' && c <= '9')
                        lprintf("%c", c);
                else if (c >= 0x20 && c <= 127)
                        lprintf("%c", c);
                else
                        lprintf(".");
        }
        lprintf("|\n");
        if (sum == 0)
                continue;
        printf("%s", linebuf);
        //if (i > 200)
        //      break;
    }
}

struct card_seq_num {
	u32 seq;
} __attribute__((packed));

void read_from(enum eyefi_file);
void write_to(enum eyefi_file, void *, int);
struct card_seq_num read_seq_from(enum eyefi_file file)
{
	struct card_seq_num *ret;
	read_from(file);
	ret = buf;
	return *ret;
}

/*
 * For O_DIRECT writes to files, we need
 * to be 512 byte aligned on Linux, I think.
 * So, just align this to something big
 * and be done with it.  FIXME :)
 */
void align_buf(void)
{
	unsigned long addr = (unsigned long)&unaligned_buf[BUFSZ];
	addr &= ~(BUFSZ-1);
	buf = (void *)addr;
	debug_printf(4, "buf: %p\n", buf);
	debug_printf(4, "unaligned: %p\n", &unaligned_buf[0]);
}

struct card_seq_num seq;

/*
 * The real manager does this so we might
 * as well, too.
 */
void zero_card_files(void)
{
	write_to(REQM, buf, BUFSZ);
	write_to(REQC, buf, BUFSZ);
	write_to(RSPM, buf, BUFSZ);
	write_to(RSPC, buf, BUFSZ);

	read_from(REQM);
	read_from(REQC);
	read_from(RSPM);
	read_from(RSPC);
}

char lower(char c)
{
	if ((c >= 'A') && (c <= 'Z'))
		c += ('a' - 'A');
	return c;
}

int atoh(char c)
{
	char lc = lower(c);
	if ((c >= '0') && (c <= '9'))
		return c - '0';
	else if ((c >= 'a') && (c <= 'z'))
		return (c - 'a') + 10;
	debug_printf(5, "non-hex character: '%c'/'%c'\n", c, lc);
	return -1;
}

int atoo(char o)
{
	if ((o >= '0') && (o <= '7'))
		return atoh(o);
	return -1;
}

int octal_esc_to_chr(char *input) {
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

char *replace_escapes(char *str)
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

#define LINEBUFSZ 1024
char *locate_eyefi_mount(void)
{
	char line[LINEBUFSZ];
	FILE *mounts = fopen("/proc/mounts", "r");

	char dev[LINEBUFSZ];
	char mnt[LINEBUFSZ];
	char fs[LINEBUFSZ];
	char opt[LINEBUFSZ];
	int foo;
	int bar;
	
	if (strlen(eyefi_mount))
		return &eyefi_mount[0];

	while (fgets(&line[0], 1023, mounts)) {
		int read;
		read = sscanf(&line[0], "%s %s %s %s %d %d",
				&dev[0], &mnt[0], &fs[0], &opt[0],
				&foo, &bar);
		// only look at fat filesystems:
		if (strcmp(fs, "msdos") && strcmp(fs, "vfat")) {
			debug_printf(2, "fs at '%s' is not fat, skipping...\n", mnt);
			continue;
		}
		// Linux's /proc/mounts has spaces like this \040
		replace_escapes(&mnt[0]);
		char *file = eyefi_file_on(REQM, &mnt[0]);
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
		strcpy(&eyefi_mount[0], &mnt[0]);
		debug_printf(1, "located EyeFi card at: '%s'\n", eyefi_mount);
		break;
	}
	fclose(mounts);
	if (strlen(eyefi_mount))
		return &eyefi_mount[0];
	return NULL;
}

void init_card()
{
	char *mnt;
	if (buf != NULL)
		return;

	debug_printf(2, "Initializing card...\n");
	mnt = locate_eyefi_mount();
	if (mnt == NULL) {
		debug_printf(1, "unable to locate Eye-Fi card\n");
		if (debug_level < 5)
			debug_printf(0, "please run with '-d5' option and report the output\n");
		else {
			debug_printf(0, "----------------------------------------------\n");
			debug_printf(0, "Debug information:\n");
			system("cat /proc/mounts >&2");
		}
		exit(1);
	}

	align_buf();
	zero_card_files();
	seq = read_seq_from(RSPC);
	if (seq.seq == 0)
		seq.seq = 0x1234;
	debug_printf(2, "Done initializing card...\n");
}

static char *eyefi_file(enum eyefi_file file)
{
	init_card();
	return eyefi_file_on(file, &eyefi_mount[0]);
}

void open_error(char *file)
{
	fprintf(stderr, "unable to open '%s'\n", file);
	fprintf(stderr, "Is the Eye-Fi card inserted and mounted at: %s ?\n", eyefi_mount);
	fprintf(stderr, "Do you have write permissions to it?\n");
	fprintf(stderr, "debug information:\n");
	if (debug_level > 0)
		system("cat /proc/mounts >&2");
	if (debug_level > 1)
		perror("bad open");
	exit(1);
}

void read_from(enum eyefi_file __file)
{
	u8 c;
	int i;
	int ret, retcntl;
	int fd;
	int zeros = 0;
	char *file = eyefi_file(__file);
	
	init_card();

	fd = open(file, O_RDONLY);
	if (fd < 0) 
		open_error(file);
	retcntl = fcntl(fd, F_SETFL, O_DIRECT);
	if (retcntl < 0) {
		perror("bad fcntl");
		exit(1);
	}
	ret = read(fd, buf, BUFSZ);
	if (debug_level > 3)
		dumpbuf(buf, 128);
	if (ret < 0) {
		perror("bad read");
		exit(1);
	}
	debug_printf(3, "read '%s': bytes: %d fcntl: %d\n", file, ret, retcntl);
	for (i=0; i < BUFSZ; i++) {
		c = ((char *)buf)[i];
		if (c == '\0') {
			zeros++;
			continue;
		}
	}
	//if (zeros)
	//	printf(" zeros: %d", zeros);
	//fsync(fd);
	free(file);
	close(fd);
}

void write_to(enum eyefi_file __file, void *stuff, int len)
{
	int ret;
	int fd;
	char *file;

	init_card();
       	file = eyefi_file(__file);
	if (len == -1)
		len = strlen(stuff);

	if (debug_level > 3) {
		debug_printf(3, "%s('%s', ..., %d)\n", __func__, file, len);
		dumpbuf(stuff, len);
	}
	memset(buf, 0, BUFSZ);
	memcpy(buf, stuff, len);
	fd = open(file, O_RDWR|O_DIRECT|O_CREAT, 0600);
	//ret = lseek(fd, 0, SEEK_SET);
	if (fd < 0)
		open_error(file);
	if (debug_level > 3)
		dumpbuf(buf, 128);
	ret = write(fd, buf, BUFSZ);
	//fsync(fd);
	close(fd);
	debug_printf(3, "wrote %d bytes to '%s' (string was %d bytes)\n", ret, file, len);
	if (ret < 0)
		exit(ret);
	free(file);
}	

/*
 * Most of the eyefi strings are pascal-style with
 * a length byte preceeding content.  (Did pascal
 * have just a byte for length or more??)
 */
struct pascal_string {
	u8 length;
	u8 value[32];
} __attribute__((packed));

void print_pascal_string(struct pascal_string *str)
{
	int i;
	for (i = 0; i < str->length; i++)
		printf("%c", str->value[i]);
}

/*
 * The 'o' command has several sub-commands:
 */
enum card_info_subcommand {
	MAC_ADDRESS   = 1,
	FIRMWARE_INFO = 2,
	CARD_KEY      = 3,
	API_URL       = 4,
	UNKNOWN1      = 5, // Chris says these are 
	UNKNOWN2      = 6, // checksums
	LOG_LEN	      = 7,
};

struct card_info_req {
	u8 o;
	u8 subcommand;
} __attribute__((packed));

struct card_info_rsp_key {
	struct pascal_string key;
};

#define MAC_BYTES 6
struct mac_address {
	u8 length;
	u8 mac[MAC_BYTES];
} __attribute__((packed));

struct card_info_api_url {
	struct pascal_string key;
};

struct card_info_log_len {
	u8 len;
	be32 val;
} __attribute__((packed));

#define write_struct(file, s) write_to((file), s, sizeof(*(s)))

void print_mac(struct mac_address *mac)
{
	int i;
	for (i=0; i < MAC_BYTES-1; i++) {
		printf("%02x:", mac->mac[i]);
	}
	printf("%02x\n", mac->mac[i]);
}

void inc_seq(void)
{
	//u32 tmpseq = be32_to_u32(seq.seq);
	//seq.seq = u32_to_be32(tmpseq+1);
	seq.seq++;
	write_struct(REQC, &seq);
}

u32 current_seq(void)
{
	return seq.seq;
}

void wait_for_response(void)
{
	int i;
	debug_printf(3, "waiting for response...\n");
	inc_seq();
	for (i = 0; i < 50; i++) {
		struct card_seq_num cardseq = read_seq_from(RSPC);
		u32 rsp = cardseq.seq;
		debug_printf(3, "read rsp code: %lx, looking for: %lx raw: %lx\n", rsp, current_seq(),
				cardseq.seq);
		if (rsp == current_seq())
			break;
		usleep(300000);
	}
	debug_printf(3, "got good seq, reading RSPM...\n");
	read_from(RSPM);
	debug_printf(3, "done reading RSPM\n");
}
struct byte_response {
	u8 response;
};

enum net_type {
	UNSECURED,
	WEP,
	WPA,
	WPA2
};

#define ESSID_LEN 32
struct scanned_net {
	char essid[ESSID_LEN];
	signed char strength;
	u8 type;
} __attribute__((packed));

struct scanned_net_list {
	u8 nr;
	struct scanned_net nets[100];
} __attribute__((packed));

struct configured_net {
	char essid[ESSID_LEN];
} __attribute__((packed));

struct configured_net_list {
	u8 nr;
	struct configured_net nets[100];
} __attribute__((packed));

char *net_test_states[] = {
	"not scanning",
	"locating network",
	"verifying network key",
	"waiting for DHCP",
	"testing connection to Eye-Fi server",
	"success",
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

char *net_test_state_name(u8 state)
{
	int size = ARRAY_SIZE(net_test_states);
	if (state >= size)
		return "unknown";
	return net_test_states[state];
}

char *net_types[] = {
	"No security",
	"WEP",
	"WPA",
	"unknown1",
	"WPA2",
};

char *net_type_name(u8 type)
{
	int size = ARRAY_SIZE(net_types);
	if (type >= size)
		return "unknown";
	return net_types[type];
}

#define WPA_KEY_BYTES 32
struct wpa_key {
	u8 key[WPA_KEY_BYTES];
} __attribute((packed));

#define WEP_KEY_BYTES 32
struct wep_key {
	u8 key[WEP_KEY_BYTES];
} __attribute((packed));

struct network_key {
	u8 len;
	union {
		struct wpa_key wpa;
		struct wep_key wep;
	};
} __attribute((packed));

#define KEY_LEN 32
struct net_request {
	char req;
	u8 essid_len;
	char essid[ESSID_LEN];
	struct network_key key;
} __attribute((packed));

/*
 * Take a string like "0ab1" and make it
 * a series of bytes: { 0x0a, 0xb1 }
 *
 * @len is the strlen() of the ascii
 *
 * Destroys the original string.
 */
char *convert_ascii_to_hex(char *ascii, int len)
{
	int i;
	if (len%2) {
		fprintf(stderr, "%s() must be even number of bytes: %d\n",
		__func__, len);
		exit(2);
	}
	for (i=0; i < len; i+=2) {
		int high = atoh(ascii[i]);
		int low  = atoh(ascii[i+1]);
		u8 byte = (high<<4 | low);
		if (high < 0 || low < 0)
			return NULL;
		debug_printf(6, "high: %02x low: %02x, both: %02x\n", high, low, byte);
		ascii[i/2] = byte;
	}
	for (i=len/2; i < len; i++)
		ascii[i] = '\0';
	return &ascii[0];
}

#define PASSPHRASE_PROG "wpa_passphrase"

struct wpa_key *make_wpa_key(char *essid, char *pass)
{
	struct wpa_key *key = malloc(sizeof(*key));

	if (strlen(pass) == WPA_KEY_BYTES*2) {
		char *hex_pass;
		debug_printf(2, "Interpreting password as hex WPA key\n");
		hex_pass = convert_ascii_to_hex(pass, WPA_KEY_BYTES*2);
		if (!hex_pass)
			return NULL;
		memcpy(&key->key[0], pass, WPA_KEY_BYTES);
	} else {
		debug_printf(2, "Interpreting password as ASCII WPA key\n");
	        pbkdf2_sha1(pass, essid, strlen(essid), 4096,
			    &key->key[0], WPA_KEY_BYTES);
	}
	return key;
}

void card_info_cmd(enum card_info_subcommand cmd)
{
	struct card_info_req cir;
	cir.o = 'o';
	cir.subcommand = cmd;

	write_struct(REQM, &cir);
	wait_for_response();
}

u32 fetch_log_length(void)
{
	card_info_cmd(LOG_LEN);
	struct card_info_log_len *loglen = buf;
	return be32_to_u32(loglen->val);
}

void print_log_len(void)
{
	u32 len = fetch_log_length();
	printf("log len: %08lx\n", len);
}

void print_card_mac(void)
{
	debug_printf(2, "%s()\n", __func__);
	card_info_cmd(MAC_ADDRESS);
	struct mac_address *mac = buf;
	assert(mac->length == MAC_BYTES);
	printf("card mac address: ");
	print_mac(mac);
}

void print_card_key(void)
{
	debug_printf(2, "%s()\n", __func__);
	card_info_cmd(CARD_KEY);
	struct card_info_rsp_key *foo = buf;
	printf("card key (len: %d): '", foo->key.length);
	print_pascal_string(&foo->key);
	printf("'\n");
}

struct noarg_request {
	u8 req;
};

void issue_noarg_command(u8 cmd)
{
	struct noarg_request req;
	req.req = cmd;
	write_struct(REQM, &req);
	wait_for_response();
}

void scan_print_nets(void)
{
	int i;

	debug_printf(2, "%s()\n", __func__);
	issue_noarg_command('g');
	struct scanned_net_list *scanned = buf;
	if (scanned->nr == 0) {
		printf("unable to detect any wireless networks\n");
		return;
	}
	printf("Scanned wireless networks:\n");
	for (i=0; i < scanned->nr; i++) {
		struct scanned_net *net = &scanned->nets[i];
		printf("'%s' type(%d): %s, strength: %d\n", net->essid,
				net->type,
				net_type_name(net->type),
				net->strength);
	}
}

void print_configured_nets(void)
{
	int i;
	struct configured_net_list *configured;

	debug_printf(2, "%s()\n", __func__);
	issue_noarg_command('l');
       	configured = buf;
	if (configured->nr == 0) {
		printf("No wireless networks configured on card\n");
		return;
	}
	printf("configured wireless networks:\n");
	for (i=0; i < configured->nr; i++) {
		struct configured_net *net = &configured->nets[i];
		printf("'%s'\n", net->essid);
	}
}

void reboot_card(void)
{
	debug_printf(2, "%s()\n", __func__);
	issue_noarg_command('b');
}

void copy_wep_key(struct wep_key *dst, struct wep_key *src)
{
  	memcpy(&dst->key, &src->key, sizeof(*dst));
}

void copy_wpa_key(struct wpa_key *dst, struct wpa_key *src)
{
  	memcpy(&dst->key, &src->key, sizeof(*dst));
}

void network_action(char cmd, char *essid, char *wpa_ascii)
{
	struct net_request nr;
	memset(&nr, 0, sizeof(nr));

	nr.req = cmd;
	strcpy(&nr.essid[0], essid);
	nr.essid_len = strlen(essid);
	struct wpa_key *wpakey;
	if (wpa_ascii) {
       		wpakey = make_wpa_key(essid, wpa_ascii);
		nr.key.len = sizeof(*wpakey);
		copy_wpa_key(&nr.key.wpa, wpakey);
	}
	write_struct(REQM, &nr);
	wait_for_response();
}

void add_network(char *essid, char *wpa_ascii)
{
	debug_printf(2, "%s()\n", __func__);
	network_action('a', essid, wpa_ascii);
}

void remove_network(char *essid)
{
	debug_printf(2, "%s()\n", __func__);
	network_action('d', essid, NULL);
}

int try_connection_to(char *essid, char *wpa_ascii)
{
	int i;
	int ret = -1;

	char *type = net_type_name(WPA);
	if (!wpa_ascii)
		type = net_type_name(UNSECURED);
	printf("trying to connect to %s network: '%s'", type, essid);
	if (wpa_ascii)
	       	printf(" with passphrase: '%s'", wpa_ascii);
	fflush(NULL);

	// test network
	network_action('t', essid, wpa_ascii);
	u8 last_rsp = -1;

	char rsp = '\0';
	for (i=0; i < 200; i++) {
		struct byte_response *r;
		issue_noarg_command('s');
		r = buf;
		rsp = r->response;
		char *state = net_test_state_name(rsp);
		if (rsp == last_rsp) {
			printf(".");
			fflush(NULL);;
		} else {
			if (rsp)
				printf("\nTesting connecion to '%s' (%d): %s", essid, rsp, state);
			last_rsp = rsp;
		}
		
		if (!strcmp("success", state)) {
			ret = 0;
			break;
		}
		if (!strcmp("not scanning", state))
			break;
		if (!strcmp("unknown", state))
			break;
	}
	printf("\n");
	if (!ret) {
		printf("Succeeded connecting to: '%s'\n", essid);
	} else {
		printf("Unable to connect to: '%s' (final state: %d/'%s')\n", essid,
				rsp, net_test_state_name(rsp));
	}
	return ret;
}

struct fetch_log_cmd {
	char m;
	be32 offset;
} __attribute__((packed));

/*
 * When you ask for the log at offset 0x0, you
 * get back 8 bytes of offsets into the rest of
 * the data
 */
struct first_log_response {
	be32 log_end;
	be32 log_start;
	u8 data[EYEFI_BUF_SIZE-8];
} __attribute__((packed));

struct rest_log_response {
	u8 data[EYEFI_BUF_SIZE];
} __attribute__((packed));

unsigned char *get_log_at_offset(u32 offset)
{
	struct fetch_log_cmd cmd;
	cmd.m = 'm';
	cmd.offset = u32_to_be32(offset);

	debug_printf(2, "getting log at offset: %08lx\n", offset);
	write_struct(REQM, &cmd);
	wait_for_response();
	return buf;
}

int get_log(void)
{
	int total_bytes = 0;
	int i;
	u32 log_start;
	u32 log_end;
	u32 log_size = fetch_log_length();
	char *resbuf = malloc(log_size);

	int nr_bufs_per_log = log_size/EYEFI_BUF_SIZE;
	for (i = 0; i < log_size/EYEFI_BUF_SIZE; i++) {
		debug_printf(1, "fetching EyeFi card log part %d/%d...",
				i+1, nr_bufs_per_log);
		fflush(NULL);
		get_log_at_offset(EYEFI_BUF_SIZE*i);
		debug_printf(1, "done\n");
		u32 log_size;
		u8 *log_data;
		if (i == 0) {
			struct first_log_response *log = buf;
			log_end = be32_to_u32(log->log_end);
			log_start = be32_to_u32(log->log_start);
			debug_printf(2, "log end:   0x%04lx\n", log_end);
			debug_printf(2, "log start: 0x%04lx\n", log_start);
			log_data = &log->data[0];
			log_size = ARRAY_SIZE(log->data);
		} else {
			struct rest_log_response *log = buf;
			log_data = &log->data[0];
			log_size = ARRAY_SIZE(log->data);
		}
		debug_printf(3, "writing %ld bytes to resbuf[%d]\n",
				log_size, total_bytes);
		memcpy(&resbuf[total_bytes], log_data, log_size);
		total_bytes += log_size;
	}
	// The last byte *should* be a null, and the 
	// official software does not print it.
	for (i = 0; i < total_bytes-1; i++) {
		int offset = (log_start+i)%total_bytes;
		char c = resbuf[offset];
		// the official software converts UNIX to DOS-style
		// line breaks, so we'll do the same
		if (c == '\n')
			printf("%c", '\r');
		printf("%c", c);
	}
	printf("\n");
	// just some simple sanity checking to make sure what
	// we are fetching looks valid
	int null_bytes_left = 20;
	if (resbuf[log_end] != 0) {
		debug_printf(2, "error: unexpected last byte (%ld/0x%lx) of log: %02x\n",
				log_end, log_end, resbuf[log_end]);
		for (i=0; i<log_size; i++) {
			if (resbuf[i])
				continue;
			if (null_bytes_left <= 0)
				continue;
			null_bytes_left--;
			debug_printf(2, "null byte %d\n", i);
		}
	}
	free(resbuf);
	return 0;
}

void usage(void)
{
	printf("Usage:\n");
	printf("  eyefitest [OPTIONS]\n");
	printf("  -a ESSID	add network (implies test unless --force)\n");
	printf("  -t ESSID	test network\n");
	printf("  -p KEY	set WPA key for add/test\n");
	printf("  -r ESSID	remove network\n");
	printf("  -s		scan for networks\n");
	printf("  -c		list configured networks\n");
	printf("  -b		reboot card\n");
	printf("  -d level	set debugging level (default: 1)\n");
	printf("  -k		print card unique key\n");
	printf("  -l		dump card log\n");
	printf("  -m		print card mac\n");
	exit(4);
}

int main(int argc, char **argv)
{
	if (argc == 1)
		usage();

	debug_printf(3, "%s starting...\n", argv[0]);
	
	//static int passed_wep = 0;
	//static int passed_wpa = 0;
	static int force = 0;
	static struct option long_options[] = {
		//{"wep", 'x', &passed_wep, 1},
		//{"wpa", 'y', &passed_wpa, 1},
		{"force", 0, &force, 1},
		{"help", 'h', NULL, 1},
	};

        int option_index;
        char c;
	char *essid = NULL;
	char *passwd = NULL;
	char network_action = 0;
        debug_printf(3, "about to parse arguments\n");
        while ((c = getopt_long_only(argc, argv, "a:bcd:klmp:r:st:",
                        &long_options[0], &option_index)) != -1) {
        	debug_printf(3, "argument: '%c' %d optarg: '%s'\n", c, c, optarg);
		switch (c) {
		case 0:
			// was a long argument
			break;
		case 'a':
		case 't':
		case 'r':
			essid = optarg;
			network_action = c;
			break;
		case 'b':
			reboot_card();
			break;
		case 'c':
			print_configured_nets();
			break;
		case 'd':
			debug_level = atoi(optarg);
			fprintf(stderr, "set debug level to: %d\n", debug_level);
			break;
		case 'k':
			print_card_key();
			break;
		case 'l':
			get_log();
			break;
		case 'm':
			print_card_mac();
			break;
		case 'p':
			passwd = optarg;
			break;
		case 's':
			scan_print_nets();
			break;
		case 'h':
		default:
			usage();
			break;
		}
	}
	debug_printf(3, "after arguments essid: '%s' passwd: '%s'\n", essid, passwd);
	if (network_action && essid) {
		int ret = 0;
		init_card();
		switch (network_action) {
		case 't':
			ret = try_connection_to(essid, passwd);
			break;
		case 'a':
			if (!force) {
				ret = try_connection_to(essid, passwd);
			} else {
				debug_printf(1, "forced: skipping network test\n");
			}
			if (ret) {
				printf("Error connecting to network '%s', not adding.\n", essid);
				printf("use --force to override\n");
				break;
			}
			add_network(essid, passwd);
			break;
		case 'r':
			remove_network(essid);
			break;
		}
	}
	return 0;
}


