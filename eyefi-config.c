/*
 * eyefi-config.c
 *
 * Copyright (C) 2008 Dave Hansen <dave@sr71.net>
 *
 * This software may be redistributed and/or modified under the terms of
 * the GNU General Public License ("GPL") version 2 as published by the
 * Free Software Foundation.
 */

#include "eyefi-config.h"

int eyefi_debug_level = 1;

int eyefi_printf(const char *fmt, ...)
{
        va_list args;
        int r;

        va_start(args, fmt);
        r = vprintf(fmt, args);
        va_end(args);

        return r;
}

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

char *eyefi_file_on(enum eyefi_file file, char *mnt)
{
	char *filename = eyefi_file_name(file);
	char *full = malloc(PATHNAME_MAX);

	if (!full)
		return NULL;

	sprintf(&full[0], "%s/EyeFi/%s", mnt, filename);
	debug_printf(4, "eyefile nr: %d on '%s' is: '%s'\n", file, mnt, &full[0]);
	return full;
}

/*
 * This lets us get away with a static allocation
 * for the buffer.  We make it size*2 so that we're
 * guaranteed to be able to get a "size" buffer
 * aligned inside of the larger one.
 */
static char unaligned_buf[EYEFI_BUF_SIZE*2];
static void *eyefi_buf;

void *eyefi_response(void)
{
	return eyefi_buf;
}

int __dumpbuf(const char *buffer, int bytesToWrite, int per_line)
{
    int ret = 0;
    int i;
    static char linebuf[500];

    for (i=0; i < bytesToWrite; i += per_line) {
        char *tmpbuf = &linebuf[0];
        unsigned long sum = 0;
        int j;
#define lprintf(args...)        do {            \
        tmpbuf += sprintf(tmpbuf, ## args);\
} while (0)

        lprintf("[%03d]: ", i);
        for (j=0; j < per_line; j++) {
                u8 c = ((unsigned char *)buffer)[i+j];
                lprintf("%02x ", (unsigned int)c);
                sum += c;
        }
        lprintf(" |");
        for (j=0; j < per_line; j++) {
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
        ret += printf("%s", linebuf);
        //if (i > 200)
        //      break;
    }
    return ret;
}

int dumpbuf(const char *buffer, int bytesToWrite)
{
	return __dumpbuf(buffer, bytesToWrite, 16);
}

void read_from(enum eyefi_file);
void write_to(enum eyefi_file, void *, int);

struct card_seq_num eyefi_seq;
struct card_seq_num read_seq_from(enum eyefi_file file)
{
	struct card_seq_num *ret;
	read_from(file);
	ret = eyefi_buf;
	return *ret;
}

/*
 * For O_DIRECT writes to files, we need
 * to be 512 byte aligned on Linux, I think.
 * So, just align this to something big
 * and be done with it.  FIXME :)
 *
 * This probably isn't necessary on chdk,
 * since I don't think it buffers I/O at
 * all.
 */
void align_buf(void)
{
	unsigned long addr = (unsigned long)&unaligned_buf[EYEFI_BUF_SIZE];
	addr &= ~(EYEFI_BUF_SIZE-1);
	eyefi_buf = (void *)addr;
	debug_printf(4, "buf: %p\n", eyefi_buf);
	debug_printf(4, "unaligned: %p\n", &unaligned_buf[0]);
}

/*
 * The real manager does this so we might
 * as well, too.
 */
void zero_card_files(void)
{
	char zbuf[EYEFI_BUF_SIZE];

	memset(&zbuf[0], 0, EYEFI_BUF_SIZE);
	write_to(REQM, zbuf, EYEFI_BUF_SIZE);
	write_to(REQC, zbuf, EYEFI_BUF_SIZE);
	write_to(RSPM, zbuf, EYEFI_BUF_SIZE);
//	write_to(RSPC, zbuf, EYEFI_BUF_SIZE);

	read_from(REQM);
	read_from(REQC);
	read_from(RSPM);
//	read_from(RSPC);
}

void init_card()
{
	char *mnt;
	if (eyefi_buf != NULL)
		return;

	debug_printf(2, "Initializing card...\n");
	mnt = locate_eyefi_mount();
	if (mnt == NULL)
		return;

	align_buf();
	zero_card_files();
	eyefi_seq = read_seq_from(RSPC);
	if (eyefi_seq.seq == 0)
		eyefi_seq.seq = 0x1234;
	eyefi_seq.seq++;
	debug_printf(2, "Done initializing card...\n");
	debug_printf(2, "seq was: %04x\n", eyefi_seq.seq);
}

static char *eyefi_file(enum eyefi_file file)
{
	init_card();
	return eyefi_file_on(file, locate_eyefi_mount());
}

void read_from(enum eyefi_file __file)
{
	int ret;
	int fd;
	char *file = eyefi_file(__file);

	init_card();

retry:
	fd = open(file, O_RDONLY);
	if (fd < 0)
		open_error(file, fd);
	fd_flush(fd);
	ret = read(fd, eyefi_buf, EYEFI_BUF_SIZE);
	if (eyefi_debug_level > 3)
		dumpbuf(eyefi_buf, 128);
	if (ret < 0) {
		close(fd);
		perror("bad read, retrying...");
		goto retry;
		exit(1);
	}
	debug_printf(4, "read '%s': bytes: %d\n", file, ret);
	/*
	 * There was a time when I was carefully recording how each response
	 * looked, and I counted the zeros in each response.  I don't care
	 * any more.
	u8 c;
	int zeros = 0;
	int i;
	for (i=0; i < EYEFI_BUF_SIZE; i++) {
		c = ((char *)eyefi_buf)[i];
		if (c == '\0') {
			zeros++;
			continue;
		}
	}
	*/
	free(file);
	close(fd);
}

int fake_write = 0;
void write_to(enum eyefi_file __file, void *stuff, int len)
{
	int ret;
	int wrote;
	int fd;
	char *file;

	if (fake_write)
		return;

	init_card();
       	file = eyefi_file(__file);
	if (len == -1)
		len = strlen(stuff);

	if (eyefi_debug_level > 3) {
		debug_printf(3, "%s('%s', ..., %d)\n", __func__, file, len);
		dumpbuf(stuff, len);
	}
	memset(eyefi_buf, 0, EYEFI_BUF_SIZE);
	memcpy(eyefi_buf, stuff, len);
	fd = open(file, O_RDWR|O_CREAT, 0600);
	if (fd < 0 )
		open_error(file, fd);
	if (eyefi_debug_level > 3)
		dumpbuf(eyefi_buf, 128);
	wrote = write(fd, eyefi_buf, EYEFI_BUF_SIZE);
	if (wrote < 0)
		open_error(file, wrote);
	ret = fd_flush(fd);
	if (ret < 0)
		open_error(file, ret);
	close(fd);
	debug_printf(3, "wrote %d bytes to '%s' (string was %d bytes)\n", wrote, file, len);
	if (ret < 0) {
		fprintf(stderr, "error writing to '%s': ", file);
		perror("");
		exit(ret);
	}
	free(file);
}

#define write_struct(file, s) write_to((file), s, sizeof(*(s)))

void inc_seq(void)
{
	/*
	 * Oddly enough, the sequence number appears
	 * to be of normal endianness.
	 */
	//u32 tmpseq = be32_to_u32(seq.seq);
	//seq.seq = u32_to_be32(tmpseq+1);
	eyefi_seq.seq++;
	write_struct(REQC, &eyefi_seq);
}

u32 eyefi_current_seq(void)
{
	return eyefi_seq.seq;
}

int wait_for_response(void)
{
	int good_rsp = 0;
	u32 rsp = 0;
	int i;
	debug_printf(3, "waiting for response...\n");
	inc_seq();
	for (i = 0; i < 50; i++) {
		struct card_seq_num cardseq = read_seq_from(RSPC);
		debug_printf(3, "read rsp code: %x, looking for: %x raw: %x\n", rsp, eyefi_current_seq(),
				cardseq.seq);
		rsp = cardseq.seq;
		if (rsp == eyefi_current_seq()) {
			good_rsp = 1;
			break;
		}
		if (eyefi_debug_level > 4) {
			read_from(REQM);
			debug_printf(1, "command issued was: '%c'\n", ((char *)eyefi_buf)[0]);
		}
		usleep(300000);
	}
	if (!good_rsp) {
		debug_printf(1, "never saw card seq response\n");
		return -1;
	}
	debug_printf(3, "got good seq (%d), reading RSPM...\n", rsp);
	read_from(RSPM);
	debug_printf(3, "done reading RSPM\n");
	return 0;
}

char *net_test_states[] = {
       "not scanning",
       "locating network",
       "verifying network key",
       "waiting for DHCP",
       "testing connection to Eye-Fi server",
       "success",
};

char *net_test_state_name(u8 state)
{
	int size = ARRAY_SIZE(net_test_states);
	if (state >= size)
		return "unknown";
	return net_test_states[state];
}

const char *net_types[] = {
	"none",
	"WEP",
	"WPA",
	"unknown1",
	"WPA2",
};
const char net_type_unknown[] = "unknown";

const char *net_type_name(u8 type)
{
	int size = ARRAY_SIZE(net_types);
	debug_printf(3, "%s(%d): '%s' size: %d\n", __func__, type, net_types[type], size);
	if (type >= size)
		return net_type_unknown;
	return net_types[type];
}

static char lower(char c)
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
	else if ((lc >= 'a') && (lc <= 'z'))
		return (lc - 'a') + 10;
	debug_printf(5, "non-hex character: '%c'/'%c'\n", c, lc);
	return -1;
}

/*
 * Take a string like "0ab1" and make it
 * a series of bytes: { 0x0a, 0xb1 }
 *
 * @len is the strlen() of the ascii
 *
 * Destroys the original string.
 */
char *convert_ascii_to_hex(char *ascii)
{
	int i;
	char *hex;
	int len = strlen(ascii);

	// Make it just as long as the ASCII password, even though it
	// will only end up half as long
	hex = strdup(ascii);
	if (len%2) {
		fprintf(stderr, "%s() must be even number of bytes: %d\n",
		__func__, len);
		exit(2);
	}
	for (i=0; i < len; i+=2) {
		int high = atoh(ascii[i]);
		int low  = atoh(ascii[i+1]);
		u8 byte = (high<<4 | low);
		if (high < 0 || low < 0) {
			fprintf(stderr, "unable to parse hex string: '%s'\n", ascii);
			return NULL;
		}
		debug_printf(6, "high: %02x low: %02x, both: %02x\n", high, low, byte);
		hex[i/2] = byte;
	}
	for (i=len/2; i < len; i++)
		hex[i] = '\0';
	return hex;
}

int make_network_key(struct network_key *key, char *essid, char *pass)
{
	char *hex_pass;
	int pass_len = strlen(pass);
	memset(key, 0, sizeof(*key));

	eyefi_printf(" interpreting passphrase as ");
	switch (pass_len) {
		case WPA_KEY_BYTES*2:
			eyefi_printf("hex WPA");
			hex_pass = convert_ascii_to_hex(pass);
			if (!hex_pass)
				return -EINVAL;
			key->len = pass_len/2;
			memcpy(&key->wpa.key[0], hex_pass, key->len);
			free(hex_pass);
			break;
		case WEP_KEY_BYTES*2:
		case WEP_40_KEY_BYTES*2:
			eyefi_printf("hex WEP");
			hex_pass = convert_ascii_to_hex(pass);
			if (!hex_pass)
				return -EINVAL;
			key->len = pass_len/2;
			memcpy(&key->wep.key[0], hex_pass, key->len);
			free(hex_pass);
			break;
		default:
			eyefi_printf("ASCII WPA");
		        pbkdf2_sha1(pass, essid, strlen(essid), 4096,
				    &key->wpa.key[0], WPA_KEY_BYTES);
			key->len = WPA_KEY_BYTES;
			break;
	}
	eyefi_printf(" key (%d bytes)\n", key->len);
	assert(key->len != 0);
	return 0;
}

int card_info_cmd(enum card_info_subcommand cmd)
{
	struct card_info_req cir;
	cir.o = 'o';
	cir.subcommand = cmd;

	write_struct(REQM, &cir);
	return wait_for_response();
}

u32 fetch_log_length(void)
{
	debug_printf(3, "%s()\n", __func__);
	card_info_cmd(LOG_LEN);
	struct card_info_log_len *loglen = eyefi_buf;
	return be32_to_u32(loglen->val);
}

struct card_firmware_info *fetch_card_firmware_info(void)
{
	debug_printf(2, "%s()\n", __func__);
	card_info_cmd(FIRMWARE_INFO);
	return (struct card_firmware_info *)eyefi_buf;
	return NULL;
}

int card_config_set(enum card_info_subcommand cmd, struct var_byte_response *args)
{
	struct card_config_cmd req;
	req.O = 'O';
	req.subcommand = cmd;
	req.arg.len = args->len;
	memcpy(&req.arg.bytes[0], &args->bytes[0], args->len);

	write_struct(REQM, &req);
	return wait_for_response();
}

void fill_with_int(struct var_byte_response *arg, int fill)
{
	// TODO bounds check the int
	arg->len = 1;
	arg->bytes[0].response = fill;
}

#define ENDLESS_ENABLED_BIT	0x80
int __set_endless_percentage(u8 raw)
{
	struct var_byte_response arg;
	fill_with_int(&arg, raw);
	return card_config_set(ENDLESS, &arg);
}

u8 __get_endless_percentage(void)
{
	u8 result;
	struct var_byte_response *rsp;
	card_info_cmd(ENDLESS);
	rsp = eyefi_buf;
	result = rsp->bytes[0].response;
	return result;
}

int set_endless_percentage(int __percentage)
{
	u8 raw = __get_endless_percentage();
	u8 per = __percentage;
	raw &= ENDLESS_ENABLED_BIT;
	raw |= per;
	return __set_endless_percentage(raw);
}

int endless_enable(int enable)
{
	u8 raw = __get_endless_percentage();
	if (enable)
		raw |= ENDLESS_ENABLED_BIT;
	else
		raw &= ~ENDLESS_ENABLED_BIT;
	return __set_endless_percentage(raw);
}

void print_endless(void)
{
	u8 raw = __get_endless_percentage();
	int enabled = (raw & ENDLESS_ENABLED_BIT);
	int percent = (raw & ~ENDLESS_ENABLED_BIT);

	printf("endless: ");
	if (enabled)
		printf("ENABLED");
	else
		printf("DISABLED");

	printf(", triggers at %d%% full\n", percent);
}


void wlan_disable(int do_disable)
{
	/*
	 * This is complete voodoo to me.  I've only ever seen
	 * a single example of this, so it's hard to figure out
	 * the structure at all.
	 */
	char new_cmd[] = {'O', 0x0a, do_disable};
	write_to(REQM, &new_cmd[0], 3);
        wait_for_response();
}

int wlan_enabled(void)
{
	struct var_byte_response *rsp;
        card_info_cmd(WLAN_ENABLED);
        rsp = eyefi_buf;
	return rsp->bytes[0].response;
}

enum transfer_mode fetch_transfer_mode(void)
{
	struct var_byte_response *rsp;
        card_info_cmd(TRANSFER_MODE);
        rsp = eyefi_buf;
	return rsp->bytes[0].response;
}

void set_transfer_mode(enum transfer_mode transfer_mode)
{
	/*
	 * I think these 'O' commands are the "set" version
	 * of the little 'o' commands which are "gets".
	 *
	 * I think the 0x1 here is the length of the next
	 * argument.
	 */
	char new_cmd[] = {'O', TRANSFER_MODE, 0x1, transfer_mode};
	write_to(REQM, &new_cmd[0], 4);
        wait_for_response();
}

void print_transfer_status(void)
{
	int tries = 10;
	struct upload_status *us;
	int i;
	// Give it some sane number so it doesn't
	// wear out the card
	for (i = 0; i < 1000; i++) {
		char *filename;
		char *dir;
		int http_len;
		int http_complete;

		card_info_cmd(UPLOAD_STATUS);
		//__dumpbuf(eyefi_buf, 128, 48);
		us = eyefi_buf;
		if (!us->len) {
			return;
			printf("transfer not in progress\n");
			if (tries-- <= 0)
				break;
			sleep(1);
			continue;
		}
		if (us->len <= 8) {
			printf("%s() result too small: %d, transfer pending???\n",
					__func__, us->len);
			return;
		}
		http_len = be32_to_u32(us->http_len);
		http_complete = be32_to_u32(us->http_done);
		filename = (char *)&us->string[0];
		dir = filename + strlen(filename) + 1;
		printf("transferring (%d) %s/%s %d/%d bytes (%4.2f%%))\n",
				us->len,
				dir, filename,
				http_complete, http_len,
				(100.0 * http_complete) / http_len);
		break;
	}
	zero_card_files();
}

struct testbuf {
	char cmd;
	u8 l1;
	char name[100];
};

struct z {
	char zeros[100];
} z;

int print_connected_to(void)
{
	struct pascal_string *essid;

	card_info_cmd(CONNECTED_TO);
	essid = eyefi_buf;
	if (!essid->length) {
		return printf("not connected\n");
	}
	return printf("connected to: %s\n", (char *)&essid->value[0]);
}

char fwbuf[1<<20];
char zbuf[1<<20];
void scan_print_nets(void);
void testit0(void)
{
	char c;
	struct testbuf tb;
	int i;
	int fdin;
	int fdout;
	//char new_cmd[] = {'O', 0x06, 0x0d, 0x0a, 0x31, 0x30, 0x2e, 0x36, 0x2e, 0x30, 0x2e, 0x31, 0x33, 0x37};

	//printf("waiting...\n");
	//print_transfer_status();
	//exit(0);
	int doagain = 1;
	//wlan_disable(0);
	//int to_test[] = {5, 8, 9, 11, 15, 16, 255, -1};
	int to_test[] = {0xFF, -1};

	zero_card_files();
	while (1) {
	//fprintf(stderr, "testing...\n");
	for (i = 0; i < 255; i++) {
		int cmd = to_test[i];
		if (cmd == -1)
			break;
		//zero_card_files();
		card_info_cmd(cmd);
		printf("UNKNOWN %3d result: ", cmd);
		int printed = dumpbuf(eyefi_buf, 256);
		if (!printed)
			printf("\n");
		print_transfer_status();
		print_connected_to();
	}
	}
	exit(0);
	scan_print_nets();
	printf("WLAN enabled: %d\n", wlan_enabled());
	//wlan_disable();
	printf("WLAN enabled: %d\n", wlan_enabled());
	for (i = 10; i <= 13; i++) {
		int printed;
		zero_card_files();
		card_info_cmd(i);
		printf("UNKNOWN %d result:\n", i);
		printed = dumpbuf(eyefi_buf, 64);
		printf("WLAN enabled: %d\n", wlan_enabled());
	}
	i = 0xff;
	card_info_cmd(i);
	printf("UNKNOWN %d result:", i);
	dumpbuf(eyefi_buf, 64);
	exit(3);

	card_info_cmd(3);
	printf("o3 result:\n");
	dumpbuf(eyefi_buf, 64);

	memset(&zbuf[0], 0, EYEFI_BUF_SIZE);
	zbuf[0] = 'o';
	zbuf[1] = 2;

	write_to(REQM, &zbuf[0], 16384);
	printf("o2 written\n");
	printf("seq: %x\n", (int)eyefi_seq.seq);
	inc_seq();

	for (i=0; i < 4; i++) {
		read_from(RSPC);
		printf("RSPC %d:\n", i);
		dumpbuf(eyefi_buf, 64);
		usleep(20000);
	}

	printf("RSPM1:\n");
	read_from(RSPM);
	dumpbuf(eyefi_buf, 64);

	memset(&zbuf[0], 0, EYEFI_BUF_SIZE);
	write_to(RSPM, zbuf, EYEFI_BUF_SIZE);
	write_to(REQM, zbuf, EYEFI_BUF_SIZE);

	fdin = open("/home/dave/projects/eyefi/EYEFIFWU.BIN.2.0001", O_RDONLY);
	perror("fdin");
	fdout = open("/media/EYE-FI/EYEFIFWU.BIN", O_WRONLY|O_CREAT);
	perror("fdout");
	if (fdin <= 0 || fdout <= 0)
		exit(1);
	fd_flush(fdin);
	i = read(fdin, &fwbuf[0], 524288);
	perror("read");
	if (i != 524288)
		exit(2);
	i = write(fdout, &fwbuf[0], 524288);
	fd_flush(fdout);
	perror("write");
	if (i != 524288)
		exit(3);

	printf("RSPM2:\n");
	read_from(RSPM);
	dumpbuf(eyefi_buf, 64);

	reboot_card();
	printf("after reboot:\n");
	dumpbuf(eyefi_buf, 64);

	printf("cic3:\n");
	card_info_cmd(3);
	dumpbuf(eyefi_buf, 64);

	printf("cic2:\n");
	card_info_cmd(2);
	dumpbuf(eyefi_buf, 64);

	memset(&zbuf[0], 0, EYEFI_BUF_SIZE);
	write_to(RSPM, zbuf, EYEFI_BUF_SIZE);
	write_to(REQM, zbuf, EYEFI_BUF_SIZE);

	printf("cic2v2:\n");
	card_info_cmd(2);
	dumpbuf(eyefi_buf, 64);

	exit(0);
	strcpy(tb.name, "www.sr71.net/");
	tb.l1 = strlen(tb.name);
	for (i = 0; i < 10; i++) {
		tb.cmd = 'O';
		tb.l1 = i;
		write_struct(RSPM, &z);
		write_struct(REQM, &tb);
		wait_for_response();
		printf("buffer after O %d:\n", i);
		dumpbuf(eyefi_buf, 64);
		printf("----------------\n");
		write_struct(REQM, &tb);
		card_info_cmd(i);
		printf("card info(%d):\n", i);
		dumpbuf(eyefi_buf, 64);
		printf("-----------\n");
	}
	return;

	strcpy(tb.name, "/public/eyefi/servname");
	strcpy(tb.name, "/config/networks.xml");
	//tb.len = strlen(tb.name);
	tb.l1 = 0;
	for (c = 'O'; c <= 'O'; c++) {
		tb.cmd = c;
		write_struct(REQM, &tb);
		wait_for_response();
		printf("dumping buffer:\n");
		dumpbuf(eyefi_buf, 64);
		printf("buffer dump done\n");
	}
}

struct card_info_rsp_key *fetch_card_key(void)
{
	struct card_info_rsp_key *key;

	debug_printf(2, "%s()\n", __func__);
	card_info_cmd(CARD_KEY);
	key = eyefi_buf;
	return key;
}

int issue_noarg_command(u8 cmd)
{
	struct noarg_request req;
	debug_printf(4, "%s() cmd: %d\n", __func__, cmd);
	req.req = cmd;
	write_struct(REQM, &req);
	return wait_for_response();
}

struct scanned_net_list *scan_nets(void)
{
	struct scanned_net_list *scanned;

	debug_printf(2, "%s()\n", __func__);
	issue_noarg_command('g');
	scanned = eyefi_response();
	return scanned;
}

struct configured_net_list *fetch_configured_nets(void)
{
	struct configured_net_list *configured;

	debug_printf(2, "%s()\n", __func__);
	issue_noarg_command('l');
	configured = eyefi_buf;
	return configured;
}

void reboot_card(void)
{
	debug_printf(2, "%s()\n", __func__);
	debug_printf(1, "rebooting card...");
	issue_noarg_command('b');
	debug_printf(1, "done\n");
}

int network_action(char cmd, char *essid, char *ascii_password)
{
	struct net_request nr;
	memset(&nr, 0, sizeof(nr));

	nr.req = cmd;
	strcpy(&nr.essid[0], essid);
	nr.essid_len = strlen(essid);

	if (ascii_password) {
       		int ret = make_network_key(&nr.key, essid, ascii_password);
		if (ret)
			return ret;
	}
	write_struct(REQM, &nr);
	return wait_for_response();
}

void add_network(char *essid, char *ascii_password)
{
	debug_printf(2, "%s('%s', '%s')\n", __func__, essid, ascii_password);
	network_action('a', essid, ascii_password);
}

void remove_network(char *essid)
{
	debug_printf(2, "%s()\n", __func__);
	network_action('d', essid, NULL);
}

int get_log_at_offset(u32 offset)
{
	struct fetch_log_cmd cmd;
	cmd.m = 'm';
	cmd.offset = u32_to_be32(offset);

	debug_printf(2, "getting log at offset: %08x\n", offset);
	write_struct(REQM, &cmd);
	return wait_for_response();
}

void add_log_piece(u8 *log, int log_len, u8 *piece, int piece_pos, int piece_size)
{
	debug_printf(2, "%s(%p, %d, %p, %d, %d)\n", __func__, log, log_len, piece, piece_pos, piece_size);
	if (piece_pos + piece_size > log_len) {
		int overflow_by = (piece_pos + piece_size) - log_len;
		int piece_overrun_pos = piece_size - overflow_by;
		piece_size -= overflow_by;
		memcpy(&log[0], &piece[piece_overrun_pos], overflow_by);
		debug_printf(2, "writing %d bytes to logbuf[0] from piece[%d]\n",
				overflow_by, piece_overrun_pos);
	}
	debug_printf(2, "writing %d bytes to logbuf[%d]\n", piece_size, piece_pos);
	memcpy(&log[piece_pos], piece, piece_size);
}

int get_log_into(u8 *resbuf)
{
	int total_bytes = 0;
	int ret;
	int i;
	u32 log_start;
	u32 log_end;
	u32 __log_size = fetch_log_length();
	int log_pieces = __log_size/EYEFI_BUF_SIZE;

	debug_printf(2, "%s() total_bytes: %d\n", __func__, __log_size);
	if (__log_size <= 0)
		return __log_size;

	/* There are 8 bytes of header in the first log entry
	 * to specify where the log starts and ends */
	u32 log_size = __log_size - 8;

	for (i = 0; i < log_pieces; i++) {
		debug_printf(1, "fetching EyeFi card log part %d/%d...",
				i+1, log_pieces);
		fflush(NULL);
		ret = get_log_at_offset(EYEFI_BUF_SIZE*i);
		debug_printf(1, "done\n");
		u8 *log_piece;
		u32 log_piece_size;
		if (i == 0) {
			struct first_log_response *log = eyefi_buf;
			log_end = log_size - be32_to_u32(log->log_end);
			log_start = log_size - be32_to_u32(log->log_start);
			debug_printf(2, "log end:   0x%04x\n", log_end);
			debug_printf(2, "log start: 0x%04x\n", log_start);
			log_piece = &log->data[0];
			log_piece_size = ARRAY_SIZE(log->data);
		} else {
			struct rest_log_response *log = eyefi_buf;
			log_piece = &log->data[0];
			log_piece_size = ARRAY_SIZE(log->data);
		}
		add_log_piece(resbuf, log_size, log_piece, log_start, log_piece_size);
		total_bytes += log_piece_size;
		log_start += log_piece_size;
		log_start = log_start % log_size;
	}
	return total_bytes;
}

