#ifndef _EYEFI_CONFIG_H
#define _EYEFI_CONFIG_H

#include <sys/types.h>

#if defined(LITTLE_ENDIAN) && !defined(__LITTLE_ENDIAN)
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif

#if defined(BIG_ENDIAN) && !defined(__BIG_ENDIAN)
#define __BIG_ENDIAN BIG_ENDIAN
#endif

#if !defined(__BIG_ENDIAN) && !defined(__LITTLE_ENDIAN)
#include <endian.h>
#include <byteswap.h>
#endif

extern int eyefi_debug_level;

#ifdef __CHDK__

#define CONFIG_EYEFI_STANDALONE 1
#define printf(...) do{}while(0)
#define putchar(...) do{}while(0)
#define puts(...) do{}while(0)
#define exit(i)                  return
#define perror(i)        do{}while(0)
#define system(i)        do{}while(0)
#define fd_flush(fd) (0)
#define assert(x)        do{}while(0)
#define output_flush()   do{}while(0)

#else
#define CONFIG_EYEFI_WITH_OS 1
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
#include <stdarg.h>

#define PATHNAME_MAX 4096

#define output_flush()	fflush(NULL)

#define debug_printf(level, args...) do {      \
	if ((level) <= eyefi_debug_level)      \
		fprintf(stderr, ## args);      \
	} while(0)

#endif

/*
 * These are defined in both eyefi-unix.c and eyefi-chdk.c
 */
extern void open_error(char *file, int err);
extern int eyefi_printf(const char *fmt, ...);

/*
 * These have to be created by the unix variants
 */
extern int fd_flush(int);

/*
 * Do some kernel-style types to make
 * definitions shorter.
 */
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define os_memset memset
#define os_memcpy memcpy
#define os_strlen strlen
#define os_strcpy strcpy

#define SHA1_MAC_LEN 20
#define MD5_MAC_LEN 16
void sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac);
void md5_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac);
void hmac_md5_vector(const u8 *key, size_t key_len, size_t num_elem,
		     const u8 *addr[], const size_t *len, u8 *mac);
void hmac_md5(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
	      u8 *mac);
void pbkdf2_sha1(const char *passphrase, const char *ssid, size_t ssid_len,
		 int iterations, u8 *buf, size_t buflen);

static inline u32 swap_bytes(u32 src)
{
        u32 dest = 0;
        dest |= (src & 0xff000000) >> 24;
        dest |= (src & 0x00ff0000) >>  8;
        dest |= (src & 0x0000ff00) <<  8;
        dest |= (src & 0x000000ff) << 24;
        return dest;
}

#ifdef __LITTLE_ENDIAN
#define le_to_host32(n) (n)
#define be_to_host32(n) swap_bytes(n)
#define host_to_be32(n) swap_bytes(n)
#else  // __BIG_ENDIAN
#define le_to_host32(n) swap_bytes(n)
#define be_to_host32(n) (n)
#define host_to_be32(n) (n)
#endif

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
static inline u32 be32_to_u32(be32 src)
{
	return swap_bytes(src.val);
}
static inline be32 u32_to_be32(u32 src)
{
	be32 ret;
	ret.val = swap_bytes(src);
	return ret;
}

/*
 * Eye-Fi Card data structures
 */

struct card_seq_num {
	u32 seq;
} __attribute__((packed));

#define EYEFI_BUF_SIZE 16384

/*
 * Most of the eyefi strings are pascal-style with
 * a length byte preceeding content.  (Did pascal
 * have just a byte for length or more??)
 */
struct pascal_string {
	u8 length;
	u8 value[32];
} __attribute__((packed));

struct var_byte_response {
	u8 len;
	u8 bytes[EYEFI_BUF_SIZE-1];
};

/*
 * The 'o' command has several sub-commands:
 */
enum card_info_subcommand {
	MAC_ADDRESS   = 1,
	FIRMWARE_INFO = 2,
	CARD_KEY      = 3,
	API_URL       = 4,
	UNKNOWN_5     = 5, // Chris says these are 
	UNKNOWN_6     = 6, // checksums
	LOG_LEN	      = 7,
	WLAN_DISABLE  = 10, // 1=disable 0=enable, write is 1 byte, read is var_byte
	UPLOAD_PENDING= 11, // {0x1, STATE}
	HOTSPOT_ENABLE= 12, // {0x1, STATE}
	CONNECTED_TO  = 13, // Currently connected Wifi network
	UPLOAD_STATUS = 14, // current uploading file info
	UNKNOWN_15    = 15, // always returns {0x01, 0x1d} as far as I've seen
	TRANSFER_MODE = 17,
	ENDLESS	      = 27, // 0x1b
	DIRECT_MODE_SSID	= 0x22, // 0 == "direct mode off"
	DIRECT_MODE_PASS	= 0x23, // set to 60 when direct mode off
	DIRECT_WAIT_FOR_CONNECTION = 0x24, // 0 == "direct mode off"
	DIRECT_WAIT_AFTER_TRANSFER = 0x25, // set to 60 when direct mode off
	UPLOAD_KEY    = 0xfd, //
	UNKNOWN_ff    = 0xff, // The D90 does this, and it looks to
			      // return a 1-byte response length
			      // followed by a number of 8-byte responses
			      // But I've only ever seen a single response
			      // [000]: 01 04 1d 00 18 56 aa d5 42 00 00 00 00 00 00 00
			      // It could be a consolidates info command like "info for
			      // everything" so the camera makes fewer calls.
};

// new code!!: 
///media/NIKON D90/EYEFI/REQM
//00000000  4f 0a 01 00 00 00 00 00  00 00 00 00 00 00 00 00  |O...............|
//00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
// that happens 3 seconds after the card goes into the D90

// 
// 1301001235/0002/REQM: 00000000  4f 0c 01 01 00 00 00 00  00 00 00 00 00 00 00 00  |O...............|
// looks like it is setting the PC's IP address:
// 1300998375/0013/REQM: 00000000  4f 06 0d 0a 31 30 2e 38  2e 30 2e 31 32 33 00 00  |O...10.8.0.123..|
// 1300762293/0016/REQM: 00000000  4f 06 0d 0a 31 30 2e 36  2e 30 2e 31 32 33 00 00  |O...10.6.0.123..|
// 1300762293/0015/REQM: 00000000  4f 06 0d 0a 31 30 2e 36  2e 30 2e 31 32 33 00 00  |O...10.6.0.123..|


struct card_info_req {
	u8 o;
	u8 subcommand;
} __attribute__((packed));

struct card_config_cmd {
	u8 O;
	u8 subcommand;
	union {
		u8 u8_args[0];
		struct var_byte_response arg;
	};
} __attribute__((packed));

struct card_info_rsp_key {
	struct pascal_string key;
};

struct card_firmware_info {
	struct pascal_string info;
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

// These go along with 'o' 17 aka. TRANSFER_MODE
enum transfer_mode {
	AUTO_TRANSFER = 0,
	SELECTIVE_TRANSFER = 1,
	SELECTIVE_SHARE = 2,
};

enum net_type {
	NET_UNSECURED,
	NET_WEP,
	NET_WPA,
	NET_WPA2
};

enum net_password_type {
	NET_PASSWORD_ASCII,
	NET_PASSWORD_RAW, /* raw hex bytes */
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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define WPA_KEY_BYTES 32
struct wpa_key {
	u8 key[WPA_KEY_BYTES];
} __attribute((packed));

#define WEP_40_KEY_BYTES 5
#define WEP_KEY_BYTES 13
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

struct noarg_request {
	u8 req;
};

/*
 * Log structures
 */
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

struct upload_status {
	u8 len;
	// These are _transfer_ sizes.  There's some padding probably for
	// wifi metadata or something, so these end up being larger than
	// the actual on-disk sizes of the jpgs or movies.
	be32 http_len;
	be32 http_done;
	// There are two strings in here:
	// 1. filename on the card
	// \0
	// 2. directory on the card where it was found
	// \0
	u8 string[0];
}  __attribute__((packed));

/*
 * Functions that are exported from eyefi-config.c
 */
u32 fetch_log_length(void);
int card_info_cmd(enum card_info_subcommand cmd);
int card_config_set(enum card_info_subcommand cmd, struct var_byte_response *args);
void *eyefi_response(void);
struct card_info_rsp_key *fetch_card_key(void);
struct card_info_rsp_key *fetch_card_upload_key(void);
int wlan_enabled(void);
void wlan_disable(int do_disable);
enum transfer_mode fetch_transfer_mode(void);
void set_transfer_mode(enum transfer_mode);
struct scanned_net_list *scan_nets(void);
const char *net_type_name(u8 type);
struct configured_net_list *fetch_configured_nets(void);
int issue_noarg_command(u8 cmd);
char *net_test_state_name(u8 state);
int network_action(char cmd, char *essid, char *wpa_ascii);
char *locate_eyefi_mount(void);
void eject_card(void);
int get_log_into(u8 *resbuf);
void reboot_card(void);
void init_card(void);
void add_network(char *essid, char *ascii_password);
void remove_network(char *essid);
struct card_firmware_info *fetch_card_firmware_info(void);

int set_endless_percentage(int __percentage);
int endless_enable(int enable);
void print_endless(void);

/*
 * Only used by the unix variants
 */
enum eyefi_file {
	RDIR = 0,
	REQC,
	REQM,
	RSPC,
	RSPM
};
char *eyefi_file_on(enum eyefi_file file, char *mnt);
char *eyefi_file_name(enum eyefi_file file);
int atoh(char c);
#endif // _EYEFI_CONFIG_H
