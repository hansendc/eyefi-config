#ifndef _EYEFI_CONFIG_H
#define _EYEFI_CONFIG_H

#include <sys/types.h>

#include <endian.h>
#include <byteswap.h>

/*
 * Do some kernel-style types to make
 * definitions shorter.
 */
typedef unsigned long u32;
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
#warning le
#define le_to_host32(n) (n)
#define be_to_host32(n) swap_bytes(n)
#define host_to_be32(n) swap_bytes(n)
#else  // __BIG_ENDIAN
#warning be
#define le_to_host32(n) swap_bytes(n)
#define be_to_host32(n) (n)
#define host_to_be32(n) (n)
#endif

#endif // _EYEFI_CONFIG_H
