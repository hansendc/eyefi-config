/*
 * eyefi-unix.c
 *
 * Copyright (C) 2008 Dave Hansen <dave@sr71.net>
 *
 * This software may be redistributed and/or modified under the terms of
 * the GNU General Public License ("GPL") version 2 as published by the
 * Free Software Foundation.
 */

#include "eyefi-config.h"

void print_pascal_string(struct pascal_string *str)
{
	int i;
	for (i = 0; i < str->length; i++)
		printf("%c", str->value[i]);
}

void print_mac(struct mac_address *mac)
{
	int i;
	for (i=0; i < MAC_BYTES-1; i++) {
		printf("%02x:", mac->mac[i]);
	}
	printf("%02x\n", mac->mac[i]);
}


void print_card_mac(void)
{
	debug_printf(2, "%s()\n", __func__);
	struct mac_address *mac;

	card_info_cmd(MAC_ADDRESS);
	mac = eyefi_response();
	debug_printf(3, "%s() mac->length: %d\n", __func__, mac->length);
	assert(mac->length == MAC_BYTES);
	printf("card mac address: ");
	print_mac(mac);
}

void print_card_firmware_info(void)
{
	struct card_firmware_info *info = fetch_card_firmware_info();
	printf("card firmware (len: %d): '", info->info.length);
	print_pascal_string(&info->info);
	printf("'\n");
}

void print_card_key(void)
{
	debug_printf(2, "%s()\n", __func__);
	struct card_info_rsp_key *foo = fetch_card_key();
	printf("card key (len: %d): '", foo->key.length);
	print_pascal_string(&foo->key);
	printf("'\n");
}

void print_upload_key(void)
{
	debug_printf(2, "%s()\n", __func__);
	struct card_info_rsp_key *foo = fetch_card_upload_key();
	printf("card upload key (len: %d): '", foo->key.length);
	print_pascal_string(&foo->key);
	printf("'\n");
}

void scan_print_nets(void)
{
	int i;

	debug_printf(2, "%s()\n", __func__);
	struct scanned_net_list *scanned = scan_nets();
	if (scanned->nr == 0) {
		printf("unable to detect any wireless networks\n");
		return;
	}
	printf("Scanned wireless networks:\n");
	for (i=0; i < scanned->nr; i++) {
		struct scanned_net *net = &scanned->nets[i];
		printf("security: ");
		if (eyefi_debug_level > 1)
			printf("(%d)", net->type);
		printf("%4s, strength: %3d ", net_type_name(net->type),
				net->strength);
		printf("essid: '%s'\n", net->essid);
	}
}

void print_configured_nets(void)
{
	int ret;
	int i;
	struct configured_net_list *configured = fetch_configured_nets();

	debug_printf(2, "%s()\n", __func__);
	ret = issue_noarg_command('l');
	if (ret) {
		printf("error issuing print networks command: %d\n", ret);
		return;
	}
	configured = eyefi_response();
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

void print_direct_mode_info(void)
{
	struct pascal_string *direct_mode_ssid;
	struct pascal_string *direct_mode_pass;
	debug_printf(2, "%s()\n", __func__);

	card_info_cmd(DIRECT_MODE_SSID);
	direct_mode_ssid = eyefi_response();
	printf("Direct mode SSID:  '");
	print_pascal_string(direct_mode_ssid);
	printf("'\n");

	card_info_cmd(DIRECT_MODE_PASS);
	direct_mode_pass = eyefi_response();
	printf("Direct mode password:  '");
	print_pascal_string(direct_mode_pass);
	printf("'\n");
}

int try_connection_to(char *essid, char *ascii_password)
{
	int i;
	int ret = -1;

	eyefi_printf("trying to connect to network: '%s'\n", essid);
	if (ascii_password)
		eyefi_printf(" with passphrase: '%s'\n", ascii_password);
	fflush(NULL);

	// test network
	ret = network_action('t', essid, ascii_password);
	if (ret)
		return ret;
	u8 last_rsp = -1;

	char rsp = '\0';
	ret = -1;
	for (i=0; i < 200; i++) {
		char *rsp_ptr = eyefi_response();
		issue_noarg_command('s');
		rsp = *rsp_ptr;
		char *state = net_test_state_name(rsp);
		debug_printf(1, "net state: 0x%02x name: '%s'\n", rsp, state);
		if (rsp == last_rsp) {
			eyefi_printf(".");
			fflush(NULL);;
		} else {
			if (rsp)
				eyefi_printf("\nTesting connecion to '%s' (%d): %s", essid, rsp, state);
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
	eyefi_printf("\n");
	if (!ret) {
		eyefi_printf("Succeeded connecting to: '%s'\n", essid);
	} else {
		eyefi_printf("Unable to connect to: '%s' (final state: %d/'%s')\n", essid,
				rsp, net_test_state_name(rsp));
	}
	return ret;
}

const char *transfer_mode_names[] = {
	"AUTO",
	"SELSHARE",
	"SELUPLOAD",
};

int __index_of_str(char *find_me, const char **to_search, int array_size)
{
	int i;

	for (i = 0; i < array_size; i++) {
		if (!strcmp(find_me, to_search[i]))
			return i;
	}
	return -1;
}
#define index_of_str(findit, chr_array)	__index_of_str(findit, chr_array, ARRAY_SIZE(chr_array))
static char unknown_buf[1024];
const char *__index_to_str(const char **array, int index, int array_size)
{
	// This is funky and not thread safe
	if (index >= array_size) {
		sprintf(&unknown_buf[0], "UNKNOWN[%d]", index);
		return &unknown_buf[0];
	}
	return array[index];
}
#define index_to_str(chr_array, index)	__index_to_str(chr_array, index, ARRAY_SIZE(chr_array))

enum transfer_mode str_to_transfer_mode(char *mode_str)
{
	return index_of_str(mode_str, transfer_mode_names);
}

void handle_transfer_mode(char *arg)
{
	enum transfer_mode mode;
	const char *mode_name;
	enum transfer_mode new_mode;
	if (arg) {
		new_mode = str_to_transfer_mode(arg);
		if (new_mode == -1) {
			int i;
			if (strcmp(arg, "help")) {
				printf("invalid --transfer-mode: %s\n", arg);
			}
			printf("valid --transfer-mode modes are:\n");
			for (i = 0; i < ARRAY_SIZE(transfer_mode_names); i++) {
				printf("\t%s\n", transfer_mode_names[i]);
			}
			exit(1);
		}
		set_transfer_mode(new_mode);
	}

	mode = fetch_transfer_mode();
	mode_name = index_to_str(transfer_mode_names, mode);
	printf("transfer mode is: %s\n", mode_name);
}

void handle_endless(char *arg)
{
	if (arg) {
		int percentage;
		if (!strcmp(arg, "enable")) {
			endless_enable(1);
		} else if (!strcmp(arg, "disable")) {
			endless_enable(0);
		} else {
			percentage = atoi(arg);
			if ((percentage >= 100) ||
			    (percentage <= 0)) {
				printf("invalid enless argument: %s\n", arg);
				return;
			}
			set_endless_percentage(percentage);
		}
	}
	print_endless();
}


void handle_wifi_onoff(char *arg)
{
	char *state;
	if (arg) {
		if (!strcmp(arg, "enable")) {
			wlan_disable(0);
		} else if (!strcmp(arg, "disable")) {
			wlan_disable(1);
		} else {
			printf("unknown wifi state, ignoring: '%s'\n", arg);
			return;
		}
	}
	if (wlan_enabled()) {
		state = "enabled";
	} else {
		state = "disabled";
	}
	printf("wifi radio status: %s\n", state);
}

int print_log(void)
{
	int i;
	u8 *resbuf = malloc(EYEFI_BUF_SIZE*4);
	int total_bytes;

	total_bytes = get_log_into(resbuf);
	if (total_bytes < 0) {
		debug_printf(1, "%s() error: %d\n", __func__, total_bytes);
		free(resbuf);
		return total_bytes;
	}
	// The last byte *should* be a null, and the 
	// official software does not print it.
	for (i = 0; i < total_bytes-1; i++) {
		char c = resbuf[i];
		// the official software converts UNIX to DOS-style
		// line breaks, so we'll do the same
		if (c == '\n')
			printf("%c", '\r');
		printf("%c", c);
	}
	printf("\n");
	// just some simple sanity checking to make sure what
	// we are fetching looks valid
	/* needs to be rethought for the new aligned logs
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
	*/
	free(resbuf);
	return 0;
}

void open_error(char *file, int ret)
{
	fprintf(stderr, "unable to open '%s' (%d)\n", file, ret);
	fprintf(stderr, "Is the Eye-Fi card inserted and mounted at: %s ?\n", locate_eyefi_mount());
	fprintf(stderr, "Do you have write permissions to it?\n");
	fprintf(stderr, "debug information:\n");
	if (eyefi_debug_level > 0)
		system("cat /proc/mounts >&2");
	if (eyefi_debug_level > 1)
		perror("bad open");
	exit(1);
}

void usage(void)
{
	printf("Usage:\n");
	printf("  eyefi-config [OPTIONS]\n");
	printf("  -a ESSID	add network (implies test unless --force)\n");
	printf("  -t ESSID	test network\n");
	printf("  -p KEY	set WPA key for add/test\n");
	printf("  -r ESSID	remove network\n");
	printf("  -s		scan for networks\n");
	printf("  -c		list configured networks\n");
	printf("  -b		reboot card\n");
	printf("  -f            print information about card firmware\n");
	printf("  -d level	set debugging level (default: 1)\n");
	printf("  -k		print card unique key\n");
	printf("  -l		dump card log\n");
	printf("  -m	 	print card mac\n");
	printf("  -u	 	print card upload key\n");
	printf("  --transfer-mode[=mode]  print or change card transfer mode\n");
	printf("                          or =help to list modes\n");
	printf("  --wifi-radio  fetch wifi radio state\n");
	printf("  --wifi-radio=enable enable wifi radio\n");
	printf("  --wifi-radio=disable disable wifi radio\n");
	printf("  --endless	fetch endless storage information\n");
	printf("  --endless=<NN> set the endless storage percentage\n");
	printf("  --endless=[enable/disable]\n");
	printf("  --direct-mode-info\n");
	exit(4);
}

int is_long_opt(int cint, struct option *long_options)
{
	struct option *opt = long_options;

	while (opt && opt->name) {
		if (opt->val == cint)
			return 1;
	}
	return 0;
}

#define __stringify_1(x...)     #x
#define __stringify(x...)       __stringify_1(x)

#define EYEFI_ARG(arg) {		\
	.long_opt = __stringify(arg),	\
}

struct eyefi_arg {
	char *long_opt;
	int (*func)(char *);
	char *arg_val;
	int tmpvar;
};

struct eyefi_arg eyefi_args[] = {
	EYEFI_ARG(force),
};

int arg_is_set(char *argv)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(eyefi_args); i++) {
		struct eyefi_arg *arg = &eyefi_args[i];
		if (!strcmp(argv, arg->long_opt)) {
			return arg->tmpvar;
		}
	}
	return 0;
}

struct option *init_args(struct option *extra, int len)
{
	int i;
	struct option *long_options;
	int longopt_nr = 0;

	long_options = malloc(sizeof(struct option) * ARRAY_SIZE(eyefi_args) + len);
	for (i = 0; i < len; i++) {
		memcpy(&long_options[longopt_nr++], &extra[i],
				sizeof(struct option));
	}
	for (i = 0; i < ARRAY_SIZE(eyefi_args); i++) {
		struct option *opt = &long_options[longopt_nr++];

		opt->name = eyefi_args[i].long_opt;
		opt->has_arg = 2;
		opt->flag = &eyefi_args[i].tmpvar;
		opt->val = 1;
	}
	return long_options;
}

int main(int argc, char *argv[])
{
	int option_index;
	char c;
	int cint;
	char *essid = NULL;
	char *passwd = NULL;
	char network_action = 0;
	static int force = 0;
	static int transfer_mode = 0;
	static int wifi_radio_on = 0;
	static int endless = 0;
	static int eject = 0;
	static int direct_mode_info = 0;
	static int debug_level_opt = 0;
	static struct option long_options[] = {
		{"force", 	  	0, &force, 1},
		{"help",	  	0,   NULL, 'h'},
		{"transfer-mode",	2, &transfer_mode,	1},
		{"wifi-radio",  	2, &wifi_radio_on,	1},
		{"endless",		2, &endless,       	1},
		{"eject",	  	2, &eject,	    	1},
		{"debug",		2, &debug_level_opt,	'd'},
		{"direct-mode-info", 	2, &direct_mode_info,	1},
		{0, 0, 0, 0}
	};

	if (argc == 1)
		usage();

	char optarg_shorts[] = "a:bcd:kflmp:r:st:uz";
	while ((cint = getopt_long_only(argc, argv, optarg_shorts,
		&long_options[0], &option_index)) != -1) {
		c = cint;
		// Process the debug option first and out-of-order
		if ((c == 'd') || (debug_level_opt != 0)) {
			fprintf(stderr, "set debug level to: %d\n", eyefi_debug_level);
			eyefi_debug_level = atoi(optarg);
			debug_level_opt = 0;
		}
	}
	// Internal getopt() variable, needs to be reset
	// to force it to restart the arg scan:
	optind = 0;

	debug_printf(3, "%s starting...\n", argv[0]);

	debug_printf(3, "about to parse arguments\n");
	debug_printf(4, "argc: %d\n", argc);
	debug_printf(4, "argv: %p\n", argv);
	while ((cint = getopt_long_only(argc, argv, optarg_shorts,
		&long_options[0], &option_index)) != -1) {
		c = cint;
		debug_printf(3, "argument: '%c' %d optarg: '%s'\n", c, c, optarg);
		if (eject) {
			eject_card();
			exit(0);
		}
		if (transfer_mode) {
			handle_transfer_mode(optarg);
			transfer_mode = 0;
			continue;
		}
		if (wifi_radio_on) {
			handle_wifi_onoff(optarg);
			wifi_radio_on = 0;
			continue;
		}
		if (endless) {
			handle_endless(optarg);
			endless = 0;
			continue;
		}
		if (direct_mode_info) {
			print_direct_mode_info();
			direct_mode_info = 0;
			continue;
		}
		switch (c) {
		case 0:
			// was a long argument
			break;
		case 'a':
		case 't':
		case 'r':
			essid = strdup(optarg);
			network_action = c;
			break;
		case 'b':
			reboot_card();
			break;
		case 'c':
			print_configured_nets();
			break;
		case 'd':
			// We handled this above
			break;
		case 'f':
			print_card_firmware_info();
			break;
		case 'k':
			print_card_key();
			break;
		case 'l':
			print_log();
			break;
		case 'm':
			print_card_mac();
			break;
		case 'p':
			passwd = strdup(optarg);
			break;
		case 'u':
			print_upload_key();
			break;
		case 's':
			scan_print_nets();
			break;
		case 'z': {
			extern void testit0(void);
			testit0();
			break;
		}
		case 'h':
		default:
			usage();
			break;
		}
	}

	debug_printf(3, "after arguments1 essid: '%s' passwd: '%s'\n", essid, passwd);
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

	free(essid);
	free(passwd);
	return 0;
}


