// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * fdtdump.c - Contributed by Pantelis Antoniou <pantelis.antoniou AT gmail.com>
 */

/*
 * extended to fitdump.c - a tool to dissect a Flattened uImage Tree
 *
 * the main difference to the original code is output of BLOBs to separate files
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <libfdt.h>
#include <libfdt_env.h>
#include <fdt.h>

#include "util.h"

#define FDT_MAGIC_SIZE	4
#define MAX_VERSION 17U

#define ALIGN(x, a)	(((x) + ((a) - 1)) & ~((a) - 1))
#define PALIGN(p, a)	((void *)(ALIGN((uintptr_t)(p), (a))))
#define GET_CELL(p)	(p += 4, *((const fdt32_t *)(p-4)))

static char *out_dir = "./fit-dump";
static char *out_name = "image.its";
static char *out_file_mask = "image_%03u.bin";
static char *nodename_file_mask = "%s.image";
static int out_file_index = 0;
static char out_file_name[PATH_MAX];

static const char *tagname(uint32_t tag)
{
	static const char * const names[] = {
#define TN(t) [t] = #t
		TN(FDT_BEGIN_NODE),
		TN(FDT_END_NODE),
		TN(FDT_PROP),
		TN(FDT_NOP),
		TN(FDT_END),
#undef TN
	};
	if (tag < ARRAY_SIZE(names))
		if (names[tag])
			return names[tag];
	return "FDT_???";
}

#define dumpf(fmt, args...) \
	do { if (debug) printf("// " fmt, ## args); } while (0)

static char *get_image_name(bool nodenames, const char *nodename)
{
	if (nodenames) snprintf(out_file_name, sizeof(out_file_name), nodename_file_mask, nodename);
	else snprintf(out_file_name, sizeof(out_file_name), out_file_mask, ++out_file_index);
	return out_file_name;
}

static void dump_image_data(const char *data, int len, const char *out_file)
{
	int fdo;
	size_t written = 0;
	size_t outlen;

	printf(" = /incbin/(\"%s\"); // size: %u\n", out_file, len);
	if ((fdo = open(out_file, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP)) == -1)
		return;
	while ((int) written < len) {
		outlen = write(fdo, (data + written), (len - written));
		if (outlen <= 0) break;
		written += outlen;
	}
	close(fdo);
}

static void dump_blob(void *blob, bool debug, bool nodenames)
{
	uintptr_t blob_off = (uintptr_t)blob;
	struct fdt_header *bph = blob;
	uint32_t off_mem_rsvmap = fdt32_to_cpu(bph->off_mem_rsvmap);
	uint32_t off_dt = fdt32_to_cpu(bph->off_dt_struct);
	uint32_t off_str = fdt32_to_cpu(bph->off_dt_strings);
	struct fdt_reserve_entry *p_rsvmap =
		(struct fdt_reserve_entry *)((char *)blob + off_mem_rsvmap);
	const char *p_struct = (const char *)blob + off_dt;
	const char *p_strings = (const char *)blob + off_str;
	uint32_t version = fdt32_to_cpu(bph->version);
	uint32_t totalsize = fdt32_to_cpu(bph->totalsize);
	uint32_t tag;
	const char *p, *s, *t;
	const char *nodename = NULL;
	int depth, sz, shift;
	int i;
	uint64_t addr, size;

	depth = 0;
	shift = 4;

	printf("/dts-v1/;\n");
	printf("// magic:\t\t0x%"PRIx32"\n", fdt32_to_cpu(bph->magic));
	printf("// totalsize:\t\t0x%"PRIx32" (%"PRIu32")\n",
	       totalsize, totalsize);
	printf("// off_dt_struct:\t0x%"PRIx32"\n", off_dt);
	printf("// off_dt_strings:\t0x%"PRIx32"\n", off_str);
	printf("// off_mem_rsvmap:\t0x%"PRIx32"\n", off_mem_rsvmap);
	printf("// version:\t\t%"PRIu32"\n", version);
	printf("// last_comp_version:\t%"PRIu32"\n",
	       fdt32_to_cpu(bph->last_comp_version));
	if (version >= 2)
		printf("// boot_cpuid_phys:\t0x%"PRIx32"\n",
		       fdt32_to_cpu(bph->boot_cpuid_phys));

	if (version >= 3)
		printf("// size_dt_strings:\t0x%"PRIx32"\n",
		       fdt32_to_cpu(bph->size_dt_strings));
	if (version >= 17)
		printf("// size_dt_struct:\t0x%"PRIx32"\n",
		       fdt32_to_cpu(bph->size_dt_struct));
	printf("\n");

	for (i = 0; ; i++) {
		addr = fdt64_to_cpu(p_rsvmap[i].address);
		size = fdt64_to_cpu(p_rsvmap[i].size);
		if (addr == 0 && size == 0)
			break;

		printf("/memreserve/ %#"PRIx64" %#"PRIx64";\n",
		       addr, size);
	}

	p = p_struct;
	while ((tag = fdt32_to_cpu(GET_CELL(p))) != FDT_END) {

		dumpf("%04"PRIxPTR": tag: 0x%08"PRIx32" (%s)\n",
		        (uintptr_t)p - blob_off - 4, tag, tagname(tag));

		if (tag == FDT_BEGIN_NODE) {
			s = p;
			p = PALIGN(p + strlen(s) + 1, 4);

			if (*s == '\0')
				s = "/";

			printf("%*s%s {\n", depth * shift, "", s);

			depth++;
			nodename = s;
			continue;
		}

		if (tag == FDT_END_NODE) {
			depth--;

			printf("%*s};\n", depth * shift, "");
			continue;
		}

		if (tag == FDT_NOP) {
			printf("%*s// [NOP]\n", depth * shift, "");
			continue;
		}

		if (tag != FDT_PROP) {
			fprintf(stderr, "%*s ** Unknown tag 0x%08"PRIx32"\n", depth * shift, "", tag);
			break;
		}
		sz = fdt32_to_cpu(GET_CELL(p));
		s = p_strings + fdt32_to_cpu(GET_CELL(p));
		if (version < 16 && sz >= 8)
			p = PALIGN(p, 8);
		t = p;

		p = PALIGN(p + sz, 4);

		dumpf("%04"PRIxPTR": string: %s\n", (uintptr_t)s - blob_off, s);
		dumpf("%04"PRIxPTR": value\n", (uintptr_t)t - blob_off);
		printf("%*s%s", depth * shift, "", s);
		if (sz > 512) {
			dump_image_data(t, sz, get_image_name(nodenames, nodename));
		}
		else {
			utilfdt_print_data(t, sz);
			printf(";\n");
		}
	}
}

/* Usage related data. */
static const char usage_synopsis[] = "fitdump [options] <file>";
/* static const char usage_short_opts[] = "ds" USAGE_COMMON_SHORT_OPTS; */
static const char usage_short_opts[] = "dn" USAGE_COMMON_SHORT_OPTS;
static struct option const usage_long_opts[] = {
	{"debug",            no_argument, NULL, 'd'},
	{"nodenames",        no_argument, NULL, 'n'},
/*	{"scan",             no_argument, NULL, 's'}, */
	USAGE_COMMON_LONG_OPTS
};
static const char * const usage_opts_help[] = {
	"Dump debug information while decoding the file",
	"Use node names for image files (<nodename>.image)",
/*	"Scan for an embedded fdt in file", */
	USAGE_COMMON_OPTS_HELP
};

static bool valid_header(char *p, size_t len)
{
	if (len < sizeof(struct fdt_header) ||
	    fdt_magic(p) != FDT_MAGIC ||
	    fdt_version(p) > MAX_VERSION ||
	    fdt_last_comp_version(p) > MAX_VERSION ||
	    fdt_totalsize(p) >= len ||
	    fdt_off_dt_struct(p) >= len ||
	    fdt_off_dt_strings(p) >= len)
		return 0;
	else
		return 1;
}

int main(int argc, char *argv[])
{
	int opt;
	const char *file;
	char *buf;
	bool debug = false;
/*	bool scan = false; */
	bool nodenames = false;
	size_t len;
	struct stat od;
	char cwd[PATH_MAX];

/*	fprintf(stderr, "\n"
"**** fdtdump is a low-level debugging tool, not meant for general use.\n"
"**** If you want to decompile a dtb, you probably want\n"
"****     dtc -I dtb -O dts <filename>\n\n"
		); */
	while ((opt = util_getopt_long()) != EOF) {
		switch (opt) {
		case_USAGE_COMMON_FLAGS

		case 'd':
			debug = true;
			break;
		case 'n':
			nodenames = true;
			break;
/*		case 's':
 *			scan = true;
 *			break;
 */		}
	}
	if (optind != argc - 1)
		usage("missing input filename");
	file = argv[optind];

	if (stat(out_dir, &od) != -1)
		die("output directory does exist already: %s\n", out_dir);

	if (mkdir(out_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1)
		die("error %u (%s) creating output directory: %s\n", errno, strerror(errno), out_dir);

	buf = utilfdt_read(file, &len);
	if (!buf)
		die("could not read: %s\n", file);

	/* try and locate an embedded fdt in a bigger blob */
/*	if (scan) { */
	{ /* always scan for FDT magic */
		unsigned char smagic[FDT_MAGIC_SIZE];
		char *p = buf;
		char *endp = buf + len;

		fdt32_st(smagic, FDT_MAGIC);

		/* poor man's memmem */
		while ((endp - p) >= FDT_MAGIC_SIZE) {
			p = memchr(p, smagic[0], endp - p - FDT_MAGIC_SIZE);
			if (!p)
				break;
			if (fdt_magic(p) == FDT_MAGIC) {
				/* try and validate the main struct */
				off_t this_len = endp - p;
				if (valid_header(p, this_len))
					break;
				if (debug)
					printf("%s: skipping fdt magic at offset %#tx\n",
						file, p - buf);
			}
			++p;
		}
		if (!p || (size_t)(endp - p) < sizeof(struct fdt_header))
			die("%s: could not locate fdt magic\n", file);
/*		printf("%s: found fdt at offset %#tx\n", file, p - buf); */
		buf = p;
	} /* else if (!valid_header(buf, len))
		die("%s: header is not valid\n", file); */

	if (NULL == getcwd(cwd, sizeof(cwd)))
		die("Unable to get current working directory: %u (%s)\n", errno, strerror(errno));
	if (chdir(out_dir) == -1)
		die("Unable to change directory to: %s, error %u (%s)\n", out_dir, errno, strerror(errno));
	if (NULL == freopen(out_name, "w", stdout))
		die("Unable to redirect STDOUT to: %s, error %u (%s)\n", out_name, errno, strerror(errno));

	dump_blob(buf, debug, nodenames);

	chdir(cwd);

	return 0;
}
