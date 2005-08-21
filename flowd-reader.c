/*
 * Copyright (c) 2004 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define PROGNAME	"flowd-reader"

#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <poll.h>

#include "common.h"
#include "flowd.h"
#include "store.h"
#include "store-v2.h"
#include "atomicio.h"

RCSID("$Id$");

static void
usage(void)
{
	fprintf(stderr, "Usage: %s [options] flow-log [flow-log ...]\n",
	    PROGNAME);
	fprintf(stderr, "This is %s version %s. Valid commandline options:\n",
	    PROGNAME, PROGVER);
	fprintf(stderr, "  -L       Read/convert legacy flow logs\n");
	fprintf(stderr, "  -q       Don't print flows to stdout (use with -o)\n");
	fprintf(stderr, "  -d       Print debugging information\n");
	fprintf(stderr, "  -f path  Filter flows using rule file\n");
	fprintf(stderr, "  -o path  Write binary log to path (use with -f)\n");
	fprintf(stderr, "  -v       Display all available flow information\n");
	fprintf(stderr, "  -U       Report times in UTC rather than local time\n");
	fprintf(stderr, "  -h       Display this help\n");
}

static int
open_start_log(const char *path, int debug)
{
	int fd;

	if (path == NULL) {
		/* Logfile on stdout */
		fd = STDOUT_FILENO;
	} else if ((fd = open(path, O_RDWR|O_APPEND|O_CREAT, 0600)) == -1)
		logerr("open(%s)", path);

	if (debug)
		fprintf(stderr, "Writing new logfile header\n");

	return (fd);
}


int
main(int argc, char **argv)
{
	int ch, i, fd, utc, r, verbose, debug;
	extern char *optarg;
	extern int optind;
	struct store_flow_complete flow;
	struct store_v2_flow_complete flow_v2;
	char buf[2048], ebuf[512];
	const char *ffile, *ofile;
	FILE *ffilef;
	int ofd, read_legacy;
	u_int32_t disp_mask;
	struct flowd_config filter_config;
	struct store_v2_header hdr_v2;

	utc = verbose = debug = read_legacy = 0;
	ofile = ffile = NULL;
	ofd = -1;
	ffilef = NULL;

	bzero(&filter_config, sizeof(filter_config));

	while ((ch = getopt(argc, argv, "LUdf:ho:qv")) != -1) {
		switch (ch) {
		case 'h':
			usage();
			return (0);
		case 'L':
			read_legacy = 1;
			break;
		case 'U':
			utc = 1;
			break;
		case 'd':
			debug = 1;
			filter_config.opts |= FLOWD_OPT_VERBOSE;
			break;
		case 'f':
			ffile = optarg;
			break;
		case 'o':
			ofile = optarg;
			break;
		case 'q':
			verbose = -1;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			exit(1);
		}
	}
	loginit(PROGNAME, 1, debug);

	if (argc - optind < 1) {
		fprintf(stderr, "No logfile specified\n");
		usage();
		exit(1);
	}

	if (ffile != NULL) {
		if ((ffilef = fopen(ffile, "r")) == NULL)
			logerr("fopen(%s)", ffile);
		if (parse_config(ffile, ffilef, &filter_config, 1) != 0)
			exit(1);
		fclose(ffilef);
	}

	if (ofile != NULL) {
		if (strcmp(ofile, "-") == 0) {
			if (!debug)
				verbose = -1;
			ofile = NULL;
			if (isatty(STDOUT_FILENO))
				logerrx("Refusing to write binary flow data to "
				    "standard output.");
		}
		ofd = open_start_log(ofile, debug);
	}

	if (filter_config.store_mask == 0)
		filter_config.store_mask = STORE_FIELD_ALL;

	disp_mask = (verbose > 0) ? STORE_DISPLAY_ALL: STORE_DISPLAY_BRIEF;
	disp_mask &= filter_config.store_mask;

	for (i = optind; i < argc; i++) {
		if (strcmp(argv[i], "-") == 0)
			fd = STDIN_FILENO;
		else if ((fd = open(argv[i], O_RDONLY)) == -1)
			logerr("open(%s)", argv[i]);

		if (read_legacy && store_v2_get_header(fd, &hdr_v2, ebuf,
		    sizeof(ebuf)) != STORE_ERR_OK)
			logerrx("%s", ebuf);

		if (verbose >= 0) {
			printf("LOGFILE %s", argv[i]);
			if (read_legacy)
				printf(" started at %s",
				    iso_time(ntohl(hdr_v2.start_time), utc));
			printf("\n");
			fflush(stdout);
		}

		for (;;) {
			bzero(&flow, sizeof(flow));

			if (read_legacy)
				r = store_v2_get_flow(fd, &flow_v2, ebuf,
				    sizeof(ebuf));
			else
				r = store_get_flow(fd, &flow, ebuf,
				    sizeof(ebuf));
				
			if (r == STORE_ERR_EOF)
				break;
			else if (r != STORE_ERR_OK)
			    	logerrx("%s", ebuf);

			if (read_legacy &&
			    store_v2_flow_convert(&flow_v2, &flow) == -1)
			    	logerrx("legacy flow conversion failed");

			if (ffile != NULL && filter_flow(&flow,
			    &filter_config.filter_list) == FF_ACTION_DISCARD)
				continue;
			if (verbose >= 0) {
				store_format_flow(&flow, buf, sizeof(buf), 
				    utc, disp_mask, 0);
				printf("%s\n", buf);
				fflush(stdout);
			}
			if (ofd != -1 && store_put_flow(ofd, &flow, 
			    filter_config.store_mask, ebuf, 
			    sizeof(ebuf)) == -1)
			    	logerrx("%s", ebuf);
		}
		if (fd != STDIN_FILENO)
			close(fd);
	}
	if (ofd != -1)
		close(ofd);

	if (ffile != NULL && debug)
		dump_config(&filter_config, "final", 1);

	return (0);
}
