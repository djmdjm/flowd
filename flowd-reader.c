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

#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <err.h>
#include <poll.h>

#include "store.h"
#include "atomicio.h"

#define MINUTE		(60)
#define HOUR		(MINUTE * 60)
#define DAY		(HOUR * 24)
#define WEEK		(DAY * 7)
#define YEAR		(WEEK * 52)

static void
usage(void)
{
	fprintf(stderr, "Usage: flowd-reader [-U] flow-log [flow-log ...]\n");
}

static const char *
iso_time(time_t t, int utc)
{
	struct tm *tm;
	static char buf[128];

	if (utc)
		tm = gmtime(&t);
	else
		tm = localtime(&t);

	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);

	return (buf);
}

static const char *ywds_time(u_long t)
{
	static char buf[128];
	char tmp[128];
	u_long r;
	int unit_div[] = { YEAR, WEEK, DAY, HOUR, MINUTE, 1, -1 };
	char unit_sym[] = { 'Y', 'W', 'D', 'H', 'M', 'S' };
	int i;

	*buf = '\0';

	for (i = 0; unit_div[i] != -1; i++) {
		if ((r = t / unit_div[i]) != 0 || unit_div[i] == 1) {
			snprintf(tmp, sizeof(tmp), "%lu%c", r, unit_sym[i]);
			strlcat(buf, tmp, sizeof(buf));
			t %= unit_div[i];
		}
	}
	return (buf);
}

int
main(int argc, char **argv)
{
	int ch, i, fd, utc, r;
	extern char *optarg;
	extern int optind;
	struct store_flow_complete flow;
	struct store_header hdr;
	char *e;

	utc = 0;
	while ((ch = getopt(argc, argv, "hU")) != -1) {
		switch (ch) {
		case 'h':
			usage();
			return (0);
		case 'U':
			utc = 1;
			break;
		default:
			fprintf(stderr, "Invalid commandline option.\n");
			usage();
			exit(1);
		}
	}

	if (argc - optind < 1) {
		fprintf(stderr, "No logfile specified\n");
		usage();
		exit(1);
	}

	for (i = optind; i < argc; i++) {
		if ((fd = open(argv[i], O_RDONLY)) == -1)
			err(1, "Couldn't open %s", argv[i]);
		if (store_get_header(fd, &hdr, &e) == -1)
			errx(1, "%s", e);
	
		printf("LOGFILE %s started at %s\n", argv[i],
		    iso_time(ntohl(hdr.start_time), utc));

		for (;;) {
			bzero(&flow, sizeof(flow));

			if ((r = store_get_flow(fd, &flow, &e)) == -1)
				errx(1, "%s", e);
			if (r == 0) /* EOF */
				break;

			flow.hdr.fields = ntohl(flow.hdr.fields);
			flow.hdr.tag = ntohl(flow.hdr.tag);
			flow.hdr.recv_secs = ntohl(flow.hdr.recv_secs);

			printf("FLOW tag %d %s ", flow.hdr.tag,
			    iso_time(flow.hdr.recv_secs, utc));

#define HASFIELD(flag)	(flow.hdr.fields & STORE_FIELD_##flag)

			if (HASFIELD(PROTO_FLAGS_TOS)) {
				printf("proto %d ", flow.pft.protocol);
				printf("tcpflags %x ", flow.pft.tcp_flags);
				printf("tos %02x " , flow.pft.tos);
			}
			if (HASFIELD(AGENT_ADDR4) || HASFIELD(AGENT_ADDR6)) {
				printf("agent %s ",
				    addr_ntop_buf(&flow.agent_addr));
			}
			if (HASFIELD(SRCDST_ADDR4) || HASFIELD(SRCDST_ADDR6)) {
				printf("src %s",
				    addr_ntop_buf(&flow.src_addr));
				if (HASFIELD(SRCDST_PORT)) {
					printf(":%d",
					    ntohs(flow.ports.src_port));
				}
				printf(" ");
				printf("dst %s",
				    addr_ntop_buf(&flow.dst_addr));
				if (HASFIELD(SRCDST_PORT)) {
					printf(":%d",
					    ntohs(flow.ports.dst_port));
				}
				printf(" ");
			}
			if (HASFIELD(GATEWAY_ADDR4) ||
			    HASFIELD(GATEWAY_ADDR6)) {
				printf("gateway %s ",
				    addr_ntop_buf(&flow.gateway_addr));
			}
			if (HASFIELD(PACKETS_OCTETS)) {
				printf("packets %lu octets %lu ", 
				    (u_long)ntohl(flow.counters.flow_packets),
				    (u_long)ntohl(flow.counters.flow_octets));
			}
			if (HASFIELD(IF_INDICES)) {
				printf("in_if %d out_if %d ", 
					ntohs(flow.ifndx.if_index_in),
					ntohs(flow.ifndx.if_index_out));
			}
			if (HASFIELD(AGENT_INFO)) {
				printf("sys_uptime_ms %s.%03u ",
				    ywds_time(ntohl(flow.ainfo.sys_uptime_ms)
				    / 1000), ntohl(flow.ainfo.sys_uptime_ms) 
				    % 1000);
				printf("time_sec %s ",
				    iso_time(ntohl(flow.ainfo.time_sec), utc));
				printf("time_nanosec %lu netflow ver %u ",
				    (u_long)ntohl(flow.ainfo.time_nanosec),
				    ntohs(flow.ainfo.netflow_version));
			}
			if (HASFIELD(FLOW_TIMES)) {
				printf("flow_start %s.%03u ", 
				    ywds_time(ntohl(flow.ftimes.flow_start) /
				    1000), ntohl(flow.ftimes.flow_start) %
				    1000);
				printf("flow_finish %s.%03u ", 
				    ywds_time(ntohl(flow.ftimes.flow_finish) /
				    1000), ntohl(flow.ftimes.flow_finish) %
				    1000);
			}
			if (HASFIELD(AS_INFO)) {
				printf("src_AS %u src_masklen %u ", 
				    ntohs(flow.asinf.src_as),
				    flow.asinf.src_mask);
				printf("dst_AS %u dst_masklen %u ", 
				    ntohs(flow.asinf.dst_as),
				    flow.asinf.dst_mask);
			}
			if (HASFIELD(FLOW_ENGINE_INFO)) {
				printf("engine_type %u engine_id %u seq %lu", 
				    flow.finf.engine_type, 
				    flow.finf.engine_id,
				    (u_long)ntohl(flow.finf.flow_sequence));
			}



			printf("\n");
			fflush(stdout);
		}

		close(fd);
	}

	return (0);
}
