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
#include "crc32.h"

/* Stash error message and return */
#define SFAILX(i, m) do {							\
		if (errptr != NULL)					\
			*errptr = (m);					\
		return (i);						\
	} while (0)

/* Stash error message, appending strerror into local "ebuf" and return */
#define SFAIL(i, m) do {						\
		if (errptr != NULL) {					\
			snprintf(ebuf, sizeof(ebuf), "%s: %s", m, 	\
			    strerror(errno));				\
			*errptr = ebuf;					\
		}							\
		return (i);						\
	} while (0)


int
store_get_header(int fd, struct store_header *hdr, char **errptr)
{
	ssize_t r;
	static char ebuf[512];

	if ((r = atomicio(read, fd, hdr, sizeof(*hdr))) == -1)
		SFAIL(-1, "read error");
	if (r < (ssize_t)sizeof(*hdr))
		SFAILX(-1, "premature EOF");

	if (ntohl(hdr->magic) != STORE_MAGIC)
		SFAILX(-1, "Bad magic");
	if (ntohl(hdr->version) != STORE_VERSION)	
		SFAILX(-1, "Unsupported version");

	return (0);
}

static int
read_field(int fd, void *f, ssize_t l, char **errptr, char *desc)
{
	ssize_t r;
	static char ebuf[256];

	if ((r = atomicio(read, fd, f, l)) == -1) {
		if (errptr != NULL) {
			snprintf(ebuf, sizeof(ebuf),
			    "read error on flow %s: %s", desc, strerror(errno));
			*errptr = ebuf;
		}
		return (-1);
	}
	if (r < l) {
		if (errptr != NULL) {
			snprintf(ebuf, sizeof(ebuf), "EOF reading %s", desc);
			*errptr = ebuf;
		}
		return (0);
	}

	return (1);
}

int
store_get_flow(int fd, struct store_flow_complete *f, char **errptr)
{
	int r;
	struct store_flow_AGENT_ADDR_V4 aa4;
	struct store_flow_AGENT_ADDR_V6 aa6;
	struct store_flow_SRCDST_ADDR_V4 sda4;
	struct store_flow_SRCDST_ADDR_V6 sda6;
	struct store_flow_GATEWAY_ADDR_V4 ga4;
	struct store_flow_GATEWAY_ADDR_V6 ga6;
	u_int32_t fields, crc;

	bzero(f, sizeof(*f));

	/* Return -1 on error or 0 on eof */
	r = read_field(fd, &f->hdr, sizeof(f->hdr), errptr, "header");
	if (r == 0 || r == -1)
		return (r);

	fields = ntohl(f->hdr.fields);

#define SHASFIELD(flag)				\
	(fields & STORE_FIELD_##flag)
#define RFIELD(flag, dest, desc) do { \
		if (SHASFIELD(flag)) { \
	 		if (read_field(fd, &dest, sizeof(dest), errptr, \
			    desc) <= 0) \
				return (-1); \
			if (SHASFIELD(CRC32) && \
			    STORE_FIELD_##flag != STORE_FIELD_CRC32) { \
				crc32_update((u_char *)&dest, sizeof(dest), \
				    &crc); \
			} \
		} \
	} while (0)

	if (SHASFIELD(CRC32))
		crc32_start(&crc);

	RFIELD(PROTO_FLAGS_TOS, f->pft, "proto/flags/tos");
	RFIELD(AGENT_ADDR4, aa4, "IPv4 agent addr");
	RFIELD(AGENT_ADDR6, aa6, "IPv6 agent addr");
	RFIELD(SRCDST_ADDR4, sda4, "IPv4 source/dest addrs");
	RFIELD(SRCDST_ADDR6, sda6, "IPv6 source/dest addrs");
	RFIELD(GATEWAY_ADDR4, ga4, "IPv4 gateway addr");
	RFIELD(GATEWAY_ADDR6, ga6, "IPv6 gateway addr");
	RFIELD(SRCDST_PORT, f->ports, "ports");
	RFIELD(PACKETS_OCTETS, f->counters, "counters");
	RFIELD(IF_INDICES, f->ifndx, "interface indicies");
	RFIELD(AGENT_INFO, f->ainfo, "agent info");
	RFIELD(FLOW_TIMES, f->ftimes, "info");
	RFIELD(AS_INFO, f->asinf, "AS info");
	RFIELD(FLOW_ENGINE_INFO, f->finf, "engine info");
	RFIELD(CRC32, f->crc32, "crc32");

	/* Sanity check and convert addresses */
	if (SHASFIELD(AGENT_ADDR4) && SHASFIELD(AGENT_ADDR6))
		SFAILX(-1, "Flow has both v4/v6 agent addrs");
	if (SHASFIELD(SRCDST_ADDR4) && SHASFIELD(SRCDST_ADDR6))
		SFAILX(-1, "Flow has both v4/v6 src/dst addrs");
	if (SHASFIELD(GATEWAY_ADDR4) && SHASFIELD(GATEWAY_ADDR6))
		SFAILX(-1, "Flow has both v4/v6 gateway addrs");

#define S_CPYADDR(d, s, fam) do {					\
		(d).af = (fam == 4) ? AF_INET : AF_INET6;		\
		memcpy(&d.v##fam, &s, sizeof(d.v##fam));		\
	} while (0)

	if (SHASFIELD(AGENT_ADDR4))
		S_CPYADDR(f->agent_addr, aa4.flow_agent_addr, 4);
	if (SHASFIELD(AGENT_ADDR6))
		S_CPYADDR(f->agent_addr, aa6.flow_agent_addr, 6);
	if (SHASFIELD(SRCDST_ADDR4)) {
		S_CPYADDR(f->src_addr, sda4.src_addr, 4);
		S_CPYADDR(f->dst_addr, sda4.dst_addr, 4);
	}
	if (SHASFIELD(SRCDST_ADDR6)) {
		S_CPYADDR(f->src_addr, sda6.src_addr, 6);
		S_CPYADDR(f->dst_addr, sda6.dst_addr, 6);
	}
	if (SHASFIELD(GATEWAY_ADDR4))
		S_CPYADDR(f->gateway_addr, ga4.gateway_addr, 4);
	if (SHASFIELD(GATEWAY_ADDR6))
		S_CPYADDR(f->gateway_addr, ga6.gateway_addr, 6);

	if (SHASFIELD(CRC32) && crc != ntohl(f->crc32.crc32))
		SFAILX(-1, "Flow checksum mismatch");

#undef S_CPYADDR
#undef SHASFIELD
#undef RFIELD

	return (1);
}

int
store_put_header(int fd, char **errptr)
{
	struct store_header hdr;
	char ebuf[512];
	int r;

	bzero(&hdr, sizeof(hdr));
	hdr.magic = htonl(STORE_MAGIC);
	hdr.version = htonl(STORE_VERSION);
	hdr.start_time = htonl(time(NULL));
	hdr.flags = htonl(0);

	r = atomicio(vwrite, fd, &hdr, sizeof(hdr));
	if (r == -1)
		SFAIL(-1, "write error on header");
	if (r < (ssize_t)sizeof(hdr))
		SFAILX(-1, "EOF while writing header");

	return (0);
}

static int
write_flow(int fd, char **errptr, 
    u_int32_t fields, 
    struct store_flow_complete *flow, 
    struct store_flow_AGENT_ADDR_V4 *aa4,
    struct store_flow_AGENT_ADDR_V6 *aa6, 
    struct store_flow_SRCDST_ADDR_V4 *sda4,
    struct store_flow_SRCDST_ADDR_V6 *sda6,
    struct store_flow_GATEWAY_ADDR_V4 *gwa4,
    struct store_flow_GATEWAY_ADDR_V6 *gwa6)
{
	char ebuf[512];
	int r;
	u_int32_t crc;

	if (fields & (STORE_FIELD_CRC32))
		crc32_start(&crc);

	if ((r = atomicio(vwrite, fd, &flow->hdr, sizeof(flow->hdr))) == -1)
		SFAIL(-1, "write flow header");
	else if (r < (ssize_t)sizeof(flow->hdr))
		SFAILX(-1, "EOF writing flow header");

#define WRITEOUT(spec, what) do {					\
	if ((fields & (STORE_FIELD_##spec))) {				\
		r = atomicio(vwrite, fd, (what), sizeof(*(what)));	\
		if (r == -1)						\
			SFAIL(-1, "write " #spec);			\
		if (r < (ssize_t)sizeof(what))				\
			SFAILX(-1, "EOF writing " #spec);		\
		if ((fields & (STORE_FIELD_CRC32)) && 			\
		    (STORE_FIELD_##spec != STORE_FIELD_CRC32)) {	\
			crc32_update((u_char *)(what), sizeof(*(what)),	\
			    &crc);					\
		}							\
	}  } while (0)

	WRITEOUT(PROTO_FLAGS_TOS, &flow->pft);
	WRITEOUT(AGENT_ADDR4, aa4);
	WRITEOUT(AGENT_ADDR6, aa6);
	WRITEOUT(SRCDST_ADDR4, sda4);
	WRITEOUT(SRCDST_ADDR6, sda6);
	WRITEOUT(GATEWAY_ADDR4, gwa4);
	WRITEOUT(GATEWAY_ADDR6, gwa6);
	WRITEOUT(SRCDST_PORT, &flow->ports);
	WRITEOUT(PACKETS_OCTETS, &flow->counters);
	WRITEOUT(IF_INDICES, &flow->ifndx);
	WRITEOUT(AGENT_INFO, &flow->ainfo);
	WRITEOUT(FLOW_TIMES, &flow->ftimes);
	WRITEOUT(AS_INFO, &flow->asinf);
	WRITEOUT(FLOW_ENGINE_INFO, &flow->finf);

	if (fields & (STORE_FIELD_CRC32))
		flow->crc32.crc32 = htonl(crc);

	WRITEOUT(CRC32, &flow->crc32);
#undef WRITEOUT

	return (0);

}

int
store_put_flow(int fd, struct store_flow_complete *flow, u_int32_t fieldmask,
    char **errptr)
{
	struct store_flow_AGENT_ADDR_V4 aa4;
	struct store_flow_AGENT_ADDR_V6 aa6;
	struct store_flow_SRCDST_ADDR_V4 sda4;
	struct store_flow_SRCDST_ADDR_V6 sda6;
	struct store_flow_GATEWAY_ADDR_V4 gwa4;
	struct store_flow_GATEWAY_ADDR_V6 gwa6;
	u_int32_t fields, origfields;
	off_t startpos;
	char ebuf[512];

	/* Remember where we started, so we can back errors out */	
	if ((startpos = lseek(fd, 0, SEEK_CUR)) == -1)
		SFAIL(-1, __func__ ":lseek");

	origfields = ntohl(flow->hdr.fields);
	fields = origfields & fieldmask;

	/* Convert addresses and set AF fields correctly */
	switch(flow->agent_addr.af) {
	case AF_INET:
		if ((fields & STORE_FIELD_AGENT_ADDR4) == 0)
			break;
		memcpy(&aa4.flow_agent_addr, &flow->agent_addr.v4,
		    sizeof(aa4.flow_agent_addr));
		fields |= STORE_FIELD_AGENT_ADDR4;
		fields &= ~STORE_FIELD_AGENT_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_FIELD_AGENT_ADDR6) == 0)
			break;
		memcpy(&aa6.flow_agent_addr, &flow->agent_addr.v6,
		    sizeof(aa6.flow_agent_addr));
		fields |= STORE_FIELD_AGENT_ADDR6;
		fields &= ~STORE_FIELD_AGENT_ADDR4;
		break;
	default:
		SFAILX(-1, __func__ "silly agent addr af");
	}

	/* NB. Assume that this is the same as dst_addr.af */
	switch(flow->src_addr.af) {
	case AF_INET:
		if ((fields & STORE_FIELD_SRCDST_ADDR4) == 0)
			break;
		memcpy(&sda4.src_addr, &flow->src_addr.v4,
		    sizeof(sda4.src_addr));
		memcpy(&sda4.dst_addr, &flow->dst_addr.v4,
		    sizeof(sda4.dst_addr));
		fields |= STORE_FIELD_SRCDST_ADDR4;
		fields &= ~STORE_FIELD_SRCDST_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_FIELD_SRCDST_ADDR6) == 0)
			break;
		memcpy(&sda6.src_addr, &flow->src_addr.v6,
		    sizeof(sda6.src_addr));
		memcpy(&sda6.dst_addr, &flow->dst_addr.v6,
		    sizeof(sda6.dst_addr));
		fields |= STORE_FIELD_SRCDST_ADDR6;
		fields &= ~STORE_FIELD_SRCDST_ADDR4;
		break;
	default:
		SFAILX(-1, __func__ "silly src/dst addrs af");
	}
	
	switch(flow->gateway_addr.af) {
	case AF_INET:
		if ((fields & STORE_FIELD_GATEWAY_ADDR4) == 0)
			break;
		memcpy(&gwa4.gateway_addr, &flow->gateway_addr.v4,
		    sizeof(gwa4.gateway_addr));
		fields |= STORE_FIELD_GATEWAY_ADDR4;
		fields &= ~STORE_FIELD_GATEWAY_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_FIELD_GATEWAY_ADDR6) == 0)
			break;
		memcpy(&gwa6.gateway_addr, &flow->gateway_addr.v6,
		    sizeof(gwa6.gateway_addr));
		fields |= STORE_FIELD_GATEWAY_ADDR6;
		fields &= ~STORE_FIELD_GATEWAY_ADDR4;
		break;
	default:
		SFAILX(-1, __func__ "silly gateway addr af");
	}

	flow->hdr.fields = htonl(fields);

	if (write_flow(fd, errptr, fields, flow, &aa4, &aa6, &sda4, &sda6,
	    &gwa4, &gwa6) == 0) {
		flow->hdr.fields = htonl(origfields);
		return (0);
	}

	flow->hdr.fields = htonl(origfields);

	/* Try to rewind to starting position, so we don't corrupt flow store */	
	if (lseek(fd, startpos, SEEK_SET) == -1)
		SFAIL(-2, __func__ ": corrupting failure on lseek");
	if (ftruncate(fd, startpos) == -1)
		SFAIL(-2, __func__ ": corrupting failure on ftruncate");

	/* Partial flow record has been removed */
	return (-1);
}

const char *
iso_time(time_t t, int utc_flag)
{
	struct tm *tm;
	static char buf[128];

	if (utc_flag)
		tm = gmtime(&t);
	else
		tm = localtime(&t);

	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);

	return (buf);
}

#define MINUTE		(60)
#define HOUR		(MINUTE * 60)
#define DAY		(HOUR * 24)
#define WEEK		(DAY * 7)
#define YEAR		(WEEK * 52)
const char *
interval_time(time_t t)
{
	static char buf[128];
	char tmp[128];
	u_long r;
	int unit_div[] = { YEAR, WEEK, DAY, HOUR, MINUTE, 1, -1 };
	char unit_sym[] = { 'y', 'w', 'd', 'h', 'm', 's' };
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

void
store_format_flow(struct store_flow_complete *flow, char *buf, size_t len, 
    int utc_flag, u_int32_t display_mask)
{
	char tmp[256];
	u_int32_t fields;

	*buf = '\0';

	fields = ntohl(flow->hdr.fields) & display_mask;

	printf("FLOW tag %u %s ", ntohl(flow->hdr.tag),
	    iso_time(ntohl(flow->hdr.recv_secs), utc_flag));

#define HASFIELD(flag)	(fields & STORE_FIELD_##flag)

	if (HASFIELD(PROTO_FLAGS_TOS)) {
		snprintf(tmp, sizeof(tmp), "proto %d ", flow->pft.protocol);
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "tcpflags %x ", flow->pft.tcp_flags);
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "tos %02x " , flow->pft.tos);
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(AGENT_ADDR4) || HASFIELD(AGENT_ADDR6)) {
		snprintf(tmp, sizeof(tmp), "agent %s ",
		    addr_ntop_buf(&flow->agent_addr));
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(SRCDST_ADDR4) || HASFIELD(SRCDST_ADDR6)) {
		snprintf(tmp, sizeof(tmp), "src %s",
		    addr_ntop_buf(&flow->src_addr));
		strlcat(buf, tmp, len);
		if (HASFIELD(SRCDST_PORT)) {
			snprintf(tmp, sizeof(tmp), ":%d",
			    ntohs(flow->ports.src_port));
			strlcat(buf, tmp, len);
		}
		strlcat(buf, " ", len);
		snprintf(tmp, sizeof(tmp), "dst %s",
		    addr_ntop_buf(&flow->dst_addr));
		strlcat(buf, tmp, len);
		if (HASFIELD(SRCDST_PORT)) {
			snprintf(tmp, sizeof(tmp), ":%d",
			    ntohs(flow->ports.dst_port));
			strlcat(buf, tmp, len);
		}
		strlcat(buf, " ", len);
	}
	if (HASFIELD(GATEWAY_ADDR4) ||
	    HASFIELD(GATEWAY_ADDR6)) {
		snprintf(tmp, sizeof(tmp), "gateway %s ",
		    addr_ntop_buf(&flow->gateway_addr));
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(PACKETS_OCTETS)) {
		snprintf(tmp, sizeof(tmp), "packets %llu octets %llu ", 
		    (u_int64_t)betoh64(flow->counters.flow_packets),
		    (u_int64_t)betoh64(flow->counters.flow_octets));
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(IF_INDICES)) {
		snprintf(tmp, sizeof(tmp), "in_if %d out_if %d ", 
			ntohs(flow->ifndx.if_index_in),
			ntohs(flow->ifndx.if_index_out));
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(AGENT_INFO)) {
		snprintf(tmp, sizeof(tmp), "sys_uptime_ms %s.%03u ",
		    interval_time(ntohl(flow->ainfo.sys_uptime_ms) / 1000),
		    ntohl(flow->ainfo.sys_uptime_ms) % 1000);
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "time_sec %s ",
		    iso_time(ntohl(flow->ainfo.time_sec), utc_flag));
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "time_nanosec %lu netflow ver %u ",
		    (u_long)ntohl(flow->ainfo.time_nanosec),
		    ntohs(flow->ainfo.netflow_version));
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(FLOW_TIMES)) {
		snprintf(tmp, sizeof(tmp), "flow_start %s.%03u ", 
		    interval_time(ntohl(flow->ftimes.flow_start) / 1000),
		    ntohl(flow->ftimes.flow_start) % 1000);
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "flow_finish %s.%03u ", 
		    interval_time(ntohl(flow->ftimes.flow_finish) / 1000),
		    ntohl(flow->ftimes.flow_finish) % 1000);
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(AS_INFO)) {
		snprintf(tmp, sizeof(tmp), "src_AS %u src_masklen %u ", 
		    ntohs(flow->asinf.src_as), flow->asinf.src_mask);
		strlcat(buf, tmp, len);
		snprintf(tmp, sizeof(tmp), "dst_AS %u dst_masklen %u ", 
		    ntohs(flow->asinf.dst_as), flow->asinf.dst_mask);
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(FLOW_ENGINE_INFO)) {
		snprintf(tmp, sizeof(tmp),
		    "engine_type %u engine_id %u seq %lu ", 
		    flow->finf.engine_type,  flow->finf.engine_id,
		    (u_long)ntohl(flow->finf.flow_sequence));
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(CRC32)) {
		snprintf(tmp, sizeof(tmp), "crc32 %08x ",
		    ntohl(flow->crc32.crc32));
		strlcat(buf, tmp, len);
	}
}

