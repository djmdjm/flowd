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
#include <time.h>
#include <poll.h>

#include "store.h"
#include "atomicio.h"
#include "crc32.h"

RCSID("$Id$");

/* Stash error message and return */
#define SFAILX(i, m, f) do {						\
		if (errptr != NULL) {					\
			snprintf(ebuf, sizeof(ebuf), "%s%s%s",		\
			    (f) ? __func__ : "", (f) ? ": " : "", m);	\
			*errptr = ebuf;					\
		}							\
		return (i);						\
	} while (0)

/* Stash error message, appending strerror into local "ebuf" and return */
#define SFAIL(i, m, f) do {						\
		if (errptr != NULL) {					\
			snprintf(ebuf, sizeof(ebuf), "%s%s%s: %s", 	\
			    (f) ? __func__ : "", (f) ? ": " : "", m, 	\
			    strerror(errno));				\
			*errptr = ebuf;					\
		}							\
		return (i);						\
	} while (0)


int
store_get_header(int fd, struct store_header *hdr, const char **errptr)
{
	ssize_t r;
	static char ebuf[512];

	if ((r = atomicio(read, fd, hdr, sizeof(*hdr))) == -1)
		SFAIL(-1, "read error", 0);
	if (r < (ssize_t)sizeof(*hdr))
		SFAILX(-1, "premature EOF", 0);

	if (ntohl(hdr->magic) != STORE_MAGIC)
		SFAILX(-1, "Bad magic", 0);
	if (ntohl(hdr->version) != STORE_VERSION)	
		SFAILX(-1, "Unsupported version", 0);

	return (0);
}

static int
read_field(int fd, void *f, ssize_t l, const char **errptr, const char *desc)
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
store_get_flow(int fd, struct store_flow_complete *f, const char **errptr)
{
	int r;
	struct store_flow_AGENT_ADDR_V4 aa4;
	struct store_flow_AGENT_ADDR_V6 aa6;
	struct store_flow_SRC_ADDR_V4 sa4;
	struct store_flow_SRC_ADDR_V6 sa6;
	struct store_flow_DST_ADDR_V4 da4;
	struct store_flow_DST_ADDR_V6 da6;
	struct store_flow_GATEWAY_ADDR_V4 ga4;
	struct store_flow_GATEWAY_ADDR_V6 ga6;
	u_int32_t fields, crc;
	static char ebuf[256];

	bzero(f, sizeof(*f));
	crc32_start(&crc);

	/* Return -1 on error or 0 on eof */
	r = read_field(fd, &f->hdr, sizeof(f->hdr), errptr, "header");
	if (r == 0 || r == -1)
		return (r);

	crc32_update((u_char *)&f->hdr, sizeof(f->hdr), &crc);

	fields = ntohl(f->hdr.fields);

#define SHASFIELD(flag)				\
	(fields & STORE_FIELD_##flag)
#define RFIELD(flag, dest, desc) do { \
		if (SHASFIELD(flag)) { \
	 		if (read_field(fd, &dest, sizeof(dest), errptr, \
			    desc) <= 0) \
				return (-1); \
			if (STORE_FIELD_##flag != STORE_FIELD_CRC32) { \
				crc32_update((u_char *)&dest, sizeof(dest), \
				    &crc); \
			} \
		} \
	} while (0)

	RFIELD(TAG, f->tag, "tag");
	RFIELD(RECV_TIME, f->recv_time, "receive time");
	RFIELD(PROTO_FLAGS_TOS, f->pft, "proto/flags/tos");
	RFIELD(AGENT_ADDR4, aa4, "IPv4 agent addr");
	RFIELD(AGENT_ADDR6, aa6, "IPv6 agent addr");
	RFIELD(SRC_ADDR4, sa4, "IPv4 source addrs");
	RFIELD(SRC_ADDR6, sa6, "IPv6 source addrs");
	RFIELD(DST_ADDR4, da4, "IPv4 dest addrs");
	RFIELD(DST_ADDR6, da6, "IPv6 dest addrs");
	RFIELD(GATEWAY_ADDR4, ga4, "IPv4 gateway addr");
	RFIELD(GATEWAY_ADDR6, ga6, "IPv6 gateway addr");
	RFIELD(SRCDST_PORT, f->ports, "ports");
	RFIELD(PACKETS, f->packets, "packets");
	RFIELD(OCTETS, f->octets, "octets");
	RFIELD(IF_INDICES, f->ifndx, "interface indicies");
	RFIELD(AGENT_INFO, f->ainfo, "agent info");
	RFIELD(FLOW_TIMES, f->ftimes, "info");
	RFIELD(AS_INFO, f->asinf, "AS info");
	RFIELD(FLOW_ENGINE_INFO, f->finf, "engine info");
	RFIELD(CRC32, f->crc32, "crc32");

	/* Sanity check and convert addresses */
	if (SHASFIELD(AGENT_ADDR4) && SHASFIELD(AGENT_ADDR6))
		SFAILX(-1, "Flow has both v4/v6 agent addrs", 0);
	if (SHASFIELD(SRC_ADDR4) && SHASFIELD(SRC_ADDR6))
		SFAILX(-1, "Flow has both v4/v6 src addrs", 0);
	if (SHASFIELD(DST_ADDR4) && SHASFIELD(DST_ADDR6))
		SFAILX(-1, "Flow has both v4/v6 dst addrs", 0);
	if (SHASFIELD(GATEWAY_ADDR4) && SHASFIELD(GATEWAY_ADDR6))
		SFAILX(-1, "Flow has both v4/v6 gateway addrs", 0);

#define S_CPYADDR(d, s, fam) do {					\
		(d).af = (fam == 4) ? AF_INET : AF_INET6;		\
		memcpy(&d.v##fam, &s, sizeof(d.v##fam));		\
	} while (0)

	if (SHASFIELD(AGENT_ADDR4))
		S_CPYADDR(f->agent_addr, aa4.flow_agent_addr, 4);
	if (SHASFIELD(AGENT_ADDR6))
		S_CPYADDR(f->agent_addr, aa6.flow_agent_addr, 6);
	if (SHASFIELD(SRC_ADDR4))
		S_CPYADDR(f->src_addr, sa4.src_addr, 4);
	if (SHASFIELD(SRC_ADDR6))
		S_CPYADDR(f->src_addr, sa6.src_addr, 6);
	if (SHASFIELD(DST_ADDR4))
		S_CPYADDR(f->dst_addr, da4.dst_addr, 4);
	if (SHASFIELD(DST_ADDR6))
		S_CPYADDR(f->dst_addr, da6.dst_addr, 6);
	if (SHASFIELD(GATEWAY_ADDR4))
		S_CPYADDR(f->gateway_addr, ga4.gateway_addr, 4);
	if (SHASFIELD(GATEWAY_ADDR6))
		S_CPYADDR(f->gateway_addr, ga6.gateway_addr, 6);

	if (SHASFIELD(CRC32) && crc != ntohl(f->crc32.crc32))
		SFAILX(-1, "Flow checksum mismatch", 0);

#undef S_CPYADDR
#undef SHASFIELD
#undef RFIELD

	return (1);
}

int
store_check_header(int fd, const char **errptr)
{
	struct store_header hdr;
	char ebuf[512];
	int r;

	if ((r = store_get_header(fd, &hdr, errptr)) != 0)
		return (r);

	/* store_get_header does all the magic & version checks for us */

	return (0);
}

int
store_put_header(int fd, const char **errptr)
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
		SFAIL(-1, "write error on header", 0);
	if (r < (ssize_t)sizeof(hdr))
		SFAILX(-1, "EOF while writing header", 0);

	return (0);
}

static int
write_flow(int fd, const char **errptr, 
    u_int32_t fields, 
    struct store_flow_complete *flow, 
    struct store_flow_AGENT_ADDR_V4 *aa4,
    struct store_flow_AGENT_ADDR_V6 *aa6, 
    struct store_flow_SRC_ADDR_V4 *sa4,
    struct store_flow_SRC_ADDR_V6 *sa6,
    struct store_flow_DST_ADDR_V4 *da4,
    struct store_flow_DST_ADDR_V6 *da6,
    struct store_flow_GATEWAY_ADDR_V4 *gwa4,
    struct store_flow_GATEWAY_ADDR_V6 *gwa6)
{
	char ebuf[512];
	int r;
	u_int32_t crc;

	crc32_start(&crc);
	crc32_update((u_char *)&flow->hdr, sizeof(flow->hdr), &crc);

	if ((r = atomicio(vwrite, fd, &flow->hdr, sizeof(flow->hdr))) == -1)
		SFAIL(-1, "write flow header", 0);
	else if (r < (ssize_t)sizeof(flow->hdr))
		SFAILX(-1, "EOF writing flow header", 0);

#define WRITEOUT(spec, what) do {					\
	if ((fields & (STORE_FIELD_##spec))) {				\
		r = atomicio(vwrite, fd, (what), sizeof(*(what)));	\
		if (r == -1)						\
			SFAIL(-1, "write " #spec, 0);			\
		if (r < (ssize_t)sizeof(what))				\
			SFAILX(-1, "EOF writing " #spec, 0);		\
		if ((STORE_FIELD_##spec != STORE_FIELD_CRC32)) {	\
			crc32_update((u_char *)(what), sizeof(*(what)),	\
			    &crc);					\
		}							\
	}  } while (0)

	WRITEOUT(TAG, &flow->tag);
	WRITEOUT(RECV_TIME, &flow->recv_time);
	WRITEOUT(PROTO_FLAGS_TOS, &flow->pft);
	WRITEOUT(AGENT_ADDR4, aa4);
	WRITEOUT(AGENT_ADDR6, aa6);
	WRITEOUT(SRC_ADDR4, sa4);
	WRITEOUT(SRC_ADDR6, sa6);
	WRITEOUT(DST_ADDR4, da4);
	WRITEOUT(DST_ADDR6, da6);
	WRITEOUT(GATEWAY_ADDR4, gwa4);
	WRITEOUT(GATEWAY_ADDR6, gwa6);
	WRITEOUT(SRCDST_PORT, &flow->ports);
	WRITEOUT(PACKETS, &flow->packets);
	WRITEOUT(OCTETS, &flow->octets);
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
    const char **errptr)
{
	struct store_flow_AGENT_ADDR_V4 aa4;
	struct store_flow_AGENT_ADDR_V6 aa6;
	struct store_flow_SRC_ADDR_V4 sa4;
	struct store_flow_SRC_ADDR_V6 sa6;
	struct store_flow_DST_ADDR_V4 da4;
	struct store_flow_DST_ADDR_V6 da6;
	struct store_flow_GATEWAY_ADDR_V4 gwa4;
	struct store_flow_GATEWAY_ADDR_V6 gwa6;
	u_int32_t fields, origfields;
	off_t startpos;
	char ebuf[512];

	/* Remember where we started, so we can back errors out */	
	if ((startpos = lseek(fd, 0, SEEK_CUR)) == -1)
		SFAIL(-1, "lseek", 1);

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
		SFAILX(-1, "silly agent addr af", 1);
	}

	switch(flow->src_addr.af) {
	case AF_INET:
		if ((fields & STORE_FIELD_SRC_ADDR4) == 0)
			break;
		memcpy(&sa4.src_addr, &flow->src_addr.v4,
		    sizeof(sa4.src_addr));
		fields |= STORE_FIELD_SRC_ADDR4;
		fields &= ~STORE_FIELD_SRC_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_FIELD_SRC_ADDR6) == 0)
			break;
		memcpy(&sa6.src_addr, &flow->src_addr.v6,
		    sizeof(sa6.src_addr));
		fields |= STORE_FIELD_SRC_ADDR6;
		fields &= ~STORE_FIELD_SRC_ADDR4;
		break;
	default:
		SFAILX(-1, "silly src addrs af", 1);
	}
	
	switch(flow->dst_addr.af) {
	case AF_INET:
		if ((fields & STORE_FIELD_DST_ADDR4) == 0)
			break;
		memcpy(&da4.dst_addr, &flow->dst_addr.v4,
		    sizeof(da4.dst_addr));
		fields |= STORE_FIELD_DST_ADDR4;
		fields &= ~STORE_FIELD_DST_ADDR6;
		break;
	case AF_INET6:
		if ((fields & STORE_FIELD_DST_ADDR6) == 0)
			break;
		memcpy(&da6.dst_addr, &flow->dst_addr.v6,
		    sizeof(da6.dst_addr));
		fields |= STORE_FIELD_DST_ADDR6;
		fields &= ~STORE_FIELD_DST_ADDR4;
		break;
	default:
		SFAILX(-1, "silly dst addrs af", 1);
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
		SFAILX(-1, "silly gateway addr af", 1);
	}

	flow->hdr.fields = htonl(fields);

	if (write_flow(fd, errptr, fields, flow, &aa4, &aa6, 
	    &sa4, &sa6, &da4, &da6, &gwa4, &gwa6) == 0) {
		flow->hdr.fields = htonl(origfields);
		return (0);
	}

	flow->hdr.fields = htonl(origfields);

	/* Try to rewind to starting position, so we don't corrupt flow store */	
	if (lseek(fd, startpos, SEEK_SET) == -1)
		SFAIL(-2, "corrupting failure on lseek", 1);
	if (ftruncate(fd, startpos) == -1)
		SFAIL(-2, "corrupting failure on ftruncate", 1);

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

	strlcat(buf, "FLOW ", len);

#define HASFIELD(flag)	(fields & STORE_FIELD_##flag)

	if (HASFIELD(TAG)) {
		snprintf(tmp, sizeof(tmp), "tag %u ", ntohl(flow->tag.tag));
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(RECV_TIME)) {
		snprintf(tmp, sizeof(tmp), "recv_time %s ", 
		    iso_time(ntohl(flow->recv_time.recv_secs), utc_flag));
		strlcat(buf, tmp, len);
	}
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
	if (HASFIELD(SRC_ADDR4) || HASFIELD(SRC_ADDR6)) {
		snprintf(tmp, sizeof(tmp), "src %s",
		    addr_ntop_buf(&flow->src_addr));
		strlcat(buf, tmp, len);
		if (HASFIELD(SRCDST_PORT)) {
			snprintf(tmp, sizeof(tmp), ":%d",
			    ntohs(flow->ports.src_port));
			strlcat(buf, tmp, len);
		}
		strlcat(buf, " ", len);
	}
	if (HASFIELD(DST_ADDR4) || HASFIELD(DST_ADDR6)) {
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
	if (HASFIELD(GATEWAY_ADDR4) || HASFIELD(GATEWAY_ADDR6)) {
		snprintf(tmp, sizeof(tmp), "gateway %s ",
		    addr_ntop_buf(&flow->gateway_addr));
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(PACKETS)) {
		snprintf(tmp, sizeof(tmp), "packets %llu ",
		    store_ntohll(flow->packets.flow_packets));
		strlcat(buf, tmp, len);
	}
	if (HASFIELD(OCTETS)) {
		snprintf(tmp, sizeof(tmp), "octets %llu ", 
		    store_ntohll(flow->octets.flow_octets));
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

u_int64_t
store_ntohll(u_int64_t v)
{
#if defined(HAVE_BETOH64)
	v = betoh64(v);
#elif !defined(WORDS_BIGENDIAN)
        v = (v & 0xff) << 56 |
	    (v & 0xff00ULL) << 40 |
	    (v & 0xff0000ULL) << 24 |
	    (v & 0xff000000ULL) << 8 |
	    (v & 0xff00000000ULL) >> 8 |
	    (v & 0xff0000000000ULL) >> 24 |
	    (v & 0xff000000000000ULL) >> 40 |
	    (v & 0xff00000000000000ULL) >> 56;
#endif

	return (v);
}

u_int64_t
store_htonll(u_int64_t v)
{
#if defined(HAVE_BETOH64)
	v = htobe64(v);
#elif !defined(WORDS_BIGENDIAN)
        v = (v & 0xff) << 56 |
	    (v & 0xff00ULL) << 40 |
	    (v & 0xff0000ULL) << 24 |
	    (v & 0xff000000ULL) << 8 |
	    (v & 0xff00000000ULL) >> 8 |
	    (v & 0xff0000000000ULL) >> 24 |
	    (v & 0xff000000000000ULL) >> 40 |
	    (v & 0xff00000000000000ULL) >> 56;
#endif

	return (v);
}
