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

/* On-disk storage format */

#ifndef _STORE_H
#define _STORE_H

#include <sys/types.h>
#include "addr.h"

/* On-disk address formats for v4 and v6 addresses */
struct store_addr6 {
	u_int8_t	d[16];
} __packed;
struct store_addr4 {
	u_int8_t	d[4];
} __packed;

#define STORE_MAGIC			0x012cf047
#define STORE_VERSION			0x00000001
/* Start of flow log file */
struct store_header {
	u_int32_t		magic;
	u_int32_t		version;
	u_int32_t		start_time;
	u_int32_t		flags;	/* Currently 0 */
} __packed;

/*
 * Optional flow fields, specify what is stored for the flow
 * NB - the flow records appear in this order on disk
 */
#define STORE_FIELD_PROTO_FLAGS_TOS	(1U)
#define STORE_FIELD_AGENT_ADDR4		(1U<<1)
#define STORE_FIELD_AGENT_ADDR6		(1U<<2)
#define STORE_FIELD_SRCDST_ADDR4	(1U<<3)
#define STORE_FIELD_SRCDST_ADDR6	(1U<<4)
#define STORE_FIELD_GATEWAY_ADDR4	(1U<<5)
#define STORE_FIELD_GATEWAY_ADDR6	(1U<<6)
#define STORE_FIELD_SRCDST_PORT		(1U<<7)
#define STORE_FIELD_PACKETS_OCTETS	(1U<<8)
#define STORE_FIELD_IF_INDICES		(1U<<9)
#define STORE_FIELD_AGENT_INFO		(1U<<10)
#define STORE_FIELD_FLOW_TIMES		(1U<<11)
#define STORE_FIELD_AS_INFO		(1U<<12)
#define STORE_FIELD_FLOW_ENGINE_INFO	(1U<<13)

#define STORE_FIELD_ALL			((1U<<14)-1)

/* Useful combinations for displaying flows */
#define STORE_DISPLAY_ALL		STORE_FIELD_ALL
#define STORE_DISPLAY_BRIEF		(STORE_FIELD_PROTO_FLAGS_TOS|\
					 STORE_FIELD_SRCDST_PORT|\
					 STORE_FIELD_PACKETS_OCTETS|\
					 STORE_FIELD_SRCDST_ADDR4|\
					 STORE_FIELD_SRCDST_ADDR6|\
					 STORE_FIELD_AGENT_ADDR4|\
					 STORE_FIELD_AGENT_ADDR6)

/* Start of flow record - present for every flow */
struct store_flow {
	u_int32_t		fields;
	u_int32_t		tag; /* set by filter */
	u_int32_t		recv_secs;
} __packed;

/* Optional flow field - present if STORE_FIELD_PROTO_FLAGS_TOS */
struct store_flow_PROTO_FLAGS_TOS {
	u_int8_t		tcp_flags;
	u_int8_t		protocol;
	u_int8_t		tos;
	u_int8_t		pad;
} __packed;

/* Optional flow field - present if STORE_FIELD_AGENT_ADDR */
struct store_flow_AGENT_ADDR_V4 {
	struct store_addr4	flow_agent_addr;
} __packed;
struct store_flow_AGENT_ADDR_V6 {
	struct store_addr6	flow_agent_addr;
} __packed;

/* Optional flow field - present if STORE_FIELD_SRCDST_ADDR */
struct store_flow_SRCDST_ADDR_V4 {
	struct store_addr4	src_addr;
	struct store_addr4	dst_addr;
} __packed;
struct store_flow_SRCDST_ADDR_V6 {
	struct store_addr6	src_addr;
	struct store_addr6	dst_addr;
} __packed;

/* Optional flow field - present if STORE_FIELD_GATEWAY_ADDR */
struct store_flow_GATEWAY_ADDR_V4 {
	struct store_addr4	gateway_addr;
} __packed;
struct store_flow_GATEWAY_ADDR_V6 {
	struct store_addr6	gateway_addr;
} __packed;

/* Optional flow field - present if STORE_FIELD_SRCDST_PORT */
struct store_flow_FLOW_SRCDST_PORT {
	u_int16_t		src_port;
	u_int16_t		dst_port;
} __packed;

/* Optional flow field - present if STORE_FIELD_PACKETS_OCTETS */
struct store_flow_PACKETS_OCTETS {
	u_int64_t		flow_packets;
	u_int64_t		flow_octets;
} __packed;

/* Optional flow field - present if STORE_FIELD_IF_INDICES */
struct store_flow_IF_INDICES {
	u_int16_t		if_index_in;
	u_int16_t		if_index_out;
} __packed;

/* Optional flow field - present if STORE_FIELD_AGENT_INFO */
struct store_flow_AGENT_INFO {
	u_int32_t		sys_uptime_ms;
	u_int32_t		time_sec;
	u_int32_t		time_nanosec;
	u_int16_t		netflow_version;
	u_int16_t		pad;
} __packed;

/* Optional flow field - present if STORE_FIELD_FLOW_TIMES */
struct store_flow_FLOW_TIMES {
	u_int32_t		flow_start;
	u_int32_t		flow_finish;
} __packed;

/* Optional flow field - present if STORE_FIELD_AS_INFO */
struct store_flow_AS_INFO {
	u_int16_t		src_as;
	u_int16_t		dst_as;
	u_int8_t		src_mask;
	u_int8_t		dst_mask;
	u_int16_t		pad;
} __packed;

/* Optional flow field - present if STORE_FIELD_FLOW_ENGINE_INFO */
struct store_flow_FLOW_ENGINE_INFO {
	u_int8_t		engine_type;
	u_int8_t		engine_id;
	u_int16_t		pad;
	u_int32_t		flow_sequence;
} __packed;

/* A abstract flow record (all fields included) */
struct store_flow_complete {
	struct store_flow			hdr;
	struct store_flow_PROTO_FLAGS_TOS	pft;
	struct xaddr				agent_addr;
	struct xaddr				src_addr;
	struct xaddr				dst_addr;
	struct xaddr				gateway_addr;
	struct store_flow_FLOW_SRCDST_PORT	ports;
	struct store_flow_PACKETS_OCTETS	counters;
	struct store_flow_IF_INDICES		ifndx;
	struct store_flow_AGENT_INFO		ainfo;
	struct store_flow_FLOW_TIMES		ftimes;
	struct store_flow_AS_INFO		asinf;
	struct store_flow_FLOW_ENGINE_INFO	finf;
} __packed;

int store_get_header(int fd, struct store_header *hdr, char **errptr);
int store_get_flow(int fd, struct store_flow_complete *f, char **errptr);
int store_put_header(int fd, char **errptr);
int store_put_flow(int fd, struct store_flow_complete *flow, char **errptr);

const char *iso_time(time_t t, int utc_flag);
const char *interval_time(time_t t);
void store_format_flow(struct store_flow_complete *flow, char *buf,
    size_t len, int utc_flag, u_int32_t display_mask);

#endif /* _STORE_H */
