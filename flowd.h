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

#ifndef _FLOWD_H
#define _FLOWD_H

#include "common.h"
#include "sys-queue.h"
#include "addr.h"
#include "filter.h"

#define PROGNAME	"flowd"
#define PROGVER		"0"
#define DEFAULT_CONFIG	"/etc/flowd.conf"
#define DEFAULT_PIDFILE	"/var/run/flowd.pid"
#define PRIVSEP_USER	"_flowd"

struct listen_addr {
	struct xaddr			addr;
	u_int16_t			port;
	int				fd;
	TAILQ_ENTRY(listen_addr)	entry;
};
TAILQ_HEAD(listen_addrs, listen_addr);

#define FLOWD_OPT_DONT_FORK		(1)
#define FLOWD_OPT_VERBOSE		(1<<1)
struct flowd_config {
	char			*log_file;
	char			*pid_file;
	u_int32_t		store_mask;
	u_int32_t		opts;
	struct listen_addrs	listen_addrs;
	struct filter_list	filter_list;
};

/* parse.y */
int parse_config(const char *, struct flowd_config *);
int cmdline_symset(char *);

#endif /* _FLOWD_H */
