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
#include <sys/queue.h>
#include <sys/time.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <err.h>
#include <poll.h>

#include "flowd.h"
#include "privsep.h"
#include "netflow.h"
#include "store.h"
#include "atomicio.h"

static sig_atomic_t exit_flag = 0;
static sig_atomic_t reopen_flag = 0;

void dump_config(struct flowd_config *);

/* Signal handlers */
static void
sighand_exit(int signo)
{
	exit_flag = signo;
}

static void
sighand_reopen(int signo)
{
	reopen_flag = 1;
}

/* Display commandline usage information */
static void
usage(void)
{
	fprintf(stderr, "Usage: %s [options]\n", PROGNAME);
	fprintf(stderr, "This is %s version %s. Valid commandline options:\n",
	    PROGNAME, PROGVER);
	fprintf(stderr, "  -d              Don't daemonise\n");
	fprintf(stderr, "  -h              Display this help\n");
	fprintf(stderr, "  -f path         Configuration file (default: %s)\n",
	    DEFAULT_CONFIG);
	fprintf(stderr, "\n");
}

static const char *
host_ntop(struct xaddr *a)
{
	static char hbuf[64];

	if (addr_ntop(a, hbuf, sizeof(hbuf)) == -1)
		return ("error");

	return (hbuf);
}

static const char *
from_ntop(struct sockaddr *s)
{
	static char hbuf[64], sbuf[32], ret[128];

	if (addr_ss_ntop((struct sockaddr_storage *)s, hbuf, sizeof(hbuf),
	    sbuf, sizeof(sbuf)) == -1)
		return ("error");

	snprintf(ret, sizeof(ret), "[%s]:%s", hbuf, sbuf);

	return (ret);
}

void
dump_config(struct flowd_config *c)
{
	struct filter_rule *fr;
	struct listen_addr *la;

	fprintf(stderr, "logfile \"%s\"\n", c->log_file);
	TAILQ_FOREACH(la, &c->listen_addrs, entry) {
		fprintf(stderr, "listen on [%s]:%d\n",
		    host_ntop(&la->addr), la->port);
	}

	TAILQ_FOREACH(fr, &c->filter_list, entry) {
		if (fr->action.action_what == FF_ACTION_ACCEPT)
			fprintf(stderr, "accept ");
		else if (fr->action.action_what == FF_ACTION_DISCARD)
			fprintf(stderr, "discard ");
		else if (fr->action.action_what == FF_ACTION_TAG)
			fprintf(stderr, "tag %lu ", (u_long)fr->action.tag);
		else
			fprintf(stderr, "UNKNOWN ");

		if (fr->quick)
			fprintf(stderr, "quick ");

		if (fr->match.match_what & FF_MATCH_AGENT_ADDR) {
			fprintf(stderr, "agent %s/%d ",
			    host_ntop(&fr->match.agent_addr), 
			    fr->match.agent_masklen);
		}

		if (fr->match.match_what & 
		    (FF_MATCH_SRC_ADDR|FF_MATCH_SRC_PORT)) {
			fprintf(stderr, "src %s/%d ",
			    host_ntop(&fr->match.src_addr), 
			    fr->match.src_masklen);
		}
		if (fr->match.match_what & FF_MATCH_SRC_PORT)
			fprintf(stderr, "port %d ", fr->match.src_port);

		if (fr->match.match_what & 
		    (FF_MATCH_DST_ADDR|FF_MATCH_DST_PORT)) {
			fprintf(stderr, "dst %s/%d ",
			    host_ntop(&fr->match.dst_addr), 
			    fr->match.dst_masklen);
		}
		if (fr->match.match_what & FF_MATCH_DST_PORT)
			fprintf(stderr, "port %d ", fr->match.dst_port);

		if (fr->match.match_what & FF_MATCH_PROTOCOL)
			fprintf(stderr, "proto %d ", fr->match.proto);

		if (fr->match.match_what & FF_MATCH_TOS)
			fprintf(stderr, "tos 0x%x ", fr->match.tos);

		fprintf(stderr, "\n");
	}
}

static int
start_log(int monitor_fd)
{
	int fd;
	struct store_header hdr;
	off_t pos;

	if ((fd = client_open_log(monitor_fd)) == -1) {
		syslog(LOG_CRIT, "Logfile open failed, exiting");
		exit(1);
	}

	/* Only write out the header if we are at the start of the file */
	switch ((pos = lseek(fd, 0, SEEK_END))) {
	case 0:
		/* New file, continue below */
		break;
	case -1:
		syslog(LOG_CRIT, "%s: llseek error, exiting: %s", __func__, 
		    strerror(errno));
		exit(1);
	default:
		/* Logfile exists, don't write new header */
		syslog(LOG_DEBUG, "Continuing with existing logfile len %lld", 
		    (long long)pos);
		return (fd);
	}

	syslog(LOG_DEBUG, "Writing new logfile header");

	bzero(&hdr, sizeof(hdr));
	hdr.magic = htonl(STORE_MAGIC);
	hdr.version = htonl(STORE_VERSION);
	hdr.start_time = htonl(time(NULL));
	hdr.flags = htonl(0);

	if (atomicio(vwrite, fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		syslog(LOG_CRIT, "%s: write log header failed, exiting: %s",
		    __func__, strerror(errno));
		exit(1);
	}

	return (fd);
}

static int
store_flow(int fd, struct store_flow_complete *flow)
{
	struct store_flow_AGENT_ADDR_V4 aa4;
	struct store_flow_AGENT_ADDR_V6 aa6;
	struct store_flow_SRCDST_ADDR_V4 sda4;
	struct store_flow_SRCDST_ADDR_V6 sda6;
	struct store_flow_GATEWAY_ADDR_V4 gwa4;
	struct store_flow_GATEWAY_ADDR_V6 gwa6;
	u_int32_t fieldspec;
	off_t startpos;

	syslog(LOG_DEBUG, "%s: entering", __func__);

	/* Remember where we started, so we can back errors out */	
	if ((startpos = lseek(fd, 0, SEEK_CUR)) == -1) {
		syslog(LOG_CRIT, "%s: lseek: %s", __func__, strerror(errno));
		return (-1);
	}

	/* Convert addresses and set AF fields correctly */

	switch(flow->agent_addr.af) {
	case AF_INET:
		memcpy(&aa4.flow_agent_addr, &flow->agent_addr.v4,
		    sizeof(aa4.flow_agent_addr));
		flow->hdr.fieldspec_flags |= STORE_FIELD_AGENT_ADDR4;
		break;
	case AF_INET6:
		memcpy(&aa6.flow_agent_addr, &flow->agent_addr.v6,
		    sizeof(aa6.flow_agent_addr));
		flow->hdr.fieldspec_flags |= STORE_FIELD_AGENT_ADDR6;
		break;
	default:
		syslog(LOG_WARNING, "%s: silly agent addr af", __func__);
		return (-1);
	}

	/* NB. Assume that this is the same as dst_addr.af */
	switch(flow->src_addr.af) {
	case AF_INET:
		memcpy(&sda4.src_addr, &flow->src_addr.v4,
		    sizeof(sda4.src_addr));
		memcpy(&sda4.dst_addr, &flow->dst_addr.v4,
		    sizeof(sda4.dst_addr));
		flow->hdr.fieldspec_flags |= STORE_FIELD_SRCDST_ADDR4;
		break;
	case AF_INET6:
		memcpy(&sda6.src_addr, &flow->src_addr.v6,
		    sizeof(sda6.src_addr));
		memcpy(&sda6.dst_addr, &flow->dst_addr.v6,
		    sizeof(sda6.dst_addr));
		flow->hdr.fieldspec_flags |= STORE_FIELD_SRCDST_ADDR6;
		break;
	default:
		syslog(LOG_WARNING, "%s: silly src/dst addr af", __func__);
		return (-1);
	}
	
	switch(flow->gateway_addr.af) {
	case AF_INET:
		memcpy(&gwa4.gateway_addr, &flow->gateway_addr.v4,
		    sizeof(gwa4.gateway_addr));
		flow->hdr.fieldspec_flags |= STORE_FIELD_GATEWAY_ADDR4;
		break;
	case AF_INET6:
		memcpy(&gwa6.gateway_addr, &flow->gateway_addr.v6,
		    sizeof(gwa6.gateway_addr));
		flow->hdr.fieldspec_flags |= STORE_FIELD_GATEWAY_ADDR6;
		break;
	default:
		syslog(LOG_WARNING, "%s: silly gateway addr af", __func__);
		return (-1);
	}

	fieldspec = flow->hdr.fieldspec_flags;

	flow->hdr.tag = htonl(flow->hdr.tag);
	flow->hdr.recv_secs = htonl(flow->hdr.recv_secs);
	flow->hdr.fieldspec_flags = htonl(flow->hdr.fieldspec_flags);

	/* Now write out the flow */
	if (atomicio(vwrite, fd, &flow->hdr, sizeof(flow->hdr)) !=
	    sizeof(flow->hdr))
		goto fail;

	syslog(LOG_DEBUG, "%s: write fields %x", __func__, fieldspec);

#define WRITEOUT(spec, what, len) do {  \
		syslog(LOG_DEBUG, "writing %s len %d", #spec, len); \
		if ((fieldspec & (spec)) && atomicio(vwrite, fd, (what), \
		    (len)) != len)  \
			goto fail; \
		} while (0)

	WRITEOUT(STORE_FIELD_AGENT_ADDR4, &aa4, sizeof(aa4));
	WRITEOUT(STORE_FIELD_AGENT_ADDR6, &aa6, sizeof(aa6));
	WRITEOUT(STORE_FIELD_SRCDST_ADDR4, &sda4, sizeof(sda4));
	WRITEOUT(STORE_FIELD_SRCDST_ADDR6, &sda6, sizeof(sda6));
	WRITEOUT(STORE_FIELD_GATEWAY_ADDR4, &gwa4, sizeof(gwa4));
	WRITEOUT(STORE_FIELD_GATEWAY_ADDR6, &gwa6, sizeof(gwa6));
	WRITEOUT(STORE_FIELD_SRCDST_PORT, &flow->ports, sizeof(flow->ports));
	WRITEOUT(STORE_FIELD_PACKETS_OCTETS, &flow->counters, sizeof(flow->counters));
	WRITEOUT(STORE_FIELD_IF_INDICES, &flow->ifndx, sizeof(flow->ifndx));
	WRITEOUT(STORE_FIELD_AGENT_INFO, &flow->ainfo, sizeof(flow->ainfo));
	WRITEOUT(STORE_FIELD_FLOW_TIMES, &flow->ftimes, sizeof(flow->ftimes));
	WRITEOUT(STORE_FIELD_AS_INFO, &flow->asinf, sizeof(flow->asinf));
	WRITEOUT(STORE_FIELD_FLOW_ENGINE_INFO, &flow->finf, sizeof(flow->finf));
#undef WRITEOUT

	return (0);

 fail:
	syslog(LOG_ERR, "%s: write failed: %s", __func__, strerror(errno));

	/* Try to rewind to starting position, so we don't corrupt flow store */	
	if (lseek(fd, startpos, SEEK_SET) == -1) {
		syslog(LOG_ERR, "%s: lseek: %s", __func__, strerror(errno));
		goto hardfail;
	}
	if (ftruncate(fd, startpos) == -1) {
		syslog(LOG_ERR, "%s: ftruncate: %s", __func__, strerror(errno));
		goto hardfail;
	}
	/* Partial flow record has been removed */
	return (-1);

 hardfail:
	syslog(LOG_CRIT, "%s: couldn't back error, exiting", __func__);
	exit(1);
}

static void 
process_flow(struct store_flow_complete *flow, struct flowd_config *conf,
    int log_fd)
{
	syslog(LOG_DEBUG, "%s: entering", __func__);

	/* Another sanity check */
	if (flow->src_addr.af != flow->dst_addr.af) {
		syslog(LOG_WARNING, "%s: flow src(%d)/dst(%d) AF mismatch",
		    __func__, flow->src_addr.af, flow->dst_addr.af);
		return;
	}

	if (filter_flow(flow, &conf->filter_list) == FF_ACTION_DISCARD)
		return; /* XXX log? count (against rule?) */

	if (store_flow(log_fd, flow) == -1)
		syslog(LOG_WARNING, "%s: store_flow failed", __func__);
	/* XXX reopen log file on one failure, exit on multiple */
}

static void 
process_netflow_v1(u_int8_t *pkt, size_t len, struct sockaddr *from,
    socklen_t fromlen, struct flowd_config *conf, int log_fd)
{
	struct NF1_HEADER *nf1_hdr = (struct NF1_HEADER *)pkt;
	struct NF1_FLOW *nf1_flow;
	struct store_flow_complete flow;
	size_t offset;
	u_int i, nflows;

	if (len < sizeof(*nf1_hdr)) {
		syslog(LOG_WARNING, "short netflow v.1 packet %d bytes from %s",
		    len, from_ntop(from));
		return;
	}
	nflows = ntohs(nf1_hdr->c.flows);
	if (nflows == 0 || nflows > NF1_MAXFLOWS) {
		syslog(LOG_WARNING, "Invalid number of flows (%u) in netflow "
		    "v.1 packet from %s", nflows, from_ntop(from));
		return;
	}
	if (len != NF1_PACKET_SIZE(nflows)) {
		syslog(LOG_WARNING, "Inconsistent Netflow v.1 packet from %s: "
		    "len %u expected %u", from_ntop(from), len,
		    NF1_PACKET_SIZE(nflows));
		return;
	}

	syslog(LOG_DEBUG, "Valid netflow v.1 packet %d flows", nflows);

	for (i = 0; i < nflows; i++) {
		offset = NF1_PACKET_SIZE(i);
		nf1_flow = (struct NF1_FLOW *)(pkt + offset);

		bzero(&flow, sizeof(flow));

		/* NB. These are converted to network byte order later */
		flow.hdr.fieldspec_flags = STORE_FIELD_ALL;
		flow.hdr.fieldspec_flags &= ~STORE_FIELD_AS_INFO;
		flow.hdr.fieldspec_flags &= ~STORE_FIELD_FLOW_ENGINE_INFO;
		/* flow.hdr.tag is set later */
		flow.hdr.recv_secs = time(NULL);

		flow.pft.tcp_flags = nf1_flow->tcp_flags;
		flow.pft.protocol = nf1_flow->protocol;
		flow.pft.tos = nf1_flow->tos;

		if (addr_ss_to_xaddr((struct sockaddr_storage *)from,
		    &flow.agent_addr) == -1) {
			syslog(LOG_WARNING, "Invalid agent address");
			break;
		}
		
		flow.src_addr.v4.s_addr = nf1_flow->src_ip;
		flow.src_addr.af = AF_INET;
		flow.dst_addr.v4.s_addr = nf1_flow->dest_ip;
		flow.dst_addr.af = AF_INET;
		flow.gateway_addr.v4.s_addr = nf1_flow->nexthop_ip;
		flow.gateway_addr.af = AF_INET;

		flow.ports.src_port = nf1_flow->src_port;
		flow.ports.dst_port = nf1_flow->dest_port;

		flow.counters.flow_packets = nf1_flow->flow_packets;
		flow.counters.flow_octets = nf1_flow->flow_octets;

		flow.ifndx.if_index_in = nf1_flow->if_index_in;
		flow.ifndx.if_index_out = nf1_flow->if_index_out;

		flow.ainfo.sys_uptime_ms = nf1_hdr->uptime_ms;
		flow.ainfo.time_sec = nf1_hdr->time_sec;
		flow.ainfo.time_nanosec = nf1_hdr->time_nanosec;

		flow.ftimes.flow_start = nf1_flow->flow_start;
		flow.ftimes.flow_finish = nf1_flow->flow_finish;

		process_flow(&flow, conf, log_fd);
	}
}

static void 
process_netflow_v5(u_int8_t *pkt, size_t len, struct sockaddr *from,
    socklen_t fromlen, struct flowd_config *conf, int log_fd)
{
	struct NF5_HEADER *nf5_hdr = (struct NF5_HEADER *)pkt;
	struct NF5_FLOW *nf5_flow;
	struct store_flow_complete flow;
	size_t offset;
	u_int i, nflows;

	if (len < sizeof(*nf5_hdr)) {
		syslog(LOG_WARNING, "short netflow v.5 packet %d bytes from %s",
		    len, from_ntop(from));
		return;
	}
	nflows = ntohs(nf5_hdr->c.flows);
	if (nflows == 0 || nflows > NF5_MAXFLOWS) {
		syslog(LOG_WARNING, "Invalid number of flows (%u) in netflow "
		    "v.5 packet from %s", nflows, from_ntop(from));
		return;
	}
	if (len != NF5_PACKET_SIZE(nflows)) {
		syslog(LOG_WARNING, "Inconsistent Netflow v.5 packet from %s: "
		    "len %u expected %u", from_ntop(from), len,
		    NF5_PACKET_SIZE(nflows));
		return;
	}

	syslog(LOG_DEBUG, "Valid netflow v.5 packet %d flows", nflows);

	for (i = 0; i < nflows; i++) {
		offset = NF5_PACKET_SIZE(i);
		nf5_flow = (struct NF5_FLOW *)(pkt + offset);

		bzero(&flow, sizeof(flow));

		/* NB. These are converted to network byte order later */
		flow.hdr.fieldspec_flags = STORE_FIELD_ALL;
		/* flow.hdr.tag is set later */
		flow.hdr.recv_secs = time(NULL);

		flow.pft.tcp_flags = nf5_flow->tcp_flags;
		flow.pft.protocol = nf5_flow->protocol;
		flow.pft.tos = nf5_flow->tos;

		if (addr_ss_to_xaddr((struct sockaddr_storage *)from,
		    &flow.agent_addr) == -1) {
			syslog(LOG_WARNING, "Invalid agent address");
			break;
		}
		
		flow.src_addr.v4.s_addr = nf5_flow->src_ip;
		flow.src_addr.af = AF_INET;
		flow.dst_addr.v4.s_addr = nf5_flow->dest_ip;
		flow.dst_addr.af = AF_INET;
		flow.gateway_addr.v4.s_addr = nf5_flow->nexthop_ip;
		flow.gateway_addr.af = AF_INET;

		flow.ports.src_port = nf5_flow->src_port;
		flow.ports.dst_port = nf5_flow->dest_port;

		flow.counters.flow_packets = nf5_flow->flow_packets;
		flow.counters.flow_octets = nf5_flow->flow_octets;

		flow.ifndx.if_index_in = nf5_flow->if_index_in;
		flow.ifndx.if_index_out = nf5_flow->if_index_out;

		flow.ainfo.sys_uptime_ms = nf5_hdr->uptime_ms;
		flow.ainfo.time_sec = nf5_hdr->time_sec;
		flow.ainfo.time_nanosec = nf5_hdr->time_nanosec;

		flow.ftimes.flow_start = nf5_flow->flow_start;
		flow.ftimes.flow_finish = nf5_flow->flow_finish;

		flow.asinf.src_as = nf5_flow->src_as;
		flow.asinf.dst_as = nf5_flow->dest_as;
		flow.asinf.src_mask = nf5_flow->src_mask;
		flow.asinf.dst_mask = nf5_flow->dst_mask;

		flow.finf.engine_type = nf5_hdr->engine_type;
		flow.finf.engine_id = nf5_hdr->engine_id;
		flow.finf.flow_sequence = nf5_hdr->flow_sequence;

		process_flow(&flow, conf, log_fd);
	}
}

static void
process_input(struct flowd_config *conf, int net_fd, int log_fd)
{
	struct sockaddr_storage from;
	socklen_t fromlen;
	u_int8_t buf[2048];
	ssize_t len;
	struct NF_HEADER_COMMON *hdr;

 retry:
	fromlen = sizeof(from);
	if ((len = recvfrom(net_fd, buf, sizeof(buf), 0, 
	    (struct sockaddr *)&from, &fromlen)) < 0) {
		if (errno == EINTR)
			goto retry;
		if (errno != EAGAIN)
			syslog(LOG_ERR, "recvfrom: %s", strerror(errno));
		/* XXX ratelimit errors */
		return;
	}
	syslog(LOG_DEBUG, "recv %d bytes from %s", len,
	    from_ntop((struct sockaddr *)&from));
	if ((size_t)len < sizeof(*hdr)) {
		syslog(LOG_WARNING, "short packet %d bytes from %s", len,
		    from_ntop((struct sockaddr *)&from));
		return;
	}
	hdr = (struct NF_HEADER_COMMON *)buf;
	switch (ntohs(hdr->version)) {
	case 1:
		process_netflow_v1(buf, len, (struct sockaddr *)&from, fromlen,
		    conf, log_fd);
		break;
	case 5:
		process_netflow_v5(buf, len, (struct sockaddr *)&from, fromlen,
		    conf, log_fd);
		break;
	default:
		syslog(LOG_INFO, "Unsupported netflow version %u from %s",
		    hdr->version, from_ntop((struct sockaddr *)&from));
		return;
	}
}

static void
flowd_mainloop(struct flowd_config *conf, int monitor_fd)
{
	int num_fds, i, log_fd;
	struct listen_addr *la;
	struct pollfd *pfd;

	num_fds = 1; /* fd to monitor */

	/* Count socks */
	TAILQ_FOREACH(la, &conf->listen_addrs, entry)
		num_fds++;

	if ((pfd = calloc(num_fds + 1, sizeof(*pfd))) == NULL) {
		syslog(LOG_ERR, "%s: calloc failed (num %d)",
		    __func__, num_fds + 1);
		exit(1);
	}

	pfd[0].fd = monitor_fd;
	pfd[0].events = POLLIN;

	i = 1;
	TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
		pfd[i].fd = la->fd;
		pfd[i].events = POLLIN;
		i++;
	}

	/* Main loop */
	log_fd = -1;
	for(;exit_flag == 0;) {
		if (reopen_flag && log_fd != -1) {
			close(log_fd);
			log_fd = -1;
		}
		if (log_fd == -1)
			log_fd = start_log(monitor_fd);
		
		syslog(LOG_DEBUG, "%s: poll(%d) entering", __func__, num_fds);
		i = poll(pfd, num_fds, INFTIM);
		syslog(LOG_DEBUG, "%s: poll(%d) = %d", __func__, num_fds, i);
		if (i <= 0) {
			if (i == 0 || errno == EINTR)
				continue;
			syslog(LOG_ERR, "%s: poll: %s", __func__,
			    strerror(errno));
			exit(1);
		}

		/* monitor exited */
		if (pfd[0].revents != 0) {
			syslog(LOG_DEBUG, "%s: monitor closed", __func__);
			break;
		}

		i = 1;
		TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
			if ((pfd[i].revents & POLLIN) != 0) {
				syslog(LOG_DEBUG, "%s: event on listener #%d "
				    "fd %d 0x%x", __func__, i - 1, pfd[i].fd, 
				    pfd[i].revents);
				process_input(conf, pfd[i].fd, log_fd);
			}
			i++;
		}
	}

	if (exit_flag != 0)
		syslog(LOG_NOTICE, "Exiting on signal %d", exit_flag);
}

static int
setup_listener(struct xaddr *addr, u_int16_t port)
{
	int fd, fl;
	struct sockaddr_storage ss;

	if (addr_xaddr_to_ss(addr, &ss, port) == -1)
		errx(1, "addr_xaddr_to_ss");
	if ((fd = socket(addr->af, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");

	fl = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &fl, sizeof(fl)) == -1)
		err(1, "setsockopt");

	if (bind(fd, (struct sockaddr *)&ss, 
	    SA_LEN((struct sockaddr *)&ss)) == -1)
		err(1, "bind");

	/* Set non-blocking */
	if ((fl = fcntl(fd, F_GETFL, 0)) == -1)
		err(1, "fcntl(%d, F_GETFL, 0)", fd);
	fl |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, fl) == -1)
		err(1, "fcntl(%d, F_SETFL, O_NONBLOCK)", fd);

	return (fd);
}

static void
listen_init(struct flowd_config *conf)
{
	struct listen_addr *la;

	TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
		if (la->fd != -1)
			close(la->fd);

		la->fd = setup_listener(&la->addr, la->port);
		if (la->fd == -1) {
			errx(1, "Listener setup of [%s]:%d failed", 
			    host_ntop(&la->addr), la->port);
		}
		if (conf->opts & FLOWD_OPT_VERBOSE) {
			fprintf(stderr, "Listener for [%s]:%d fd = %d\n",
			    host_ntop(&la->addr), la->port, la->fd);
		}
	}
}

int
main(int argc, char **argv)
{
	int ch;
	extern char *optarg;
	extern int optind;
	char *config_file = DEFAULT_CONFIG;
	struct flowd_config conf = {
		NULL, 0 ,
		TAILQ_HEAD_INITIALIZER(conf.listen_addrs),
		TAILQ_HEAD_INITIALIZER(conf.filter_list)
	};
	int monitor_fd;

	while ((ch = getopt(argc, argv, "dhD:f:")) != -1) {
		switch (ch) {
		case 'd':
			conf.opts |= FLOWD_OPT_DONT_FORK;
			conf.opts |= FLOWD_OPT_VERBOSE;
			break;
		case 'h':
			usage();
			return (0);
		case 'D':
			if (cmdline_symset(optarg) < 0)
				errx(1, "could not parse macro definition %s",
				    optarg);
			break;
		case 'f':
			config_file = optarg;
			break;
		default:
			fprintf(stderr, "Invalid commandline option.\n");
			usage();
			exit(1);
		}
	}

	if (parse_config(config_file, &conf))
		exit(1);

	if (TAILQ_EMPTY(&conf.listen_addrs))
		errx(1, "No listening addresses specified");
	if (conf.log_file == NULL)
		errx(1, "No log file specified");

	/* dump_config(&conf); */

	closefrom(STDERR_FILENO + 1);

	/* Start listening (do this early to report errors before privsep) */
	listen_init(&conf);

	/* Open log before privsep */
	openlog(PROGNAME, LOG_NDELAY|LOG_PID| 
	    (conf.opts & FLOWD_OPT_DONT_FORK ? LOG_PERROR : 0), LOG_DAEMON);

	/* Start the monitor - we continue as the unprivileged child */
	privsep_init(&conf, &monitor_fd);

	signal(SIGINT, sighand_exit);
	signal(SIGTERM, sighand_exit);
	signal(SIGHUP, sighand_reopen);

	flowd_mainloop(&conf, monitor_fd);

	return (0);
}
