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
from_ntop(struct sockaddr_storage *s)
{
	static char hbuf[64], sbuf[32], ret[128];

	if (addr_ss_ntop(s, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf)) == -1)
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
		if (fr->action.action_what == FF_ACTION_DISCARD)
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

static void
process_input(struct flowd_config *conf, int fd)
{
	struct sockaddr_storage from;
	socklen_t fromlen;
	u_int8_t buf[2048];
	ssize_t len;

 retry:
	fromlen = sizeof(from);
	if ((len = recvfrom(fd, buf, sizeof(buf), 0, 
	    (struct sockaddr *)&from, &fromlen)) == -1) {
		if (errno == EINTR)
			goto retry;
		if (errno != EAGAIN)
			syslog(LOG_ERR, "recvfrom: %s", strerror(errno));
		/* XXX ratelimit errors */
		return;
	}
	syslog(LOG_INFO, "recv %d bytes from %s", len, from_ntop(&from));
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
		if (log_fd == -1 && 
		    (log_fd = client_open_log(monitor_fd)) == -1) {
			syslog(LOG_CRIT, "Logfile open failed, exiting");
			exit(1);
		}
		
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
				process_input(conf, pfd[i].fd);
			}
			i++;
		}
	}

	if (exit_flag != 0)
		syslog(LOG_NOTICE, "Exiting on signal %d", exit_flag);
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
