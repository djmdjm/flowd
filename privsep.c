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
#include <sys/stat.h>
#include <sys/wait.h>

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <err.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <paths.h>

#include "flowd.h"
#include "privsep.h"
#include "atomicio.h"

RCSID("$Id$");

static sig_atomic_t child_exited = 0;
static pid_t child_pid = -1;
static int monitor_to_child_sock = -1;

#define C2M_MSG_OPEN_LOG	1	/* send: nothing   ret: fdpass */
#define C2M_MSG_RECONFIGURE	2	/* send: nothing   ret: conf+fdpass */

/* Utility functions */
static char *
privsep_read_string(int fd)
{
	size_t len;
	char buf[8192], *ret;

	if (atomicio(read, fd, &len, sizeof(len)) != sizeof(len)) {
		syslog(LOG_ERR, "%s: read len: %s", __func__, strerror(errno));
		return (NULL);
	}
	if (len == 0 || len >= sizeof(buf)) {
		syslog(LOG_ERR, "%s: silly len: %u", __func__, len);
		return (NULL);
	}
	if (atomicio(read, fd, buf, len) != len) {
		syslog(LOG_ERR, "%s: read str: %s", __func__, strerror(errno));
		return (NULL);
	}
	buf[len] = '\0';
	if ((ret = strdup(buf)) == NULL)
		syslog(LOG_ERR, "%s: strdup failed", __func__);
	return (ret);
}

static int
privsep_write_string(int fd, char *s)
{
	size_t len;

	if ((len = strlen(s)) == 0) {
		syslog(LOG_ERR, "%s: silly len: %u", __func__, len);
		return (-1);
	}
	if (atomicio(vwrite, fd, &len, sizeof(len)) != sizeof(len)) {
		syslog(LOG_ERR, "%s: write len: %s", __func__, strerror(errno));
		return (-1);
	}
	if (atomicio(vwrite, fd, s, len) != len) {
		syslog(LOG_ERR, "%s: write(str): %s", __func__, strerror(errno));
		return (-1);
	}

	return (0);
}

static int
write_pid_file(const char *path)
{
	FILE *pid_file;

	if ((pid_file = fopen(path, "w")) == NULL) {
		syslog(LOG_ERR, "fopen(%s): %s", path, strerror(errno));
		return (-1);
	}
	if (fprintf(pid_file, "%ld\n", (long)getpid()) == -1) {
		syslog(LOG_ERR, "fprintf(%s): %s", path, strerror(errno));
		return (-1);
	}
	fclose(pid_file);

	return (0);
}

int
read_config(const char *path, struct flowd_config *conf)
{
	syslog(LOG_DEBUG, "%s: entering", __func__);

	if (parse_config(path, conf))
		return (-1);

	if (TAILQ_EMPTY(&conf->listen_addrs)) {
		syslog(LOG_ERR, "No listening addresses specified");
		return (-1);
	}
	if (conf->log_file == NULL) {
		syslog(LOG_ERR, "No log file specified");
		return (-1);
	}
	if (conf->pid_file == NULL && 
	    (conf->pid_file = strdup(DEFAULT_PIDFILE)) == NULL) {
		syslog(LOG_ERR, "strdup pidfile");
		return (-1);
	}

	if (conf->opts & FLOWD_OPT_VERBOSE)
		dump_config(conf); 

	return (0);
}

int
open_listener(struct xaddr *addr, u_int16_t port)
{
	int fd, fl;
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);

	if (addr_xaddr_to_sa(addr, (struct sockaddr *)&ss, &slen, port) == -1) {
		syslog(LOG_ERR, "addr_xaddr_to_sa");
		return (-1);
	}

	if ((fd = socket(addr->af, SOCK_DGRAM, 0)) == -1) {
		syslog(LOG_ERR, "socket: %s", strerror(errno));
		return (-1);
	}

	/* Set non-blocking */
	if ((fl = fcntl(fd, F_GETFL, 0)) == -1) {
		syslog(LOG_ERR, "fcntl(%d, F_GETFL, 0): %s",
		    fd, strerror(errno));
		return (-1);
	}
	fl |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, fl) == -1) {
		syslog(LOG_ERR, "fcntl(%d, F_SETFL, O_NONBLOCK): %s",
		    fd, strerror(errno));
		return (-1);
	}

	/* Set v6-only for AF_INET6 sockets (no mapped address crap) */
	fl = 1;
	if (addr->af == AF_INET6 &&
	    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &fl, sizeof(fl)) == -1) {
		syslog(LOG_ERR, "setsockopt(IPV6_V6ONLY): %s", strerror(errno));
		return (-1);
	}

	if (bind(fd, (struct sockaddr *)&ss, slen) == -1) {
		syslog(LOG_ERR, "bind: %s", strerror(errno));
		return (-1);
	}

	syslog(LOG_DEBUG, "Listener for [%s]:%d fd = %d", addr_ntop_buf(addr),
	    port, fd);

	return (fd);
}

/* Client functions */
int
client_open_log(int monitor_fd)
{
	int fd = -1;
	u_int msg = C2M_MSG_OPEN_LOG;

	syslog(LOG_DEBUG, "%s: entering", __func__);

	if (atomicio(vwrite, monitor_fd, &msg, sizeof(msg)) != sizeof(msg)) {
		syslog(LOG_ERR, "%s: write: %s", __func__, strerror(errno));
		return (-1);
	}
	if ((fd = receive_fd(monitor_fd)) == -1)
		return (-1);

	return (fd);

}

int
client_reconfigure(int monitor_fd, struct flowd_config *conf)
{
	u_int msg = C2M_MSG_RECONFIGURE, n, i, ok;
	struct listen_addr *la;
	struct filter_rule *fr;

	syslog(LOG_DEBUG, "%s: entering", __func__);

	if (atomicio(vwrite, monitor_fd, &msg, sizeof(msg)) != sizeof(msg)) {
		syslog(LOG_ERR, "%s: write: %s", __func__, strerror(errno));
		return (-1);
	}

	free(conf->log_file);
	free(conf->pid_file);
	while ((la = TAILQ_FIRST(&conf->listen_addrs)) != NULL) {
		close(la->fd);
		TAILQ_REMOVE(&conf->listen_addrs, la, entry);
		free(la);
	}
	while ((fr = TAILQ_FIRST(&conf->filter_list)) != NULL) {
		TAILQ_REMOVE(&conf->filter_list, fr, entry);
		free(fr);
	}
	bzero(conf, sizeof(*conf));
	TAILQ_INIT(&conf->listen_addrs);
	TAILQ_INIT(&conf->filter_list);

	syslog(LOG_DEBUG, "%s: ready to receive config", __func__);

	if (atomicio(read, monitor_fd, &ok, sizeof(ok)) != sizeof(ok)) {
		syslog(LOG_ERR, "%s: read(ok): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	if (!ok) {
		syslog(LOG_ERR, "New config is invalid");
		return (-1);
	}

	if ((conf->log_file = privsep_read_string(monitor_fd)) == NULL) {
		syslog(LOG_ERR, "%s: Couldn't read conf.log_file", __func__);
		return (-1);
	}
	if ((conf->pid_file = privsep_read_string(monitor_fd)) == NULL) {
		syslog(LOG_ERR, "%s: Couldn't read conf.pid_file", __func__);
		return (-1);
	}
		
	if (atomicio(read, monitor_fd, &conf->store_mask,
	    sizeof(conf->store_mask)) != sizeof(conf->store_mask)) {
		syslog(LOG_ERR, "%s: read(conf.store_mask): %s", __func__,
		    strerror(errno));
		return (-1);
	}

	if (atomicio(read, monitor_fd, &conf->opts, sizeof(conf->opts)) !=
	    sizeof(conf->opts)) {
		syslog(LOG_ERR, "%s: read(conf.opts): %s", __func__,
		    strerror(errno));
		return (-1);
	}

	/* Read Listen Addrs */
	if (atomicio(read, monitor_fd, &n, sizeof(n)) != sizeof(n)) {
		syslog(LOG_ERR, "%s: read(num listen_addrs): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	if (n == 0 || n > 8192) {
		syslog(LOG_ERR, "%s: silly number of listen_addrs: %d",
		    __func__, n);
		return (-1);
	}
	syslog(LOG_DEBUG, "%s: reading %u listen_addrs", __func__, n);
	for (i = 0; i < n; i++) {
		if ((la = calloc(1, sizeof(*la))) == NULL) {
			syslog(LOG_ERR, "%s: calloc", __func__);
			return (-1);
		}
		if (atomicio(read, monitor_fd, la,
		    sizeof(*la)) != sizeof(*la)) {
			syslog(LOG_ERR, "%s: read(listen_addr): %s", __func__,
			    strerror(errno));
			return (-1);
		}
		if ((la->fd = receive_fd(monitor_fd)) == -1) {
			free(la);
			return (-1);
		}
		TAILQ_INSERT_TAIL(&conf->listen_addrs, la, entry);
	}

	/* Read Filter Rules */
	if (atomicio(read, monitor_fd, &n, sizeof(n)) != sizeof(n)) {
		syslog(LOG_ERR, "%s: read(num filter_rules): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	if (n == 0 || n > 1024*1024) {
		syslog(LOG_ERR, "%s: silly number of filter_rules: %d",
		    __func__, n);
		return (-1);
	}
	syslog(LOG_DEBUG, "%s: reading %u filter_rules", __func__, n);
	for (i = 0; i < n; i++) {
		if ((fr = calloc(1, sizeof(*fr))) == NULL) {
			syslog(LOG_ERR, "%s: calloc", __func__);
			return (-1);
		}
		if (atomicio(read, monitor_fd, fr,
		    sizeof(*fr)) != sizeof(*fr)) {
			syslog(LOG_ERR, "%s: read(filter_rule): %s", __func__,
			    strerror(errno));
			return (-1);
		}
		TAILQ_INSERT_TAIL(&conf->filter_list, fr, entry);
	}

	dump_config(conf); 

	return (0);
}

/* Client answer functions */
static int
answer_open_log(struct flowd_config *conf, int client_fd)
{
	int fd;

	syslog(LOG_DEBUG, "%s: entering", __func__);

	fd = open(conf->log_file, O_RDWR|O_APPEND|O_CREAT, 0600);
	if (fd == -1) {
		syslog(LOG_ERR, "%s: open: %s", __func__, strerror(errno));
		return (-1);
	}
	if (send_fd(client_fd, fd) == -1)
		return (-1);
	close(fd);
	return (0);
}

static int
answer_reconfigure(struct flowd_config *conf, int client_fd,
    const char *config_path)
{
	u_int n, ok;
	struct listen_addr *la;
	struct filter_rule *fr;
	struct flowd_config newconf;

	bzero(&newconf, sizeof(newconf));
	TAILQ_INIT(&newconf.listen_addrs);
	TAILQ_INIT(&newconf.filter_list);

	/* Transfer all options not set in config file */
	newconf.opts |= conf->opts & (FLOWD_OPT_VERBOSE);

	syslog(LOG_DEBUG, "%s: entering", __func__);

	if (read_config(config_path, &newconf) == -1) {
		syslog(LOG_ERR, "New config has errors");
		return (-1);
	}

	ok = 1;
	TAILQ_FOREACH(la, &newconf.listen_addrs, entry) {
		if ((la->fd = open_listener(&la->addr, la->port)) == -1) {
			syslog(LOG_ERR, "Listener setup of [%s]:%d failed", 
			    addr_ntop_buf(&la->addr), la->port);
			ok = 0;
			break;
		}
	}
	syslog(LOG_DEBUG, "%s: post listener open, ok = %d", __func__, ok);
	if (atomicio(vwrite, client_fd, &ok, sizeof(ok)) != sizeof(ok)) {
		syslog(LOG_ERR, "%s: write(ok): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	if (ok == 0)
		return (-1);

	if (privsep_write_string(client_fd, newconf.log_file) == -1) {
		syslog(LOG_ERR, "%s: Couldn't write newconf.log_file",
		    __func__);
		return (-1);
	}
	if (privsep_write_string(client_fd, newconf.pid_file) == -1) {
		syslog(LOG_ERR, "%s: Couldn't read newconf.pid_file",
		    __func__);
		return (-1);
	}
		
	if (atomicio(vwrite, client_fd, &newconf.store_mask,
	    sizeof(newconf.store_mask)) != sizeof(newconf.store_mask)) {
		syslog(LOG_ERR, "%s: write(newconf.store_mask): %s", __func__,
		    strerror(errno));
		return (-1);
	}

	if (atomicio(vwrite, client_fd, &newconf.opts,
	    sizeof(newconf.opts)) != sizeof(newconf.opts)) {
		syslog(LOG_ERR, "%s: write(newconf.opts): %s", __func__,
		    strerror(errno));
		return (-1);
	}

	/* Write Listen Addrs */
	n = 0;
	TAILQ_FOREACH(la, &newconf.listen_addrs, entry)
		n++;
	syslog(LOG_DEBUG, "%s: writing %u listen_addrs", __func__, n);
	if (atomicio(vwrite, client_fd, &n, sizeof(n)) != sizeof(n)) {
		syslog(LOG_ERR, "%s: write(num listen_addrs): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	TAILQ_FOREACH(la, &newconf.listen_addrs, entry) {
		if (atomicio(vwrite, client_fd, la,
		    sizeof(*la)) != sizeof(*la)) {
			syslog(LOG_ERR, "%s: write(listen_addr): %s", __func__,
			    strerror(errno));
			return (-1);
		}
		if (send_fd(client_fd, la->fd) == -1)
			return (-1);
		close(la->fd);
		la->fd = -1;
	}

	/* Write Filter Rules */
	n = 0;
	TAILQ_FOREACH(fr, &newconf.filter_list, entry)
		n++;
	syslog(LOG_DEBUG, "%s: writing %u filter_rules", __func__, n);
	if (atomicio(vwrite, client_fd, &n, sizeof(n)) != sizeof(n)) {
		syslog(LOG_ERR, "%s: write(num filter_rules): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	TAILQ_FOREACH(fr, &newconf.filter_list, entry) {
		if (atomicio(vwrite, client_fd, fr,
		    sizeof(*fr)) != sizeof(*fr)) {
			syslog(LOG_ERR, "%s: write(filter_rule): %s", __func__,
			    strerror(errno));
			return (-1);
		}
	}

	/* Cleanup old config and move new one into place */

	unlink(conf->pid_file);

	free(conf->log_file);
	free(conf->pid_file);
	while ((la = TAILQ_FIRST(&conf->listen_addrs)) != NULL) {
		TAILQ_REMOVE(&conf->listen_addrs, la, entry);
		free(la);
	}
	while ((fr = TAILQ_FIRST(&conf->filter_list)) != NULL) {
		TAILQ_REMOVE(&conf->filter_list, fr, entry);
		free(fr);
	}

	memcpy(conf, &newconf, sizeof(*conf));
	TAILQ_INIT(&conf->listen_addrs);
	TAILQ_INIT(&conf->filter_list);

	TAILQ_FOREACH(la, &newconf.listen_addrs, entry)
		TAILQ_INSERT_TAIL(&conf->listen_addrs, la, entry);
	TAILQ_FOREACH(fr, &newconf.filter_list, entry)
		TAILQ_INSERT_TAIL(&conf->filter_list, fr, entry);

	if (write_pid_file(conf->pid_file) == -1)
		return (-1);

	syslog(LOG_DEBUG, "%s: done", __func__);

	return (0);
}

/* Signal handlers */
static void
sighand_exit(int signo)
{
	if (monitor_to_child_sock != -1)
		shutdown(monitor_to_child_sock, SHUT_RDWR);
	if (!child_exited && child_pid > 1)
		kill(child_pid, signo);
}

static void
sighand_child(int signo)
{
	child_exited = 1;
}

static void
sighand_reopen(int signo)
{
	if (!child_exited && child_pid > 1)
		if (kill(child_pid, signo) != 0)
			_exit(1);
}

static void
privsep_master(struct flowd_config *conf, const char *config_path)
{
	int status, r;
	u_int what;

	for (;!child_exited;) {
		r = atomicio(read, monitor_to_child_sock, &what, sizeof(what));
		if (r == 0) {
			syslog(LOG_DEBUG, "%s: child exited", __func__);
			break;
		}
		if (r != sizeof(what)) {
			syslog(LOG_ERR, "%s: read: %s", __func__,
			    strerror(errno));
			unlink(conf->pid_file);
			exit(1);
		}

		switch (what) {
		case C2M_MSG_OPEN_LOG:
			if (answer_open_log(conf, monitor_to_child_sock)) {
				unlink(conf->pid_file);
				exit(1);
			}
			break;
		case C2M_MSG_RECONFIGURE:
			if (answer_reconfigure(conf, monitor_to_child_sock, 
			    config_path)) {
				unlink(conf->pid_file);
				exit(1);
			}
			break;
		default:
			syslog(LOG_ERR, "Unknown message %d", what);
			break;
		}
	}

	r = 0;
	if (child_exited) {
		if (waitpid(child_pid, &status, 0) == -1) {
			syslog(LOG_ERR, "%s: waitpid: %s", __func__,
			    strerror(errno));
			r = 1;
		} else if (!WIFEXITED(status)) { 
			syslog(LOG_ERR, "child exited abnormally");
			r = 1;
		} else if (WEXITSTATUS(status) != 0) {
			syslog(LOG_ERR, "child exited with status %d",
			    WEXITSTATUS(status));
			r = 1;
		}
	}

	unlink(conf->pid_file);
	exit(r);
}

void
privsep_init(struct flowd_config *conf, int *child_to_monitor_sock, 
    const char *config_path)
{
	int s[2], devnull;
	struct passwd *pw;
	struct listen_addr *la;

	syslog(LOG_DEBUG, "%s: entering", __func__);

	if (socketpair(AF_LOCAL, SOCK_STREAM, PF_UNSPEC, s) == -1)
		err(1, "socketpair");

	monitor_to_child_sock = s[0];
	*child_to_monitor_sock = s[1];

	if ((pw = getpwnam(PRIVSEP_USER)) == NULL) {
		errx(1, "Privilege separation user %s doesn't exist",
		    PRIVSEP_USER);
	}

	if ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		err(1, "open(/dev/null)");

	if ((conf->opts & FLOWD_OPT_DONT_FORK) == 0)
		daemon(0, 1);

	if (dup2(devnull, STDIN_FILENO) == -1 || 
	    dup2(devnull, STDOUT_FILENO) == -1)
		err(1, "dup2");

	switch (child_pid = fork()) {
	case -1:
		err(1, "fork");
	case 0: /* Child */
		closelog();
		openlog(PROGNAME, LOG_NDELAY|LOG_PID| 
		    (conf->opts & FLOWD_OPT_DONT_FORK ? LOG_PERROR : 0),
		    LOG_DAEMON);
		close(monitor_to_child_sock);
		if (setsid() == -1)
			err(1, "setsid");
		if (chdir(pw->pw_dir) == -1)
			err(1, "chdir(%s)", pw->pw_dir);
		if (chroot(pw->pw_dir) == -1)
			err(1, "chroot(%s)", pw->pw_dir);
		if (chdir("/") == -1) 
			err(1, "chdir(/)");
		if (setgroups(1, &pw->pw_gid) == -1)
			err(1, "setgroups");
		if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
			err(1, "setresgid");
		if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
			err(1, "setresuid");

		if ((conf->opts & FLOWD_OPT_DONT_FORK) == 0 && 
		    dup2(devnull, STDERR_FILENO) == -1) {
			syslog(LOG_ERR, "dup2: %s", strerror(errno));
			exit(1);
		}
		close(devnull);
		setproctitle("net");
		return;
	default: /* Parent */
		closelog();
		openlog(PROGNAME, LOG_NDELAY|LOG_PID| 
		    (conf->opts & FLOWD_OPT_DONT_FORK ? LOG_PERROR : 0),
		    LOG_DAEMON);
		if ((conf->opts & FLOWD_OPT_DONT_FORK) == 0 && 
		    dup2(devnull, STDERR_FILENO) == -1) {
			syslog(LOG_ERR, "dup2: %s", strerror(errno));
			exit(1);
		}
		close(devnull);
		close(*child_to_monitor_sock);
		TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
			if (la->fd != -1)
				close(la->fd);
			la->fd = -1;
		}
		setproctitle("monitor");
		if (write_pid_file(conf->pid_file) == -1)
			exit(1);

		signal(SIGINT, sighand_exit);
		signal(SIGTERM, sighand_exit);
		signal(SIGHUP, sighand_reopen);
		signal(SIGCHLD, sighand_child);

		privsep_master(conf, config_path);
	}
	/* NOTREACHED */
}

