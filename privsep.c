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
#include <netdb.h>

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
static void
log_reinit(u_int32_t logopts)
{
	closelog();
	openlog(PROGNAME, LOG_NDELAY|LOG_PID|
	    (logopts & FLOWD_OPT_DONT_FORK ? LOG_PERROR : 0), LOG_DAEMON);
	if (logopts & FLOWD_OPT_VERBOSE)
		setlogmask(LOG_UPTO(LOG_DEBUG));
	else
		setlogmask(LOG_UPTO(LOG_INFO));
}

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

#ifdef IPV6_V6ONLY
	/* Set v6-only for AF_INET6 sockets (no mapped address crap) */
	fl = 1;
	if (addr->af == AF_INET6 &&
	    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &fl, sizeof(fl)) == -1) {
		syslog(LOG_ERR, "setsockopt(IPV6_V6ONLY): %s", strerror(errno));
		return (-1);
	}
#endif

	if (bind(fd, (struct sockaddr *)&ss, slen) == -1) {
		syslog(LOG_ERR, "bind: %s", strerror(errno));
		return (-1);
	}

	syslog(LOG_DEBUG, "Listener for [%s]:%d fd = %d", addr_ntop_buf(addr),
	    port, fd);

	return (fd);
}

static void
replace_conf(struct flowd_config *conf, struct flowd_config *newconf)
{
	struct listen_addr *la;
	struct filter_rule *fr;

	free(conf->log_file);
	free(conf->pid_file);
	while ((la = TAILQ_FIRST(&conf->listen_addrs)) != NULL) {
		if (la->fd != -1)
			close(la->fd);
		TAILQ_REMOVE(&conf->listen_addrs, la, entry);
		free(la);
	}
	while ((fr = TAILQ_FIRST(&conf->filter_list)) != NULL) {
		TAILQ_REMOVE(&conf->filter_list, fr, entry);
		free(fr);
	}

	memcpy(conf, newconf, sizeof(*conf));
	TAILQ_INIT(&conf->listen_addrs);
	TAILQ_INIT(&conf->filter_list);

	while ((la = TAILQ_LAST(&newconf->listen_addrs, listen_addrs)) != NULL) {
		TAILQ_REMOVE(&newconf->listen_addrs, la, entry);
		TAILQ_INSERT_HEAD(&conf->listen_addrs, la, entry);
	}

	while ((fr = TAILQ_LAST(&newconf->filter_list, filter_list)) != NULL) {
		TAILQ_REMOVE(&newconf->filter_list, fr, entry);
		TAILQ_INSERT_HEAD(&conf->filter_list, fr, entry);
	}

	bzero(newconf, sizeof(*newconf));
}

static int
recv_config(int fd, struct flowd_config *conf)
{
	u_int n, i;
	struct listen_addr *la;
	struct filter_rule *fr;
	struct flowd_config newconf;

	syslog(LOG_DEBUG, "%s: entering fd = %d", __func__, fd);

	bzero(&newconf, sizeof(newconf));
	TAILQ_INIT(&newconf.listen_addrs);
	TAILQ_INIT(&newconf.filter_list);

	syslog(LOG_DEBUG, "%s: ready to receive config", __func__);

	if ((newconf.log_file = privsep_read_string(fd)) == NULL) {
		syslog(LOG_ERR, "%s: Couldn't read conf.log_file", __func__);
		return (-1);
	}
	if ((newconf.pid_file = privsep_read_string(fd)) == NULL) {
		syslog(LOG_ERR, "%s: Couldn't read conf.pid_file", __func__);
		return (-1);
	}
		
	if (atomicio(read, fd, &newconf.store_mask,
	    sizeof(newconf.store_mask)) != sizeof(newconf.store_mask)) {
		syslog(LOG_ERR, "%s: read(conf.store_mask): %s", __func__,
		    strerror(errno));
		return (-1);
	}

	if (atomicio(read, fd, &newconf.opts, sizeof(newconf.opts)) !=
	    sizeof(newconf.opts)) {
		syslog(LOG_ERR, "%s: read(conf.opts): %s", __func__,
		    strerror(errno));
		return (-1);
	}

	/* Read Listen Addrs */
	if (atomicio(read, fd, &n, sizeof(n)) != sizeof(n)) {
		syslog(LOG_ERR, "%s: read(num listen_addrs): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	if (n == 0 || n > 8192) {
		syslog(LOG_ERR, "%s: silly number of listen_addrs: %d",
		    __func__, n);
		return (-1);
	}
	for (i = 0; i < n; i++) {
		if ((la = calloc(1, sizeof(*la))) == NULL) {
			syslog(LOG_ERR, "%s: calloc", __func__);
			return (-1);
		}
		if (atomicio(read, fd, la,
		    sizeof(*la)) != sizeof(*la)) {
			syslog(LOG_ERR, "%s: read(listen_addr): %s", __func__,
			    strerror(errno));
			return (-1);
		}
		if (la->fd != -1 && (la->fd = receive_fd(fd)) == -1)
			return (-1);
		TAILQ_INSERT_TAIL(&newconf.listen_addrs, la, entry);
	}

	/* Read Filter Rules */
	if (atomicio(read, fd, &n, sizeof(n)) != sizeof(n)) {
		syslog(LOG_ERR, "%s: read(num filter_rules): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	if (n == 0 || n > 1024*1024) {
		syslog(LOG_ERR, "%s: silly number of filter_rules: %d",
		    __func__, n);
		return (-1);
	}
	for (i = 0; i < n; i++) {
		if ((fr = calloc(1, sizeof(*fr))) == NULL) {
			syslog(LOG_ERR, "%s: calloc", __func__);
			return (-1);
		}
		if (atomicio(read, fd, fr,
		    sizeof(*fr)) != sizeof(*fr)) {
			syslog(LOG_ERR, "%s: read(filter_rule): %s", __func__,
			    strerror(errno));
			return (-1);
		}
		TAILQ_INSERT_TAIL(&newconf.filter_list, fr, entry);
	}

	replace_conf(conf, &newconf);

	return (0);
}

static int
send_config(int fd, struct flowd_config *conf)
{
	u_int n;
	struct listen_addr *la;
	struct filter_rule *fr;

	syslog(LOG_DEBUG, "%s: entering fd = %d", __func__, fd);

	if (privsep_write_string(fd, conf->log_file) == -1) {
		syslog(LOG_ERR, "%s: Couldn't write conf.log_file",
		    __func__);
		return (-1);
	}
	if (privsep_write_string(fd, conf->pid_file) == -1) {
		syslog(LOG_ERR, "%s: Couldn't write conf.pid_file",
		    __func__);
		return (-1);
	}
		
	if (atomicio(vwrite, fd, &conf->store_mask,
	    sizeof(conf->store_mask)) != sizeof(conf->store_mask)) {
		syslog(LOG_ERR, "%s: write(conf.store_mask): %s", __func__,
		    strerror(errno));
		return (-1);
	}

	if (atomicio(vwrite, fd, &conf->opts,
	    sizeof(conf->opts)) != sizeof(conf->opts)) {
		syslog(LOG_ERR, "%s: write(conf.opts): %s", __func__,
		    strerror(errno));
		return (-1);
	}

	/* Write Listen Addrs */
	n = 0;
	TAILQ_FOREACH(la, &conf->listen_addrs, entry)
		n++;
	if (atomicio(vwrite, fd, &n, sizeof(n)) != sizeof(n)) {
		syslog(LOG_ERR, "%s: write(num listen_addrs): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
		if (atomicio(vwrite, fd, la,
		    sizeof(*la)) != sizeof(*la)) {
			syslog(LOG_ERR, "%s: write(listen_addr): %s", __func__,
			    strerror(errno));
			return (-1);
		}
		if (la->fd != -1 && send_fd(fd, la->fd) == -1)
			return (-1);
	}

	/* Write Filter Rules */
	n = 0;
	TAILQ_FOREACH(fr, &conf->filter_list, entry)
		n++;
	if (atomicio(vwrite, fd, &n, sizeof(n)) != sizeof(n)) {
		syslog(LOG_ERR, "%s: write(num filter_rules): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	TAILQ_FOREACH(fr, &conf->filter_list, entry) {
		if (atomicio(vwrite, fd, fr,
		    sizeof(*fr)) != sizeof(*fr)) {
			syslog(LOG_ERR, "%s: write(filter_rule): %s", __func__,
			    strerror(errno));
			return (-1);
		}
	}

	syslog(LOG_DEBUG, "%s: done", __func__);

	return (0);
}

static int
drop_privs(struct passwd *pw, int do_chroot)
{
	if (setsid() == -1) {
		syslog(LOG_ERR, "setsid: %s", strerror(errno));
		return (-1);
	}
	if (do_chroot) {
		if (chdir(pw->pw_dir) == -1) {
			syslog(LOG_ERR, "chdir(%s): %s", pw->pw_dir,
			    strerror(errno));
			return (-1);
		}
		if (chroot(pw->pw_dir) == -1) {
			syslog(LOG_ERR, "chroot(%s): %s", pw->pw_dir,
			    strerror(errno));
			return (-1);
		}
	}
	if (chdir("/") == -1) {
		syslog(LOG_ERR, "chdir(/): %s", strerror(errno));
		return (-1);
	}
	if (setgroups(1, &pw->pw_gid) == -1) {
		syslog(LOG_ERR, "setgroups: %s", strerror(errno));
		return (-1);
	}
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1) {
		syslog(LOG_ERR, "setresgid: %s", strerror(errno));
		return (-1);
	}
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1) {
		syslog(LOG_ERR, "setresuid: %s", strerror(errno));
		return (-1);
	}
	return (0);
}

static int
child_get_config(const char *path, struct flowd_config *conf)
{
	int s[2], ok, status;
	pid_t ccpid;
	void (*oldsigchld)(int);
	FILE *cfg;
	struct passwd *pw;
	struct flowd_config newconf = {
		NULL, NULL, 0, 0, 
		TAILQ_HEAD_INITIALIZER(newconf.listen_addrs),
		TAILQ_HEAD_INITIALIZER(newconf.filter_list)
	};

	syslog(LOG_DEBUG, "%s: entering", __func__);

	if ((pw = getpwnam(PRIVSEP_USER)) == NULL) {
		syslog(LOG_ERR, "Privilege separation user %s doesn't exist",
		    PRIVSEP_USER);
	}
	endpwent();

	if (socketpair(AF_LOCAL, SOCK_STREAM, PF_UNSPEC, s) == -1) {
		syslog(LOG_ERR, "%s: socketpair: %s", __func__,
		    strerror(errno));
		return (-1);
	}

	oldsigchld = signal(SIGCHLD, SIG_DFL);
	switch (ccpid = fork()) {
	case -1:
		syslog(LOG_ERR, "%s: fork: %s", __func__,
		    strerror(errno));
		return (-1);
	case 0: /* Child */
		close(s[0]);
		setproctitle("config");

		if ((cfg = fopen(path, "r")) == NULL) {
			syslog(LOG_ERR, "fopen(%s): %s", path, strerror(errno));
			exit(1);
		}
		if (drop_privs(pw, 0) == -1)
			exit(1);
		ok = (parse_config(path, cfg, &newconf) == 0);
		fclose(cfg);
		if (atomicio(vwrite, s[1], &ok, sizeof(ok)) != sizeof(ok)) {
			syslog(LOG_ERR, "%s: write(ok): %s", __func__,
			    strerror(errno));
			exit(1);
		}
		if (!ok)
			exit(1);
		if (send_config(s[1], &newconf) == -1)
			exit(1);
		syslog(LOG_DEBUG, "%s: child config done", __func__);

		exit(0);
	default: /* Parent */
		close(s[1]);
		break;
	}

	/* Parent */
	if (atomicio(read, s[0], &ok, sizeof(ok)) != sizeof(ok)) {
		syslog(LOG_ERR, "%s: read(ok): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	if (!ok)
		return (-1);
	if (recv_config(s[0], conf) == -1)
		return (-1);
	close(s[0]);

	if (waitpid(ccpid, &status, 0) == -1) {
		syslog(LOG_ERR, "%s: waitpid: %s", __func__,
		    strerror(errno));
		return (-1);
	}	
	if (!WIFEXITED(status)) { 
		syslog(LOG_ERR, "child exited abnormally");
		return (-1);
	}
	if (WEXITSTATUS(status) != 0) {
		syslog(LOG_ERR, "child exited with status %d",
		    WEXITSTATUS(status));
		return (-1);
	}

	signal(SIGCHLD, oldsigchld);

	return (0);
}

int
read_config(const char *path, struct flowd_config *conf)
{
	u_int32_t opts;

	syslog(LOG_DEBUG, "%s: entering", __func__);

	/* Preserve options not set in config file */
	opts = (conf->opts & (FLOWD_OPT_DONT_FORK|FLOWD_OPT_VERBOSE));

	if (child_get_config(path, conf))
		return (-1);

	conf->opts |= opts;

	return (0);
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
	u_int msg = C2M_MSG_RECONFIGURE, ok;
	struct listen_addr *la;

	syslog(LOG_DEBUG, "%s: entering", __func__);

	TAILQ_FOREACH(la, &conf->listen_addrs, entry) {
		if (la->fd != -1)
			close(la->fd);
		la->fd = -1;
	}

	if (atomicio(vwrite, monitor_fd, &msg, sizeof(msg)) != sizeof(msg)) {
		syslog(LOG_ERR, "%s: write: %s", __func__, strerror(errno));
		return (-1);
	}

	if (atomicio(read, monitor_fd, &ok, sizeof(ok)) != sizeof(ok)) {
		syslog(LOG_ERR, "%s: read(ok): %s", __func__,
		    strerror(errno));
		return (-1);
	}
	if (!ok) {
		syslog(LOG_ERR, "New config is invalid");
		return (-1);
	}

	if (recv_config(monitor_fd, conf) == -1)
		return (-1);

	syslog(LOG_DEBUG, "%s: done", __func__);

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
	u_int ok;
	struct flowd_config newconf;
	struct listen_addr *la;

	bzero(&newconf, sizeof(newconf));
	TAILQ_INIT(&newconf.listen_addrs);
	TAILQ_INIT(&newconf.filter_list);

	syslog(LOG_DEBUG, "%s: entering", __func__);

	ok = 1;
	if (read_config(config_path, &newconf) == -1) {
		syslog(LOG_ERR, "New config has errors");
		ok = 0;
	}
	newconf.opts |= (conf->opts & (FLOWD_OPT_DONT_FORK|FLOWD_OPT_VERBOSE));

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

	if (send_config(client_fd, &newconf) == -1)
		return (-1);

	TAILQ_FOREACH(la, &newconf.listen_addrs, entry) {
		close(la->fd);
		la->fd = -1;
	}

	/* Cleanup old config and move new one into place */
	unlink(conf->pid_file);

	replace_conf(conf, &newconf);

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
sighand_relay(int signo)
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
	endpwent();

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
		log_reinit(conf->opts);
		close(monitor_to_child_sock);

		if (drop_privs(pw, 1) == -1)
			exit(1);

		if ((conf->opts & FLOWD_OPT_DONT_FORK) == 0 && 
		    dup2(devnull, STDERR_FILENO) == -1) {
			syslog(LOG_ERR, "dup2: %s", strerror(errno));
			exit(1);
		}
		close(devnull);
		setproctitle("net");
		return;
	default: /* Parent */
		log_reinit(conf->opts);
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
		signal(SIGCHLD, sighand_child);
		signal(SIGHUP, sighand_relay);
#ifdef SIGINFO
		signal(SIGINFO, sighand_relay);
#endif
		signal(SIGUSR1, sighand_relay);
		signal(SIGUSR2, sighand_relay);

		privsep_master(conf, config_path);
	}
	/* NOTREACHED */
}

