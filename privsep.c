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
#include <syslog.h>
#include <paths.h>

#include "flowd.h"
#include "privsep.h"
#include "atomicio.h"

static sig_atomic_t child_exited = 0;
static pid_t child_pid = -1;
static int monitor_to_child_sock = -1;

#define C2M_MSG_OPEN_LOG	1	/* send: nothing	ret: fdpass */

/* Client functions */
int
client_open_log(int monitor_fd)
{
	int fd = -1, msg = C2M_MSG_OPEN_LOG;

	syslog(LOG_DEBUG, "%s: entering", __func__);

	if (atomicio(vwrite, monitor_fd, &msg, sizeof(msg)) != sizeof(msg)) {
		syslog(LOG_ERR, "%s: write: %s", __func__, strerror(errno));
		return (-1);
	}
	if ((fd = receive_fd(monitor_fd)) == -1)
		return (-1);

	return (fd);

}

/* Client answer functions */
static int
answer_open_log(struct flowd_config *conf, int client_fd)
{
	int fd;

	syslog(LOG_DEBUG, "%s: entering", __func__);

	fd = open(conf->log_file, O_WRONLY|O_APPEND|O_CREAT, 0600);
	if (fd == -1) {
		syslog(LOG_ERR, "%s: open: %s", __func__, strerror(errno));
		return (-1);
	}
	if (send_fd(client_fd, fd) == -1)
		return (-1);
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
privsep_master(struct flowd_config *conf)
{
	int status, what, r;

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
privsep_init(struct flowd_config *conf, int *child_to_monitor_sock)
{
	int s[2], devnull;
	struct passwd *pw;
	struct listen_addr *la;
	FILE *pid_file;

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
		if ((pid_file = fopen(conf->pid_file, "w")) == NULL) {
			syslog(LOG_ERR, "fopen(%s): %s", conf->pid_file,
			    strerror(errno));
			exit(1);
		}
		if (fprintf(pid_file, "%ld\n", (long)getpid()) == -1) {
			syslog(LOG_ERR, "fprintf(pid_file): %s", 
			    strerror(errno));
			exit(1);
		}
		fclose(pid_file);

		signal(SIGINT, sighand_exit);
		signal(SIGTERM, sighand_exit);
		signal(SIGHUP, sighand_reopen);
		signal(SIGCHLD, sighand_child);

		privsep_master(conf);
	}
	/* NOTREACHED */
}

