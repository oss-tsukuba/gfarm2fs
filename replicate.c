/*
 * $Id$
 */

#include "config.h"

#ifdef HAVE_PRIVATE_SRCS
/* replace replicate.c with replicate_private.c */
#include "replicate_private.c"
#else /* ! HAVE_PRIVATE_SRCS */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <libgen.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>

/*
 * fuse.h requres that _FILE_OFFSET_BITS is defined in any case, but
 * AC_SYS_LARGEFILE does not define it on a 64bit platform like x86_64
 * since it is not necessary.  To avoid this problem we define it here.
 */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#define FUSE_USE_VERSION 25
#include <fuse.h>

#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <gfarm/gfarm.h>
#include <gfarm2fs.h>
#include "gfarm2fs_msg_enums.h"

#ifdef HAVE_GFS_REPLICATE_FILE_TO
#define gfs_replicate_to(file, dsthost, dstport) \
	gfs_replicate_file_to(file, dsthost, 0)
#endif

static int replicate_ncopy;
static int replicate_max_concurrency;
volatile sig_atomic_t replicate_concurrency = 0;
static int replicate_enabled;

#define XATTR_NCOPY	"gfarm.ncopy"

/*
 * #define UNSAFE_DEBUG
 *
 * Since gflog_info() is not async-signal-safe,
 * UNSAFE_DEBUG shouldn't be defined.
 */

static void
sigchld_handler(int sig)
{
	int pid, status;
#ifdef UNSAFE_DEBUG
	int no;
	char *msg;
#endif

	for (;;) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == -1 || pid == 0)
			break;
		--replicate_concurrency;

#ifdef UNSAFE_DEBUG
		if (WIFEXITED(status)) {
			msg = "exit";
			no = WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			msg = "killed by signal";
			no = WTERMSIG(status);
		} else {
			msg = "unknown status";
			no = status;
		}
		gflog_info(GFARM_MSG_2000041, "replicate [%d]: %s %d",
		    pid, msg, no);
#endif
	}
}

static int available_nhosts;
static struct gfarm_host_sched_info *available_hosts;
static struct timeval available_host_cache_time;
static const char *schedule_path = GFARM_PATH_ROOT;

static int
is_expired(int expiration)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	return (now.tv_sec > available_host_cache_time.tv_sec + expiration);
}

static gfarm_error_t
update_schedule_info(const char *domain)
{
	gfarm_error_t e;

	if (available_hosts != NULL)
		gfarm_host_sched_info_free(available_nhosts, available_hosts);
	available_hosts = NULL;
	e = gfarm_schedule_hosts_domain_all(schedule_path, domain,
	    &available_nhosts, &available_hosts);
	gettimeofday(&available_host_cache_time, NULL);
	return (e);
}

void
gfarm2fs_replicate_init(struct gfarm2fs_param *param)
{
	struct sigaction sa;
	char *domain = "";
	gfarm_error_t e;

	if (param->ncopy < 2 || param->copy_limit < 0)
		return;

	e = update_schedule_info(domain);
	if (e != GFARM_ERR_NO_ERROR)
		return;

	replicate_ncopy = param->ncopy;
	replicate_max_concurrency = param->copy_limit;

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);

	replicate_enabled = 1;
}

void
gfarm2fs_replicate_final(void)
{
	if (available_hosts != NULL)
		gfarm_host_sched_info_free(available_nhosts, available_hosts);
}

static int
get_required_ncopy(const char *path)
{
	int ncopy = replicate_ncopy;
#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
	char *p, *ep, s_ncopy[GFARM_INT32STRLEN];
	size_t size_ncopy;
	gfarm_error_t e;
	int nc;

	p = strdup(path);
	if (p == NULL)
		return (ncopy);

	for (;;) {
		size_ncopy = sizeof(s_ncopy);
		e = gfs_getxattr(p, XATTR_NCOPY, s_ncopy, &size_ncopy);
		if (e == GFARM_ERR_NO_ERROR) {
			s_ncopy[size_ncopy] = '\0';
			nc = strtol(s_ncopy, &ep, 10);
			if (*ep == '\0') {
				ncopy = nc;
				break;
			}
		}
		if (p[0] == '/' && p[1] == '\0')
			break;
		p = dirname(p);
	}
	free(p);
#endif
	return (ncopy);
}

static int
stat_ncopy(const char *path)
{
	struct gfs_stat st;
	gfarm_error_t e;
	int ncopy;

	e = gfs_lstat_cached(path, &st);
	if (e == GFARM_ERR_NO_ERROR) {
		ncopy = st.st_ncopy;
		gfs_stat_free(&st);
		return (ncopy);
	}
	return (0);
}

static gfarm_error_t
select_nhosts(int *nhosts, char ***hostsp, int **portsp)
{
	char **hosts, *domain = "";
	int *ports, expiration = 60; /* 60 sec */
	gfarm_error_t e;

	if (is_expired(expiration)) {
		e = update_schedule_info(domain);
		if (e != GFARM_ERR_NO_ERROR)
			return (e);
	}
	GFARM_MALLOC_ARRAY(hosts, *nhosts);
	if (hosts == NULL)
		return (GFARM_ERR_NO_MEMORY);
	GFARM_MALLOC_ARRAY(ports, *nhosts);
	if (ports == NULL) {
		free(hosts);
		return (GFARM_ERR_NO_MEMORY);
	}
	e = gfarm_schedule_hosts_acyclic_to_write(schedule_path,
	    available_nhosts, available_hosts, nhosts, hosts, ports);
	if (e != GFARM_ERR_NO_ERROR) {
		free(hosts);
		free(ports);
	} else {
		*hostsp = hosts;
		*portsp = ports;
	}
	return (e);
}

static gfarm_error_t
replicate_file(const char *path, int ncopy, int ndsts, char **dsts, int *ports)
{
	int i, n = 0;
	gfarm_error_t e = GFARM_ERR_NO_ERROR;

	for (i = 0; i < ndsts && n < ncopy; ++i) {
		e = gfs_replicate_to(path, dsts[i], ports[i]);
		if (e == GFARM_ERR_NO_ERROR ||
		    e == GFARM_ERR_OPERATION_NOW_IN_PROGRESS)
			++n;
		else if (e == GFARM_ERR_ALREADY_EXISTS)
			/* skip */;
		else {
			gflog_error(GFARM_MSG_2000047,
			    "%s: replicataion to %s:%d fails: %s",
			    path, dsts[i], ports[i], gfarm_error_string(e));
			break;
		}
	}
	return (n == ncopy ? GFARM_ERR_NO_ERROR : e);
}

void
gfarm2fs_replicate(const char *path, struct fuse_file_info *fi)
{
	int ncopy, cur_ncopy, n, pid, *ports;
	int wait = 0, max_wait = 10;
	char **dsts;
	gfarm_error_t e;

	if (!replicate_enabled)
		return;

	/* if necessary number of copies is less than 2, return */
	ncopy = get_required_ncopy(path);
	if (ncopy < 2)
		return;

	/* if it has enough number of copies, return */
	cur_ncopy = stat_ncopy(path);
	if (ncopy <= cur_ncopy)
		return;

	/* if enough number of replication processes are in process, wait */
	while (replicate_max_concurrency > 0 &&
	    replicate_concurrency >= replicate_max_concurrency &&
	    wait++ < max_wait)
		sleep(1);
	if (wait >= max_wait) {
		gflog_error(GFARM_MSG_2000045, "%s: too busy to replicate",
		    path);
		return;
	}

	/* at most ncopy hosts required */
	n = ncopy;
	e = select_nhosts(&n, &dsts, &ports);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_2000048, "%s: failed to schedule hosts",
		    path);
		return;
	}

	/* create 'ncopy - cur_ncopy' copies */
	if (replicate_max_concurrency == 0) {
		gflog_info(GFARM_MSG_2000049,
		    "replicate: %s ncopy %d (required %d)", path, n, ncopy);
		e = replicate_file(path, ncopy - cur_ncopy, n, dsts, ports);
		free(dsts);
		free(ports);
		return;
	}
	switch ((pid = fork())) {
	case 0:
		e = gfarm_terminate();
		if (e == GFARM_ERR_NO_ERROR)
			e = gfarm_initialize(NULL, NULL);
		if (e != GFARM_ERR_NO_ERROR) {
			gflog_error(GFARM_MSG_2000050,
			    "%s: failed to initialize: %s",
			    path, gfarm_error_string(e));
			_exit(1);
		}
		e = replicate_file(path, ncopy - cur_ncopy, n, dsts, ports);
		(void)gfarm_terminate();
		_exit(e == GFARM_ERR_NO_ERROR ? 0 : 1);
	case -1:
		gflog_error_errno(GFARM_MSG_2000044, "fork");
		break;
	default:
		gflog_info(GFARM_MSG_2000042,
		    "replicate [%d]: %s ncopy %d (required %d)",
		    pid, path, n, ncopy);
		++replicate_concurrency;
		break;
	}
	free(dsts);
	free(ports);
}

#endif /* HAVE_PRIVATE_SRCS */
