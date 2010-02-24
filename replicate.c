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

static char *rep = "gfrep";
static int replicate_ncopy;
static int replicate_max_concurrency;
volatile sig_atomic_t replicate_concurrency = 0;
static int replicate_enabled;

#define XATTR_NCOPY	"gfarm.ncopy"

static void
sigchld_handler(int sig)
{
	int pid, status, no;
	char *msg;

	for (;;) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == -1 || pid == 0)
			break;
		--replicate_concurrency;

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
		gflog_info(GFARM_MSG_UNFIXED, "replicate [%d]: %s %d",
		    pid, msg, no);
	}
}

void
gfarm2fs_replicate_init(struct gfarm2fs_param *param)
{
	struct sigaction sa;

	if (param->ncopy <= 0 || param->copy_limit <= 0)
		return;

	replicate_enabled = 1;
	replicate_ncopy = param->ncopy;
	replicate_max_concurrency = param->copy_limit;

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);
}

void
gfarm2fs_replicate_final(void)
{
	/* Do nothing */
}

static int
gfarm2fs_replicate_ncopy(const char *path)
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
gfarm2fs_replicate_stat_ncopy(const char *path)
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

void
gfarm2fs_replicate(const char *path, struct fuse_file_info *fi)
{
	char str_ncopy[GFARM_INT32STRLEN];
	int ncopy;

	if (!replicate_enabled)
		return;

	/* if necessary number of copies is less than 2, return */
	ncopy = gfarm2fs_replicate_ncopy(path);
	if (ncopy < 2)
		return;

	/*
	 * if it is opened in read only mode and it has enough number
	 * of copies, return
	 */
	if (fi != NULL && (fi->flags & O_ACCMODE) == O_RDONLY &&
	    ncopy <= gfarm2fs_replicate_stat_ncopy(path))
		return;

	/* if enough number of replication processes are in process, wait */
	while (replicate_concurrency >= replicate_max_concurrency)
		sleep(1);

	snprintf(str_ncopy, sizeof(str_ncopy), "%d", ncopy);
	switch (fork()) {
	case 0:
		gflog_info(GFARM_MSG_UNFIXED,
		    "replicate [%d]: path %s ncopy %s", getpid(),
		    path, str_ncopy);
		execlp(rep, rep, "-q", "-N", str_ncopy, path, NULL);
		gflog_error_errno(GFARM_MSG_UNFIXED, "failed to exec %s", rep);
		_exit(1);
	case -1:
		gflog_error_errno(GFARM_MSG_UNFIXED, "fork");
		break;
	default:
		++replicate_concurrency;
		break;
	}
}

#endif /* HAVE_PRIVATE_SRCS */
