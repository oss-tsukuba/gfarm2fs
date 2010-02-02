/*
 * $Id$
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <libgen.h>
#include <string.h>
#include <stdlib.h>

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
static int replicate_disable;

#define XATTR_NCOPY	"ncopy";

static void
sigchld_handler(int sig)
{
	int pid, status;

	for (;;) {
		pid = waitpid(-1, &status, WNOHANG);
		if (pid == -1 || pid == 0)
			break;
		--replicate_concurrency;
		gflog_info(1, "replicate [%d]: %d", pid, status);
	}
}

void
gfarm2fs_replicate_init(struct gfarm2fs_param *param)
{
	struct sigaction sa;

	if (param->ncopy == 0) {
		replicate_disable = 1;
		return;
	}
	replicate_ncopy = param->ncopy;
	replicate_max_concurrency = param->copy_limit;

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);
}

static int
gfarm2fs_replicate_ncopy(const char *path)
{
	int ncopy = replicate_ncopy;
#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
	char *p, s_ncopy[GFARM_INT32STRLEN];
	int nc;

	p = strdup(path);
	if (p == NULL)
		return (ncopy);

	for (;;) {
		rv = gfarm2fs_getxattr(p, XATTR_NCOPY,
		    &s_ncopy, sizeof(s_ncopy));
		if (rv == 0) {
			nc = strtol(str_ncopy, &ep, 10);
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

void
gfarm2fs_replicate(const char *path, struct fuse_file_info *fi)
{
	char str_ncopy[GFARM_INT32STRLEN];
	int ncopy;

	if (replicate_disable)
		return;

	ncopy = gfarm2fs_replicate_ncopy(path);
	if (ncopy < 2)
		return;

	while (replicate_concurrency >= replicate_max_concurrency)
		sleep(1);

	snprintf(str_ncopy, sizeof(str_ncopy), "%d", ncopy);
	switch (fork()) {
	case 0:
		gflog_info(1, "replicate [%d]: path %s ncopy %s", getpid(),
		    path, str_ncopy);
		execlp(rep, rep, "-q", "-N", str_ncopy, path, NULL);
		perror(rep);
		_exit(1);
	case -1:
		perror("fork");
		break;
	default:
		++replicate_concurrency;
		break;
	}
}
