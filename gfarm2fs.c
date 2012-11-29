/*
 * GfarmFS-FUSE for Gfarm version 2
 *
 * $Id$
 */

#include "config.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <limits.h>
#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

#if !defined(S_IFDIR) && defined(__S_IFDIR)
/*
 * XXX Is this really necessary?
 * At least CentOS 5.0 and all NetBSD releases don't need this #define.
 */
#define S_IFDIR	__S_IFDIR
#endif

/*
 * fuse.h requres that _FILE_OFFSET_BITS is defined in any case, but
 * AC_SYS_LARGEFILE does not define it on a 64bit platform like x86_64
 * since it is not necessary.  To avoid this problem we define it here.
 */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#define FUSE_USE_VERSION 26
#include <fuse.h>

#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <gfarm/gfarm.h>

#include "gfarm2fs.h"
#include "replicate.h"
#include "open_file.h"
#include "xattr.h"
#include "id.h"
#include "gfarm2fs_msg_enums.h"

/* for old interface */
#undef USE_GETDIR

/* XXX FIXME */
#define GFS_DEV		((dev_t)-1)
#define GFS_BLKSIZE	8192
#define STAT_BLKSIZ	512	/* for st_blocks */

char *program_name = "gfarm2fs";

static const char GFARM2FS_SYSLOG_FACILITY_DEFAULT[] = "local0";
static const char GFARM2FS_SYSLOG_PRIORITY_DEBUG[] = "debug";

static const char *mount_point;

#define PATH_LEN_LIMIT 200
static const char syslog_fmt[] = "<%s:%s>[%s]%s%s: %s";
static const char trunc_str[] = "(...)";
static const char empty_str[] = "";

#define gfarm2fs_check_error(msgNo, fuse_opname, gfarm_funcname, \
			     gfarm_path, gfarm_e) \
{ \
	if (gfarm_e != GFARM_ERR_NO_ERROR) { \
		int ret_errno    = gfarm_error_to_errno(gfarm_e); \
		int path_len     = strlen(gfarm_path); \
		int path_offset  = 0; \
		const char *path_prefix = empty_str; \
		if (path_len > PATH_LEN_LIMIT) { \
			path_offset = path_len - PATH_LEN_LIMIT; \
			path_prefix = trunc_str; \
		} \
		if (ret_errno == EINVAL || fuse_opname == OP_RELEASE) { \
			gflog_error(msgNo, syslog_fmt, fuse_opname, \
				gfarm_funcname, mount_point, \
				path_prefix, gfarm_path + path_offset, \
				gfarm_error_string(gfarm_e)); \
		} else if (ret_errno != ENOENT) { \
			gflog_info(msgNo, syslog_fmt, fuse_opname, \
				gfarm_funcname, mount_point, \
				path_prefix, gfarm_path + path_offset, \
				gfarm_error_string(gfarm_e)); \
		} else { \
			gflog_debug(msgNo, syslog_fmt, fuse_opname, \
				gfarm_funcname, mount_point, \
				path_prefix, gfarm_path + path_offset, \
				gfarm_error_string(gfarm_e)); \
		} \
	} \
}

static const char OP_GETATTR[] = "GETATTR";
static const char OP_FGETATTR[] = "FGETATTR";
#if 0 /* XXX Part of invoking gfs_access() is defined "if 0" now */
static const char OP_ACCESS[] = "ACCESS";
#endif
static const char OP_READLINK[] = "READLINK";
#ifndef USE_GETDIR
static const char OP_OPENDIR[] = "OPENDIR";
static const char OP_READDIR[] = "READDIR";
static const char OP_RELEASEDIR[] = "RELEASEDIR";
#else /* USE_GETDIR */
static const char OP_GETDIR[] = "GETDIR";
#endif /* USE_GETDIR */
static const char OP_MKNOD[] = "MKNOD";
static const char OP_MKDIR[] = "MKDIR";
static const char OP_UNLINK[] = "UNLINK";
static const char OP_RMDIR[] = "RMDIR";
static const char OP_SYMLINK[] = "SYMLINK";
static const char OP_RENAME[] = "RENAME";
static const char OP_LINK[] = "LINK";
static const char OP_CHMOD[] = "CHMOD";
static const char OP_CHOWN[] = "CHOWN";
static const char OP_TRUNCATE[] = "TRUNCATE";
static const char OP_FTRUNCATE[] = "FTRUNCATE";
static const char OP_UTIMENS[] = "UTIMENS";
static const char OP_CREATE[] = "CREATE";
static const char OP_OPEN[] = "OPEN";
static const char OP_READ[] = "READ";
static const char OP_WRITE[] = "WRITE";
static const char OP_STATFS[] = "STATFS";
static const char OP_RELEASE[] = "RELEASE";
static const char OP_FSYNC[] = "FSYNC";
static const char OP_FLUSH[] = "FLUSH";
#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
static const char OP_SETXATTR[] = "SETXATTR";
static const char OP_GETXATTR[] = "GETXATTR";
static const char OP_LISTXATTR[] = "LISTXATTR";
static const char OP_REMOVEXATTR[] = "REMOVEXATTR";
#endif /* HAVE_SYS_XATTR_H && ENABLE_XATTR */

#define GFARM_DIR	".gfarm"

static const char gfarm_path_prefix[] = GFARM_DIR "/";
#define GFARM_PATH_PREFIX_LEN	(sizeof(gfarm_path_prefix) - 1)

static char *gfarm2fs_path_prefix, *gfarm2fs_realpath_prefix;
static size_t gfarm2fs_path_prefix_len, gfarm2fs_realpath_prefix_len;
const static char *gfarm2fs_subdir;
static size_t gfarm2fs_subdir_len;
#define IS_SUBDIR(p)	(memcmp(p, gfarm2fs_subdir, gfarm2fs_subdir_len) == 0)

static void
gfarm2fs_record_mount_point(const char *mpoint, const char *subdir)
{
	char buf[PATH_MAX];

	if (realpath(mpoint, buf) == NULL) {
		gflog_error(GFARM_MSG_2000058, "realpath(%s): %s",
		    mpoint, strerror(errno));
		exit(1);
	}

	if (strcmp(mpoint, buf) == 0) {
		gfarm2fs_realpath_prefix_len = 0;
		gfarm2fs_realpath_prefix = NULL;
	} else {
		gfarm2fs_realpath_prefix_len =
		    strlen(buf) + 1 + GFARM_PATH_PREFIX_LEN;
		gfarm2fs_realpath_prefix =
		    malloc(gfarm2fs_realpath_prefix_len + 1);
		if (gfarm2fs_realpath_prefix == NULL) {
			gflog_error(GFARM_MSG_2000059,
			    "no memory for \"%s/%s\"", buf, gfarm_path_prefix);
			exit(1);
		}
		sprintf(gfarm2fs_realpath_prefix, "%s/%s",
		    buf, gfarm_path_prefix);
	}

	gfarm2fs_path_prefix_len =
	    strlen(mpoint) + 1 + GFARM_PATH_PREFIX_LEN;
	gfarm2fs_path_prefix = malloc(gfarm2fs_path_prefix_len + 1);
	if (gfarm2fs_path_prefix == NULL) {
		gflog_error(GFARM_MSG_2000060,
		    "no memory for \"%s/%s\"", mpoint, gfarm_path_prefix);
		exit(1);
	}
	sprintf(gfarm2fs_path_prefix, "%s/%s",
	    mpoint, gfarm_path_prefix);

	/* subdir may be modified (free'ed?) when it includes trailing /s */
	gfarm2fs_subdir = subdir != NULL ? strdup(subdir) : "";
	if (gfarm2fs_subdir == NULL) {
		gflog_error(GFARM_MSG_UNFIXED,
		    "no memory to allocate subdir \"%s\"", subdir);
		exit(1);
	}
	gfarm2fs_subdir_len = strlen(gfarm2fs_subdir);
	/* ignore one trailing slash.  see gfarm2fs_getattr */
	if (gfarm2fs_subdir_len > 0 &&
	    gfarm2fs_subdir[gfarm2fs_subdir_len - 1] == '/')
		--gfarm2fs_subdir_len;
}

gfarm_error_t
gfarmize_path(const char *path, struct gfarmized_path *gfarmized)
{
	const char *p = path;
	int sz;

	if (IS_SUBDIR(p))
		p += gfarm2fs_subdir_len;
	if (p[0] == '/')
		p++;
	if (memcmp(p, gfarm_path_prefix, GFARM_PATH_PREFIX_LEN) == 0) {
		sz = strlen(p)
		    - GFARM_PATH_PREFIX_LEN + 2 + GFARM_URL_PREFIX_LENGTH + 1;
		GFARM_MALLOC_ARRAY(gfarmized->path, sz);
		if (gfarmized->path == NULL)
			return (GFARM_ERR_NO_MEMORY);
		snprintf(gfarmized->path, sz, "%s//%s",
		    GFARM_URL_PREFIX, p + GFARM_PATH_PREFIX_LEN);
		gfarmized->alloced = 1;
		return (GFARM_ERR_NO_ERROR);
	}
	gfarmized->alloced = 0;
	gfarmized->path = (char *)path; /* UNCONST */
	return (GFARM_ERR_NO_ERROR);
}

void
free_gfarmized_path(struct gfarmized_path *gfarmized)
{
	if (gfarmized->alloced)
		free(gfarmized->path);
}

/* NOTE: *pathp must be malloc'ed memory */
static gfarm_error_t
ungfarmize_path(char **pathp, const char *c_path)
{
	char *path = *pathp, *p, *metadb = NULL;
	const static char metadb_xattr[] = "gfarm2fs.metadb";
	size_t metadb_size = 0;
	gfarm_error_t e;

	if (gfarm_is_url(path) &&
	    path[GFARM_URL_PREFIX_LENGTH] == '/' &&
	    path[GFARM_URL_PREFIX_LENGTH + 1] == '/') {
		if (path[GFARM_URL_PREFIX_LENGTH + 2] == '/' &&
		    (gfarm2fs_xattr_get(c_path, metadb_xattr, NULL,
			&metadb_size) == GFARM_ERR_NO_ERROR)) {
			/* expand metadb and port from the current path */
			GFARM_MALLOC_ARRAY(metadb, metadb_size + 1);
			if (metadb == NULL) /* 1 for '\0' */
				return (GFARM_ERR_NO_MEMORY);
			e = gfarm2fs_xattr_get(c_path, metadb_xattr,
				metadb, &metadb_size);
			if (e != GFARM_ERR_NO_ERROR)
				return (e);
			metadb[metadb_size] = '\0';
		}
		/* "gfarm://host/path" -> "MOUNT_POINT/.gfarm/host/path" */
		p = malloc(gfarm2fs_path_prefix_len + metadb_size +
		    strlen(path) - (GFARM_URL_PREFIX_LENGTH + 2) + 1);
		if (p == NULL) {
			/* NOTE: *pathp is not freed in this case */
			return (GFARM_ERR_NO_MEMORY);
		}
		sprintf(p, "%s%s%s", gfarm2fs_path_prefix,
		    metadb == NULL ? "" : metadb,
		    path + GFARM_URL_PREFIX_LENGTH + 2);
		free(metadb);
		free(path);
		*pathp = p;
	}
	return (GFARM_ERR_NO_ERROR);
}

static gfarm_error_t
parent_path(const char *path, struct gfarmized_path *gfarmized)
{
	gfarm_error_t e = gfarmize_path(path, gfarmized);
	const char *p;

	if (e != GFARM_ERR_NO_ERROR)
		return (e);

	p = gfarm_url_dir(gfarmized->path);
	if (p == NULL)
		return (GFARM_ERR_NO_MEMORY);
	if (gfarmized->alloced)
		free(gfarmized->path);
	else
		gfarmized->alloced = 1;
	gfarmized->path = (char *)p; /* UNCONST */
	return (GFARM_ERR_NO_ERROR);
}

/*
 * convert oldpath for symlink(3) to gfarm://-style URL,
 * but only for the following style:
 *	/MOUNT/POINT/.gfarm/host:port/PATH/NAME
 */
static gfarm_error_t
gfarmize_symlink_old(const char *old, struct gfarmized_path *gfarmized_old)
{
	if (gfarm_is_url(old)) {
		gfarmized_old->path = (char *)old;	/* UNCONST */
		gfarmized_old->alloced = 0;
		return (GFARM_ERR_NO_ERROR);
	}

	/* is "/MOUNT/POINT/.gfarm/host:port/PATH/NAME" ? */
	if (memcmp(old, gfarm2fs_path_prefix, gfarm2fs_path_prefix_len) == 0) {
		/* convert to "gfarm://host:/path" */
		gfarmized_old->path =
		    malloc(GFARM_URL_PREFIX_LENGTH + 2 +
		    strlen(old) - gfarm2fs_path_prefix_len + 1);
		if (gfarmized_old->path == NULL)
			return (GFARM_ERR_NO_MEMORY);
		sprintf(gfarmized_old->path, "%s//%s",
		    GFARM_URL_PREFIX,
		    old + gfarm2fs_path_prefix_len);
		gfarmized_old->alloced = 1;
	} else if (gfarm2fs_realpath_prefix != NULL &&
	    memcmp(old, gfarm2fs_realpath_prefix,
	    gfarm2fs_realpath_prefix_len) == 0) {
		/* convert to "gfarm://host:/path" */
		gfarmized_old->path =
		    malloc(GFARM_URL_PREFIX_LENGTH + 2 +
		    strlen(old) - gfarm2fs_realpath_prefix_len + 1);
		if (gfarmized_old->path == NULL)
			return (GFARM_ERR_NO_MEMORY);
		sprintf(gfarmized_old->path, "%s//%s",
		    GFARM_URL_PREFIX,
		    old + gfarm2fs_realpath_prefix_len);
		gfarmized_old->alloced = 1;
	} else {
		gfarmized_old->path = (char *)old;	/* UNCONST */
		gfarmized_old->alloced = 0;
	}
	return (GFARM_ERR_NO_ERROR);
}

static uid_t
get_uid(const char *gpath, char *user)
{
	gfarm_error_t e;
	uid_t uid;

	e = gfarm2fs_get_uid(gpath, user, &uid);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_warning(GFARM_MSG_2000089,
			      "get_uid(%s) failed: %s",
			      user, gfarm_error_string(e));
		return (gfarm2fs_get_nobody_uid());
	}
	return (uid);
}

static int
get_gid(const char *gpath, char *group)
{
	gfarm_error_t e;
	gid_t gid;

	e = gfarm2fs_get_gid(gpath, group, &gid);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_warning(GFARM_MSG_2000090,
			      "get_gid(%s) failed: %s",
			      group, gfarm_error_string(e));
		return (gfarm2fs_get_nogroup_gid());
	}
	return (gid);
}

static int
get_faked_nlink(struct gfs_stat *st)
{
	return (GFARM_S_ISDIR(st->st_mode) ? 32000 : st->st_nlink);
}

static int
get_genuine_nlink(struct gfs_stat *st)
{
	return (st->st_nlink);
}

static int (*get_nlink)(struct gfs_stat *st) = get_faked_nlink;

static void
copy_gfs_stat(const char *gpath, struct stat *dst, struct gfs_stat *src)
{
	memset(dst, 0, sizeof(*dst));
	dst->st_dev = GFS_DEV;
	dst->st_ino = src->st_ino;
	dst->st_mode = src->st_mode;
	dst->st_nlink = get_nlink(src);
	dst->st_uid = get_uid(gpath, src->st_user);
	dst->st_gid = get_gid(gpath, src->st_group);
	dst->st_size = src->st_size;
	dst->st_blksize = GFS_BLKSIZE;
	dst->st_blocks = (src->st_size + STAT_BLKSIZ - 1) / STAT_BLKSIZ;
	dst->st_atime = src->st_atimespec.tv_sec;
	dst->st_mtime = src->st_mtimespec.tv_sec;
	dst->st_ctime = src->st_ctimespec.tv_sec;
	gfarm2fs_stat_atime_nsec_set(dst, src->st_atimespec.tv_nsec);
	gfarm2fs_stat_mtime_nsec_set(dst, src->st_mtimespec.tv_nsec);
	gfarm2fs_stat_ctime_nsec_set(dst, src->st_ctimespec.tv_nsec);
}

/* st_outp needs gfs_stat_free() */
static gfarm_error_t
gfarm2fs_fstat(
	struct gfarm2fs_file *fp,
	struct gfs_stat *st_inp, struct gfs_stat *st_outp)
{
	gfarm_error_t e;

	/* assert(st_outp); */

	/* get atime, mtime and size from gfsd */
	e = gfs_pio_stat(fp->gf, st_outp); /* include gfs_fstat() */
	if (e != GFARM_ERR_NO_ERROR)
		return (e);

	if (fp->time_updated) { /* use atime and mtime from gfmd */
		if (st_inp == NULL) {
			struct gfs_stat st_gfmd;

			/* gfs_fstat() again */
			e = gfs_fstat(fp->gf, &st_gfmd); /* from gfmd */
			if (e != GFARM_ERR_NO_ERROR) {
				gfs_stat_free(st_outp);
				return (e);
			}
			st_outp->st_atimespec = st_gfmd.st_atimespec;
			st_outp->st_mtimespec = st_gfmd.st_mtimespec;
			gfs_stat_free(&st_gfmd);
		} else {
			st_outp->st_atimespec = st_inp->st_atimespec;
			st_outp->st_mtimespec = st_inp->st_mtimespec;
		}
	}
	return (GFARM_ERR_NO_ERROR);
}

static int
gfarm2fs_getattr(const char *path, struct stat *stbuf)
{
	struct gfarmized_path gfarmized;
	struct gfs_stat st;
	struct gfarm2fs_file *fp;
	gfarm_error_t e;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000061, OP_GETATTR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_lstat_cached(gfarmized.path, &st);
	if (e != GFARM_ERR_NO_ERROR) {
		if (IS_SUBDIR(gfarmized.path) &&
		    strcmp(gfarmized.path + gfarm2fs_subdir_len, "/" GFARM_DIR)
		    == 0) {
			memset(stbuf, 0, sizeof(*stbuf));
			stbuf->st_dev = GFS_DEV;
			stbuf->st_ino = 1;
			stbuf->st_mode = S_IFDIR | 0111;
			stbuf->st_nlink = 1; /* tell find(1) to ignore nlink */
			stbuf->st_uid = 0;
			stbuf->st_gid = 0;
			stbuf->st_size = 1024;
			stbuf->st_blksize = GFS_BLKSIZE;
			stbuf->st_blocks =
			    (stbuf->st_size + STAT_BLKSIZ - 1) / STAT_BLKSIZ;
			stbuf->st_atime = 0;
			stbuf->st_mtime = 0;
			stbuf->st_ctime = 0;
			return (GFARM_ERR_NO_ERROR);
		}
		gfarm2fs_check_error(GFARM_MSG_2000001, OP_GETATTR,
					"gfs_lstat_cached", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}
	if ((fp = gfarm2fs_open_file_lookup(st.st_ino)) != NULL) {
		struct gfs_stat st2;

		e = gfarm2fs_fstat(fp, &st, &st2);
		if (e != GFARM_ERR_NO_ERROR) {
			gfs_stat_free(&st);
			gfarm2fs_check_error(GFARM_MSG_2000046, OP_GETATTR,
				"gfs_pio_stat", gfarmized.path, e);
			free_gfarmized_path(&gfarmized);
			return (-gfarm_error_to_errno(e));
		}
		gfs_stat_free(&st);
		st = st2;
	}
	copy_gfs_stat(gfarmized.path, stbuf, &st);
	gfs_stat_free(&st);
	free_gfarmized_path(&gfarmized);
	return (0);
}

static inline struct gfarm2fs_file *
get_filep(struct fuse_file_info *fi)
{
	return ((struct gfarm2fs_file *)(uintptr_t)fi->fh);
}

static int
gfarm2fs_fgetattr(const char *path, struct stat *stbuf,
	struct fuse_file_info *fi)
{
	struct gfs_stat st;
	struct gfarmized_path gfarmized;
	struct gfarm2fs_file *fp = get_filep(fi);
	gfarm_error_t e;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000091, OP_FGETATTR,
					"gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfarm2fs_fstat(fp, NULL, &st);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000002, OP_FGETATTR,
					"gfs_pio_stat", path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}

	copy_gfs_stat(path, stbuf, &st);
	free_gfarmized_path(&gfarmized);
	gfs_stat_free(&st);
	return (0);
}

static int
gfarm2fs_access(const char *path, int mask)
{
	/* XXX FIXME */
	return (-ENOSYS);
#if 0
	gfarm_error_t e;
	struct gfarmized_path gfarmized;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000062, OP_ACCESS,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_access(gfarmized.path, mask);
	gfarm2fs_check_error(GFARM_MSG_2000003, OP_ACCESS,
			     "gfs_access", gfarmized.path, e);
	free_gfarmized_path(&gfarmized);
	return (-gfarm_error_to_errno(e));
#endif
}

static int
gfarm2fs_readlink(const char *path, char *buf, size_t size)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;
	char *old;
	size_t len;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000063, OP_READLINK,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}

	e = gfs_readlink(gfarmized.path, &old);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000004, OP_READLINK,
				     "gfs_readlink", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}

	e = ungfarmize_path(&old, path);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000064, OP_READLINK,
		    "ungfarmize_path", old, GFARM_ERR_NO_MEMORY);
		free(old);
		free_gfarmized_path(&gfarmized);
		return (-ENOMEM);
	}

	len = strlen(old);
	if (len >= size)
		len = size - 1;
	memcpy(buf, old, len);
	buf[len] = '\0';
	free(old);
	free_gfarmized_path(&gfarmized);
	return (0);
}

#ifndef USE_GETDIR
static int
gfarm2fs_opendir(const char *path, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;
	GFS_Dir dp;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000065, OP_OPENDIR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_opendir_caching(gfarmized.path, &dp);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000005, OP_OPENDIR,
				     "gfs_opendir_caching", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}

	fi->fh = (unsigned long) dp;
	free_gfarmized_path(&gfarmized);
	return (0);
}

static inline GFS_Dir
get_dirp(struct fuse_file_info *fi)
{
	return (GFS_Dir) (uintptr_t) fi->fh;
}

static int
gfarm2fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	off_t offset, struct fuse_file_info *fi)
{
	GFS_Dir dp = get_dirp(fi);
	struct gfs_dirent *de;
	struct stat st;
	gfarm_off_t off = 0;
	int seekdir_works = 0;
	gfarm_error_t e, e2;

	(void) path;
	e2 = gfs_seekdir(dp, offset);
	if (e2 == GFARM_ERR_NO_ERROR) {
		seekdir_works = 1;
	} else if (e2 != GFARM_ERR_FUNCTION_NOT_IMPLEMENTED) {
		/* was GFARM_ERR_FUNCTION_NOT_IMPLEMENTED until gfarm-2.5.4 */
		gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_READDIR,
				     "gfs_seekdir", path, e2);
	}

	while ((e = gfs_readdir(dp, &de)) == GFARM_ERR_NO_ERROR &&
		de != NULL) {
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_fileno;
		st.st_mode = de->d_type << 12;
		if (seekdir_works) {
			e2 = gfs_telldir(dp, &off);
			gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_READDIR,
					     "gfs_telldir", path, e2);
		}
		if (filler(buf, de->d_name, &st, off))
			break;
	}
	gfarm2fs_check_error(GFARM_MSG_2000006, OP_READDIR,
				"gfs_readdir", path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_releasedir(const char *path, struct fuse_file_info *fi)
{
	GFS_Dir dp = get_dirp(fi);
	gfarm_error_t e;

	(void) path;
	e = gfs_closedir(dp);
	gfarm2fs_check_error(GFARM_MSG_2000007, OP_RELEASEDIR,
				"gfs_closedir", path, e);
	return (-gfarm_error_to_errno(e));
}
#else /* USE_GETDIR */

static int
gfarm2fs_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
	gfarm_error_t e, e2;
	struct gfarmized_path gfarmized;
	GFS_Dir dp;
	struct gfs_dirent *de;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000066, OP_GETDIR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_opendir_caching(gfarmized.path, &dp);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000008, OP_GETDIR,
				     "gfs_opendir_caching", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}

	while ((e = gfs_readdir(dp, &de)) == GFARM_ERR_NO_ERROR &&
		de != NULL) {
		if (filler(h, de->d_name, de->d_type << 12, de->d_fileno))
			break;
	}
	gfarm2fs_check_error(GFARM_MSG_2000009, OP_GETDIR,
			     "gfs_readdir", gfarmized.path, e);

	e2 = gfs_closedir(dp);
	gfarm2fs_check_error(GFARM_MSG_2000010, OP_GETDIR,
			     "gfs_closedir", gfarmized.path, e2);

	free_gfarmized_path(&gfarmized);

	if (e == GFARM_ERR_NO_ERROR)
		e = e2;

	return (-gfarm_error_to_errno(e));
}
#endif

static int
gfarm2fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	struct gfarmized_path gfarmized;
	GFS_File gf;
	gfarm_error_t e;

	if (!S_ISREG(mode))
		return (-ENOSYS);

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000067, OP_MKNOD,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_pio_create(gfarmized.path, GFARM_FILE_WRONLY,
	    mode & GFARM_S_ALLPERM, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000011, OP_MKNOD,
					"gfs_pio_create", gfarmized.path, e);
	} else {
		e = gfs_pio_close(gf);
		gfarm2fs_check_error(GFARM_MSG_2000012, OP_MKNOD,
					"gfs_pio_close", gfarmized.path, e);
	}
	free_gfarmized_path(&gfarmized);

	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_mkdir(const char *path, mode_t mode)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000068, OP_MKDIR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_mkdir(gfarmized.path, mode & GFARM_S_ALLPERM);
	gfarm2fs_check_error(GFARM_MSG_2000013, OP_MKDIR,
				"gfs_mkdir", gfarmized.path, e);
	free_gfarmized_path(&gfarmized);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_unlink(const char *path)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000069, OP_UNLINK,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_unlink(gfarmized.path);
	gfarm2fs_check_error(GFARM_MSG_2000014, OP_UNLINK,
			     "gfs_unlink", gfarmized.path, e);
	free_gfarmized_path(&gfarmized);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_rmdir(const char *path)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000070, OP_RMDIR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_rmdir(gfarmized.path);
	gfarm2fs_check_error(GFARM_MSG_2000015, OP_RMDIR,
			     "gfs_rmdir", gfarmized.path, e);
	free_gfarmized_path(&gfarmized);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_symlink(const char *old, const char *new)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized_old, gfarmized_new;

	e = gfarmize_symlink_old(old, &gfarmized_old);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000071, OP_SYMLINK,
				     "gfarmize_symlink_old", old, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfarmize_path(new, &gfarmized_new);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000092, OP_SYMLINK,
				     "gfarmize_symlink_new", new, e);
		free_gfarmized_path(&gfarmized_old);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_symlink(gfarmized_old.path, gfarmized_new.path);
	gfarm2fs_check_error(GFARM_MSG_2000016, OP_SYMLINK,
			     "gfs_symlink", new, e);
	free_gfarmized_path(&gfarmized_new);
	free_gfarmized_path(&gfarmized_old);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_rename(const char *from, const char *to)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized_from, gfarmized_to;

	e = gfarmize_path(from, &gfarmized_from);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000072, OP_RENAME,
				     "gfarmize_path", from, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfarmize_path(to, &gfarmized_to);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000073, OP_RENAME,
				     "gfarmize_path", to, e);
		free_gfarmized_path(&gfarmized_from);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_rename(gfarmized_from.path, gfarmized_to.path);
	gfarm2fs_check_error(GFARM_MSG_2000017, OP_RENAME,
				"gfs_rename", gfarmized_from.path, e);
	free_gfarmized_path(&gfarmized_to);
	free_gfarmized_path(&gfarmized_from);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_link(const char *from, const char *to)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized_from, gfarmized_to;

	e = gfarmize_path(from, &gfarmized_from);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000074, OP_LINK,
				     "gfarmize_path", from, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfarmize_path(to, &gfarmized_to);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000075, OP_LINK,
				     "gfarmize_path", to, e);
		free_gfarmized_path(&gfarmized_from);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_link(gfarmized_from.path, gfarmized_to.path);
	gfarm2fs_check_error(GFARM_MSG_2000018, OP_LINK,
			     "gfs_link", gfarmized_to.path, e);
	free_gfarmized_path(&gfarmized_to);
	free_gfarmized_path(&gfarmized_from);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_chmod(const char *path, mode_t mode)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000076, OP_CHMOD,
				     "gfarmize_path", gfarmized.path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_chmod(gfarmized.path, mode & GFARM_S_ALLPERM);
	gfarm2fs_check_error(GFARM_MSG_2000019, OP_CHMOD,
			     "gfs_chmod", gfarmized.path, e);
	free_gfarmized_path(&gfarmized);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_chown(const char *path, uid_t uid, gid_t gid)
{
	gfarm_error_t e;
	char *user = NULL, *group = NULL;
	struct gfarmized_path gfarmized;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000077, OP_CHOWN,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	if (uid != -1 &&
	    ((e = gfarm2fs_get_user(gfarmized.path, uid, &user))
	     != GFARM_ERR_NO_ERROR)) {
		gfarm2fs_check_error(GFARM_MSG_2000093, OP_CHOWN,
				     "gfarm2fs_get_user", path, e);
		goto end;
	}

	if (gid != -1 &&
	    ((e = gfarm2fs_get_group(gfarmized.path, gid, &group))
	     != GFARM_ERR_NO_ERROR)) {
		gfarm2fs_check_error(GFARM_MSG_2000094, OP_CHOWN,
				     "gfarm2fs_get_group", path, e);
		goto end;
	}
#ifdef HAVE_GFS_LCHOWN
	e = gfs_lchown(gfarmized.path, user, group);
	gfarm2fs_check_error(GFARM_MSG_2000020, OP_CHOWN,
			     "gfs_lchown", gfarmized.path, e);
#else
	e = gfs_chown(gfarmized.path, user, group);
	gfarm2fs_check_error(GFARM_MSG_2000020, OP_CHOWN,
			     "gfs_chown", gfarmized.path, e);
#endif
end:
	free_gfarmized_path(&gfarmized);
	free(user);
	free(group);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_truncate(const char *path, off_t size)
{
	gfarm_error_t e, e2;
	struct gfarmized_path gfarmized;
	GFS_File gf;
	int flags = GFARM_FILE_WRONLY;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000078, OP_TRUNCATE,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	if (size == 0)
		flags |= GFARM_FILE_TRUNC;
	e = gfs_pio_open(gfarmized.path, flags, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000021, OP_TRUNCATE,
				     "gfs_pio_open", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}

	e = gfs_pio_truncate(gf, size);
	gfarm2fs_check_error(GFARM_MSG_2000022, OP_TRUNCATE,
			     "gfs_pio_truncate", gfarmized.path, e);
	e2 = gfs_pio_close(gf);
	gfarm2fs_check_error(GFARM_MSG_2000023, OP_TRUNCATE,
			     "gfs_pio_close", gfarmized.path, e2);
	free_gfarmized_path(&gfarmized);

	return (-gfarm_error_to_errno(e != GFARM_ERR_NO_ERROR ? e : e2));
}

static int
gfarm2fs_ftruncate(const char *path, off_t size,
		   struct fuse_file_info *fi)
{
	gfarm_error_t e;
	struct gfarm2fs_file *fp = get_filep(fi);

	(void) path;
	e = gfs_pio_truncate(fp->gf, size);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000024, OP_FTRUNCATE,
		    "gfs_pio_ftruncate", path, e);
	} else
		fp->time_updated = 0;
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_utimens(const char *path, const struct timespec ts[2])
{
	struct gfarm_timespec gt[2];
	gfarm_error_t e;
	struct gfarmized_path gfarmized;
	struct gfarm2fs_file *fp;
	struct gfs_stat st;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_UTIMENS,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_lstat_cached(gfarmized.path, &st);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_UTIMENS,
		    "gfs_lstat_cached", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}
	if ((fp = gfarm2fs_open_file_lookup(st.st_ino)) != NULL) {
		fp->gt[0].tv_sec = ts[0].tv_sec;
		fp->gt[0].tv_nsec = ts[0].tv_nsec;
		fp->gt[1].tv_sec = ts[1].tv_sec;
		fp->gt[1].tv_nsec = ts[1].tv_nsec;
		fp->time_updated = 1;
	}
	gfs_stat_free(&st);
	gt[0].tv_sec = ts[0].tv_sec;
	gt[0].tv_nsec = ts[0].tv_nsec;
	gt[1].tv_sec = ts[1].tv_sec;
	gt[1].tv_nsec = ts[1].tv_nsec;
#ifdef HAVE_GFS_LUTIMES
	e = gfs_lutimes(gfarmized.path, gt);
#else
	e = gfs_utimes(gfarmized.path, gt);
#endif
	gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_UTIMENS,
			     "gfs_lutimes", gfarmized.path, e);
	free_gfarmized_path(&gfarmized);
	return (-gfarm_error_to_errno(e));
}

#define IS_WRITABLE(x) (((x) & GFARM_FILE_WRONLY) != 0 || \
			((x) & GFARM_FILE_RDWR) != 0)

static int
gfs_hook_open_flags_gfarmize(int open_flags)
{
	int gfs_flags;

	switch (open_flags & O_ACCMODE) {
	case O_RDONLY:
		gfs_flags = GFARM_FILE_RDONLY;
		break;
	case O_WRONLY:
		gfs_flags = GFARM_FILE_WRONLY;
		break;
	case O_RDWR:
		gfs_flags = GFARM_FILE_RDWR;
		break;
	default: return (-1);
	}

#if 0 /* this is unnecessary */
	if ((open_flags & O_CREAT) != 0)
		gfs_flags |= GFARM_FILE_CREATE;
#endif
	if ((open_flags & O_TRUNC) != 0)
		gfs_flags |= GFARM_FILE_TRUNC;
#if 0 /* not yet on Gfarm v2 */
	if ((open_flags & O_APPEND) != 0)
		gfs_flags |= GFARM_FILE_APPEND;
	if ((open_flags & O_EXCL) != 0)
		gfs_flags |= GFARM_FILE_EXCLUSIVE;
#endif
#if 0 /* not yet on Gfarm v2 */
	/* open(2) and creat(2) should be unbuffered */
	gfs_flags |= GFARM_FILE_UNBUFFERED;
#endif
	return (gfs_flags);
}

static gfarm_error_t
gfarm2fs_file_init(
	const char *path, GFS_File gf, struct gfarm2fs_file **fpp, int flags)
{
	gfarm_error_t e;
	struct gfarm2fs_file *fp;
	struct gfs_stat st;

	e = gfs_lstat_cached(path, &st);
	if (e != GFARM_ERR_NO_ERROR)
		return (e);

	GFARM_MALLOC(fp);
	if (fp) {
		fp->flags = flags;
		fp->gf = gf;
		fp->time_updated = 0;
		fp->inum = st.st_ino;
		*fpp = fp;
		gfs_stat_free(&st);
		return (GFARM_ERR_NO_ERROR);
	} else {
		gfs_stat_free(&st);
		return (GFARM_ERR_NO_MEMORY);
	}
}

static int
gfarm2fs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	struct gfarm2fs_file *fp;
	gfarm_error_t e;
	struct gfarmized_path gfarmized;
	GFS_File gf;
	int flags;

	flags = gfs_hook_open_flags_gfarmize(fi->flags);
	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000080, OP_CREATE,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_pio_create(gfarmized.path, flags, mode & GFARM_S_ALLPERM, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000026, OP_CREATE,
				     "gfs_pio_create", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}
	e = gfarm2fs_file_init(gfarmized.path, gf, &fp, flags);
	if (e != GFARM_ERR_NO_ERROR) {
		(void)gfs_pio_close(gf);
		gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_CREATE,
		    "gfarm2fs_file_init", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}

	fi->fh = (unsigned long)fp;
	gfarm2fs_open_file_enter(fp, fi->flags|O_CREAT);
	free_gfarmized_path(&gfarmized);
	return (0);
}

static int
gfarm2fs_open(const char *path, struct fuse_file_info *fi)
{
	struct gfarm2fs_file *fp;
	GFS_File gf;
	int flags;
	gfarm_error_t e;
	struct gfarmized_path gfarmized;

	flags = gfs_hook_open_flags_gfarmize(fi->flags);
	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000081, OP_OPEN,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_pio_open(gfarmized.path, flags, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000027, OP_OPEN,
				     "gfs_pio_open", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}
	e = gfarm2fs_file_init(gfarmized.path, gf, &fp, flags);
	if (e != GFARM_ERR_NO_ERROR) {
		(void)gfs_pio_close(gf);
		gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_OPEN,
		    "gfarm2fs_file_init", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}

	fi->fh = (unsigned long)fp;
	gfarm2fs_open_file_enter(fp, fi->flags);
	free_gfarmized_path(&gfarmized);
	return (0);
}

static int
gfarm2fs_read(const char *path, char *buf, size_t size, off_t offset,
	struct fuse_file_info *fi)
{
	gfarm_error_t e;
	gfarm_off_t off;
	int rv;
	struct gfarm2fs_file *fp = get_filep(fi);

	(void) path;
	e = gfs_pio_seek(fp->gf, offset, GFARM_SEEK_SET, &off);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000028, OP_READ,
					"gfs_pio_seek", path, e);
	} else {
		e = gfs_pio_read(fp->gf, buf, size, &rv);
		gfarm2fs_check_error(GFARM_MSG_2000029, OP_READ,
					"gfs_pio_read", path, e);
	}
	if (e != GFARM_ERR_NO_ERROR)
		rv = -gfarm_error_to_errno(e);
	else
		fp->time_updated = 0;
	return (rv);
}

static int
gfarm2fs_write(const char *path, const char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	gfarm_off_t off;
	int rv;
	struct gfarm2fs_file *fp = get_filep(fi);

	(void) path;
	e = gfs_pio_seek(fp->gf, offset, GFARM_SEEK_SET, &off);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000030, OP_WRITE,
					"gfs_pio_seek", path, e);
	} else {
		e = gfs_pio_write(fp->gf, buf, size, &rv);
		gfarm2fs_check_error(GFARM_MSG_2000031, OP_WRITE,
					"gfs_pio_write", path, e);
	}
	if (e != GFARM_ERR_NO_ERROR)
		rv = -gfarm_error_to_errno(e);
	else
		fp->time_updated = 0;
	return (rv);
}

static int
gfarm2fs_statfs(const char *path, struct statvfs *stbuf)
{
	gfarm_error_t e;
	gfarm_off_t used, avail, files;

	/* XXX FIXME - path should be passed to the Gfarm API */
	e = gfs_statfs(&used, &avail, &files);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000032, OP_STATFS,
					"gfs_statfs", path, e);
		return (-gfarm_error_to_errno(e));
	}
	stbuf->f_bsize = 1024;	/* XXX */
	stbuf->f_frsize = 1024;	/* XXX */
	stbuf->f_blocks = used + avail;
	stbuf->f_bfree = avail;
	stbuf->f_bavail = avail;
	stbuf->f_files = files;
	stbuf->f_ffree = -1;	/* XXX */
	stbuf->f_favail = -1;	/* XXX */
	stbuf->f_fsid = 298;	/* XXX */
	stbuf->f_flag = 0;	/* XXX */
	stbuf->f_namemax = GFS_MAXNAMLEN;
	return (0);
}

static int
gfarm2fs_release(const char *path, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	struct gfarm2fs_file *fp = get_filep(fi);

	(void) path;
	gfarm2fs_open_file_remove(fp);
	e = gfs_pio_close(fp->gf);
	gfarm2fs_check_error(GFARM_MSG_2000033, OP_RELEASE,
				"gfs_pio_close", path, e);
	if (fp->time_updated) {
		struct gfarmized_path gfarmized;

		e = gfarmize_path(path, &gfarmized);
		if (e != GFARM_ERR_NO_ERROR) {
			gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_RELEASE,
			    "gfarmize_path", path, e);
		} else {
#ifdef HAVE_GFS_LUTIMES
			e = gfs_lutimes(gfarmized.path, fp->gt);
#else
			e = gfs_utimes(gfarmized.path, fp->gt);
#endif
			gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_RELEASE,
			    "gfs_lutimes", gfarmized.path, e);
			free_gfarmized_path(&gfarmized);
		}
	}
	free(fp);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
	gfarm_error_t e;

	(void) path;
	if (isdatasync) {
		e = gfs_pio_datasync(get_filep(fi)->gf);
		gfarm2fs_check_error(GFARM_MSG_2000034, OP_FSYNC,
					"gfs_pio_datasync", path, e);
	} else {
		e = gfs_pio_sync(get_filep(fi)->gf);
		gfarm2fs_check_error(GFARM_MSG_2000035, OP_FSYNC,
					"gfs_pio_sync", path, e);
	}
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_flush(const char *path, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	struct gfarm2fs_file *fp = get_filep(fi);

	if (IS_WRITABLE(fp->flags)) {
		e = gfs_pio_flush(fp->gf);
		gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_FLUSH,
		    "gfs_pio_flush", path, e);
		return (-gfarm_error_to_errno(e));
	} else
		return (0);
}

#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
static int
gfarm2fs_setxattr(const char *path, const char *name, const char *value,
	size_t size, int flags)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;
	int gflags;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000082, OP_SETXATTR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	switch (flags) {
	case 0:
		gflags = 0;
		break;
#ifdef GFS_XATTR_CREATE
	case XATTR_CREATE:
		gflags = GFS_XATTR_CREATE;
		break;
#endif
#ifdef GFS_XATTR_REPLACE
	case XATTR_REPLACE:
		gflags = GFS_XATTR_REPLACE;
		break;
#endif
	default:
		gflags = flags; /* XXX FIXME */
		break;
	}
	/* include gfs_lsetxattr() */
	e = gfarm2fs_xattr_set(gfarmized.path, name, value, size, gflags);
	gfarm2fs_check_error(GFARM_MSG_2000036, OP_SETXATTR,
			     "gfs_lsetxattr", gfarmized.path, e);
	free_gfarmized_path(&gfarmized);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_getxattr(const char *path, const char *name, char *value, size_t size)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;
	size_t s = size;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000083, OP_GETXATTR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	/* include gfs_lgetxattr_cached() */
	e = gfarm2fs_xattr_get(gfarmized.path, name, value, &s);
	if (e == GFARM_ERR_NO_SUCH_OBJECT) {
		/*
		 * NOTE: man getxattr(2) says that ENOATTR must be returned,
		 * but it's not defined in header files.
		 * We return -ENODATA because "strace ls -l /" is below.
		 *   open("/", O_RDONLY|O_NONBLOCK|O_LARGEFILE|O_DIRECTORY) = 3
		 *   ....
		 *   getxattr("/etc", "system.posix_acl_access"..., 0x0, 0)
		 *     = -1 ENODATA (No data available)
		 *   getxattr("/etc", "system.posix_acl_default"..., 0x0, 0)
		 *     = -1 ENODATA (No data available)
		 *   ...
		 */
		free_gfarmized_path(&gfarmized);
		return (-ENODATA);
	}
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000037, OP_GETXATTR,
				     "gfs_lgetxattr_cached", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}
	free_gfarmized_path(&gfarmized);
	return (s);
}

static int
gfarm2fs_listxattr(const char *path, char *list, size_t size)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;
	size_t s = size;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000084, OP_LISTXATTR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_llistxattr(gfarmized.path, list, &s);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000038, OP_LISTXATTR,
				     "gfs_llistxattr", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}
	free_gfarmized_path(&gfarmized);
	return (s);
}

static int
gfarm2fs_removexattr(const char *path, const char *name)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000085, OP_REMOVEXATTR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	/* include gfs_lremovexattr() */
	e = gfarm2fs_xattr_remove(gfarmized.path, name);
	gfarm2fs_check_error(GFARM_MSG_2000039, OP_REMOVEXATTR,
			     "gfs_lremovexattr", gfarmized.path, e);
	free_gfarmized_path(&gfarmized);
	if (e == GFARM_ERR_NO_SUCH_OBJECT)
		return (-ENODATA);
	else
		return (-gfarm_error_to_errno(e));
}
#endif /* HAVE_SYS_XATTR_H && ENABLE_XATTR */

static struct fuse_operations gfarm2fs_oper = {
    .getattr	= gfarm2fs_getattr,
    .fgetattr	= gfarm2fs_fgetattr,
    .access	= gfarm2fs_access,
    .readlink	= gfarm2fs_readlink,
#ifndef USE_GETDIR
    .opendir	= gfarm2fs_opendir,
    .readdir	= gfarm2fs_readdir,
    .releasedir	= gfarm2fs_releasedir,
#else
    .getdir	= gfarm2fs_getdir,
#endif
    .mknod	= gfarm2fs_mknod,
    .mkdir	= gfarm2fs_mkdir,
    .symlink	= gfarm2fs_symlink,
    .unlink	= gfarm2fs_unlink,
    .rmdir	= gfarm2fs_rmdir,
    .rename	= gfarm2fs_rename,
    .link	= gfarm2fs_link,
    .chmod	= gfarm2fs_chmod,
    .chown	= gfarm2fs_chown,
    .truncate	= gfarm2fs_truncate,
    .ftruncate	= gfarm2fs_ftruncate,
    .utimens	= gfarm2fs_utimens,
    .create	= gfarm2fs_create,
    .open	= gfarm2fs_open,
    .read	= gfarm2fs_read,
    .write	= gfarm2fs_write,
    .statfs	= gfarm2fs_statfs,
    .release	= gfarm2fs_release,
    .fsync	= gfarm2fs_fsync,
    .flush	= gfarm2fs_flush,
#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
    .setxattr	= gfarm2fs_setxattr,
    .getxattr	= gfarm2fs_getxattr,
    .listxattr	= gfarm2fs_listxattr,
    .removexattr = gfarm2fs_removexattr,
#endif
};

/***
 *** for cached mode
 ***/

static void
uncache_parent(const char *path)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e = parent_path(path, &gfarmized);

	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_2000086, "parent_path(%s): %s",
			    path, gfarm_error_string(e));
		return;
	}
	gfs_stat_cache_purge(gfarmized.path);
	free_gfarmized_path(&gfarmized);
}

static void
uncache_path(const char *path)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e = gfarmize_path(path, &gfarmized);

	if (e != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_2000087, "gfarmize_path(%s): %s",
			    path, gfarm_error_string(e));
		return;
	}
	gfs_stat_cache_purge(gfarmized.path);
	free_gfarmized_path(&gfarmized);
}

static int
gfarm2fs_mknod_cached(const char *path, mode_t mode, dev_t rdev)
{
	int rv = gfarm2fs_mknod(path, mode, rdev);

	if (rv == 0)
		uncache_parent(path);
	return (rv);
}

static int
gfarm2fs_mkdir_cached(const char *path, mode_t mode)
{
	int rv = gfarm2fs_mkdir(path, mode);

	if (rv == 0)
		uncache_parent(path);
	return (rv);
}

static int
gfarm2fs_unlink_cached(const char *path)
{
	int rv = gfarm2fs_unlink(path);

	if (rv == 0) {
		uncache_path(path);
		uncache_parent(path);
	}
	return (rv);
}

static int
gfarm2fs_rmdir_cached(const char *path)
{
	int rv = gfarm2fs_rmdir(path);

	if (rv == 0) {
		uncache_path(path);
		uncache_parent(path);
	}
	return (rv);
}

static int
gfarm2fs_symlink_cached(const char *old, const char *to)
{
	int rv = gfarm2fs_symlink(old, to);

	if (rv == 0)
		uncache_parent(to);
	return (rv);
}

static int
gfarm2fs_rename_cached(const char *from, const char *to)
{
	int rv = gfarm2fs_rename(from, to);
	struct gfs_stat st;

	if (rv == 0) {
		uncache_path(from);
		uncache_parent(from);
		uncache_path(to);
		uncache_parent(to);

		/* try to replicate the destination file just in case */
		if (gfs_lstat_cached(to, &st) == GFARM_ERR_NO_ERROR) {
			if (GFARM_S_ISREG(st.st_mode))
				gfarm2fs_replicate(to, NULL);
			gfs_stat_free(&st);
		}
	}
	return (rv);
}

static int
gfarm2fs_link_cached(const char *from, const char *to)
{
	int rv = gfarm2fs_link(from, to);

	if (rv == 0)
		uncache_parent(to);
	return (rv);
}

static int
gfarm2fs_chmod_cached(const char *path, mode_t mode)
{
	int rv = gfarm2fs_chmod(path, mode);

	if (rv == 0)
		uncache_path(path);
	return (rv);
}

static int
gfarm2fs_chown_cached(const char *path, uid_t uid, gid_t gid)
{
	int rv = gfarm2fs_chown(path, uid, gid);

	if (rv == 0)
		uncache_path(path);
	return (rv);
}

static int
gfarm2fs_truncate_cached(const char *path, off_t size)
{
	int rv = gfarm2fs_truncate(path, size);

	if (rv == 0)
		uncache_path(path);
	gfarm2fs_replicate(path, NULL);
	return (rv);
}

static int
gfarm2fs_ftruncate_cached(const char *path, off_t size,
			struct fuse_file_info *fi)
{
	int rv = gfarm2fs_ftruncate(path, size, fi);

	if (rv == 0)
		uncache_path(path);
	return (rv);
}

static int
gfarm2fs_utimens_cached(const char *path, const struct timespec ts[2])
{
	int rv = gfarm2fs_utimens(path, ts);

	if (rv == 0)
		uncache_path(path);
	return (rv);
}

static int
gfarm2fs_create_cached(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int rv = gfarm2fs_create(path, mode, fi);

	if (rv == 0)
		uncache_parent(path);
	return (rv);
}

static int
gfarm2fs_open_cached(const char *path, struct fuse_file_info *fi)
{
	int rv = gfarm2fs_open(path, fi);

	if (rv == 0)
		uncache_path(path);
	return (rv);
}

static int
gfarm2fs_write_cached(const char *path, const char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	int rv = gfarm2fs_write(path, buf, size, offset, fi);

	if (rv == 0)
		uncache_path(path);
	return (rv);
}

static int
gfarm2fs_release_cached(const char *path, struct fuse_file_info *fi)
{
	int rv = gfarm2fs_release(path, fi);

	if (rv == 0 && ((fi->flags & O_ACCMODE) == O_WRONLY ||
			(fi->flags & O_ACCMODE) == O_RDWR ||
			(fi->flags & O_TRUNC) != 0))
		uncache_path(path);
	gfarm2fs_replicate(path, fi);
	return (rv);
}

#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
static int
gfarm2fs_setxattr_cached(const char *path, const char *name, const char *value,
	size_t size, int flags)
{
	int rv = gfarm2fs_setxattr(path, name, value, size, flags);

	if (rv == 0)
		uncache_path(path);
	return (rv);
}

static int
gfarm2fs_removexattr_cached(const char *path, const char *name)
{
	int rv = gfarm2fs_removexattr(path, name);

	if (rv == 0)
		uncache_path(path);
	return (rv);
}

#endif /* HAVE_SETXATTR && ENABLE_XATTR */

static struct fuse_operations gfarm2fs_cached_oper = {
    .getattr	= gfarm2fs_getattr,
    .fgetattr	= gfarm2fs_fgetattr,
    .access	= gfarm2fs_access,
    .readlink	= gfarm2fs_readlink,
#ifndef USE_GETDIR
    .opendir	= gfarm2fs_opendir,
    .readdir	= gfarm2fs_readdir,
    .releasedir	= gfarm2fs_releasedir,
#else
    .getdir	= gfarm2fs_getdir,
#endif
    .mknod	= gfarm2fs_mknod_cached,
    .mkdir	= gfarm2fs_mkdir_cached,
    .symlink	= gfarm2fs_symlink_cached,
    .unlink	= gfarm2fs_unlink_cached,
    .rmdir	= gfarm2fs_rmdir_cached,
    .rename	= gfarm2fs_rename_cached,
    .link	= gfarm2fs_link_cached,
    .chmod	= gfarm2fs_chmod_cached,
    .chown	= gfarm2fs_chown_cached,
    .truncate	= gfarm2fs_truncate_cached,
    .ftruncate	= gfarm2fs_ftruncate_cached,
    .utimens	= gfarm2fs_utimens_cached,
    .create	= gfarm2fs_create_cached,
    .open	= gfarm2fs_open_cached,
    .read	= gfarm2fs_read,
    .write	= gfarm2fs_write_cached,
    .statfs	= gfarm2fs_statfs,
    .release	= gfarm2fs_release_cached,
    .fsync	= gfarm2fs_fsync,
    .flush	= gfarm2fs_flush,
#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
    .setxattr	= gfarm2fs_setxattr_cached,
    .getxattr	= gfarm2fs_getxattr,
    .listxattr	= gfarm2fs_listxattr,
    .removexattr = gfarm2fs_removexattr_cached,
#endif
};

/***
 *** main
 ***/

#ifdef HAVE_GFARM_SCHEDULE_CACHE_DUMP
void
debug_handler(int signo)
{
	/* XXX this function is not really async-signal-safe */
	gfarm_schedule_cache_dump();
}
#endif

static void
setup_dumper(void)
{
#ifdef HAVE_GFARM_SCHEDULE_CACHE_DUMP
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = debug_handler;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGUSR2, &sa, NULL);
#endif
}

/* KEY_GFARM2FS_OPT uses in "template has a format" case.
 * This has no meaning except for just marker. */
enum {
	KEY_GFARM2FS_OPT,
	KEY_F,
	KEY_D,
	KEY_VERSION,
	KEY_HELP,
	KEY_FIX_ACL,
	KEY_DISABLE_ACL,
	KEY_ENABLE_CACHED_ID,
	KEY_GENUINE_NLINK,
	KEY_DISABLE_GENUINE_NLINK,
};

#define GFARM2FS_OPT(t, p, v) \
	{ t, offsetof(struct gfarm2fs_param, p), v }

static struct fuse_opt gfarm2fs_opts[] = {
	GFARM2FS_OPT("gfs_stat_timeout=%lf", cache_timeout, KEY_GFARM2FS_OPT),
	GFARM2FS_OPT("-E %lf", cache_timeout, KEY_GFARM2FS_OPT),
	/* GFARM2FS_OPT("use_stderr", use_syslog, 0), */
	GFARM2FS_OPT("syslog=%s", facility, KEY_GFARM2FS_OPT),
	GFARM2FS_OPT("loglevel=%s", loglevel, KEY_GFARM2FS_OPT),
	GFARM2FS_OPT("ncopy=%d", ncopy, KEY_GFARM2FS_OPT),
	GFARM2FS_OPT("copy_limit=%d", copy_limit, KEY_GFARM2FS_OPT),
	FUSE_OPT_KEY("-f", KEY_F),
	FUSE_OPT_KEY("-d", KEY_D),
	FUSE_OPT_KEY("debug", KEY_D),
	FUSE_OPT_KEY("-V", KEY_VERSION),
	FUSE_OPT_KEY("--version", KEY_VERSION),
	FUSE_OPT_KEY("-h", KEY_HELP),
	FUSE_OPT_KEY("--help", KEY_HELP),
	FUSE_OPT_KEY("fix_acl", KEY_FIX_ACL),
	FUSE_OPT_KEY("disable_acl", KEY_DISABLE_ACL), /* for debug */
	FUSE_OPT_KEY("enable_cached_id", KEY_ENABLE_CACHED_ID), /* for debug */
	FUSE_OPT_KEY("genuine_nlink", KEY_GENUINE_NLINK),
	FUSE_OPT_KEY("disable_genuine_nlink", KEY_DISABLE_GENUINE_NLINK),
	GFARM2FS_OPT("auto_uid_min=%d", auto_uid_min, KEY_GFARM2FS_OPT),
	GFARM2FS_OPT("auto_uid_max=%d", auto_uid_max, KEY_GFARM2FS_OPT),
	GFARM2FS_OPT("auto_gid_min=%d", auto_gid_min, KEY_GFARM2FS_OPT),
	GFARM2FS_OPT("auto_gid_max=%d", auto_gid_max, KEY_GFARM2FS_OPT),
	FUSE_OPT_END
};

static void
usage(const char *progname, struct gfarm2fs_param *paramsp)
{
	fprintf(stderr,
"usage: %s mountpoint [options]\n"
"\n"
"general options:\n"
"    -o opt,[opt...]         mount options\n"
"    -h   --help             print help\n"
"    -V   --version          print version\n"
"\n"
"GFARM2FS options:\n"
"    -o syslog=facility      syslog facility (default: %s)\n"
"    -o loglevel=priority    syslog priority level\n"
"                            (default: log_level directive in gfarm2.conf)\n"
"    -E T                    cache timeout for gfs_stat (default: 1.0 sec.)\n"
"    -o gfs_stat_timeout=T   same -E option\n"
"    -o ncopy=N              number of copies\n"
"                            (default: 0 - disable replication)\n"
"    -o copy_limit=N         maximum number of concurrent copy creations\n"
"                            (default: %d)\n"
"    -o disable_genuine_nlink use faked st_nlink\n"
"    -o auto_uid_min=N       minimum UID automatically assigned (default: %d)\n"
"    -o auto_uid_max=N       maximum UID automatically assigned (default: %d)\n"
"    -o auto_gid_min=N       minimum GID automatically assigned (default: %d)\n"
"    -o auto_gid_max=N       maximum GID automatically assigned (default: %d)\n"
		"\n", progname,
		GFARM2FS_SYSLOG_FACILITY_DEFAULT,
		paramsp->copy_limit,
		paramsp->auto_uid_min,
		paramsp->auto_uid_max,
		paramsp->auto_gid_min,
		paramsp->auto_gid_max);
}

static int
gfarm2fs_fuse_main(struct fuse_args *args, struct fuse_operations *fo)
{
#if FUSE_VERSION >= 26
	return (fuse_main(args->argc, args->argv, fo, NULL));
#else
	return (fuse_main(args->argc, args->argv, fo));
#endif
}

#ifdef HAVE_BUG_OF_FUSE_OPT_PARSE_ON_NETBSD /* NetBSD-5.1 and before */
struct gfarm2fs_param *paramsp;
#endif

static int
gfarm2fs_opt_proc(void *data, const char *arg, int key,
			struct fuse_args *outargs)
{
	char *s;

#ifndef HAVE_BUG_OF_FUSE_OPT_PARSE_ON_NETBSD
	struct gfarm2fs_param *paramsp = data;
#endif

	switch (key) {
	case FUSE_OPT_KEY_OPT: /* -?, -o opt, --opt */
		if (memcmp(arg, "subdir=", 7) == 0) {
			s = strdup(arg + 7);
			if (s != NULL)
				paramsp->subdir = s;
		}
		return (1); /* through */
	case FUSE_OPT_KEY_NONOPT:
		if (!paramsp->mount_point)
			paramsp->mount_point = arg;
		return (1); /* through */
	case KEY_F:
		paramsp->foreground = 1;
		return (1); /* through */
	case KEY_D:
		paramsp->debug = 1;
		return (1); /* through */
	case KEY_FIX_ACL:
		paramsp->fix_acl = 1;
		return (0);
	case KEY_DISABLE_ACL:
		paramsp->disable_acl = 1;
		return (0);
	case KEY_ENABLE_CACHED_ID:
		paramsp->enable_cached_id = 1;
		return (0);
	case KEY_DISABLE_GENUINE_NLINK:
		paramsp->genuine_nlink = 0;
		return (0);
	case KEY_VERSION:
		fprintf(stderr, "GFARM2FS version %s\n", VERSION);
#if FUSE_VERSION >= 25
		fuse_opt_add_arg(outargs, "--version");
		gfarm2fs_fuse_main(outargs, &gfarm2fs_oper);
#endif
		exit(0);
	case KEY_HELP:
		usage(outargs->argv[0], paramsp);
		fuse_opt_add_arg(outargs, "-ho");
		gfarm2fs_fuse_main(outargs, &gfarm2fs_oper);
		exit(1);
	default:
		return (0);
	}
}

int
main(int argc, char *argv[])
{
	struct fuse_operations *operation_mode = &gfarm2fs_cached_oper;
	gfarm_error_t e;
	int ret_fuse_main;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	int syslog_priority;
	int syslog_facility = -1;

	struct gfarm2fs_param params = {
		.mount_point = NULL,
		.subdir = NULL,
		.foreground = 0,
		.debug = 0,
		.cache_timeout = -1.0,
		.use_syslog = 1,
		.facility = NULL,
		.loglevel = NULL,
		.ncopy = 0,
		.disable_acl = 0,      /* for debug */
		.enable_cached_id = 0, /* for debug */
		.genuine_nlink = 1,
		.fix_acl = 0,
		.auto_uid_min = 70000,
		.auto_uid_max = 79999,
		.auto_gid_min = 70000,
		.auto_gid_max = 79999,
#ifdef HAVE_GFS_REPLICATE_FILE_TO
		.copy_limit = 10
#else /* version 2.3.X */
		.copy_limit = 0
#endif
	};
#ifdef HAVE_BUG_OF_FUSE_OPT_PARSE_ON_NETBSD
	paramsp = &params;
#endif

	umask(0);
	e = gfarm_initialize(&argc, &argv);
	if (e != GFARM_ERR_NO_ERROR) {
		fprintf(stderr, "%s: %s\n", *argv, gfarm_error_string(e));
		exit(1);
	}

	if (fuse_opt_parse(&args, &params, gfarm2fs_opts,
			   gfarm2fs_opt_proc) == -1) {
		fprintf(stderr, "failed to parse option\n");
		exit(1);
	}
	/*
	 * specify '-s' option to disable multithreaded operations
	 * libgfarm is not thread-safe for now
	 */
	fuse_opt_add_arg(&args, "-s");
#if FUSE_VERSION >= 28
	/* -o atomic_o_trunc required to overwrite a "lost all replica" file */
	fuse_opt_add_arg(&args, "-oatomic_o_trunc");
#endif
	/* use inum in Gfarm */
	fuse_opt_add_arg(&args, "-ouse_ino");
	if (params.mount_point == NULL) {
		fprintf(stderr, "missing mountpoint\n");
		fprintf(stderr, "see `%s -h' for usage\n", program_name);
		exit(1);
	}
	mount_point = params.mount_point;
	gfarm2fs_record_mount_point(mount_point, params.subdir);

	if (params.foreground || params.debug) {
		params.use_syslog = 0; /* use stderr */
		if (params.loglevel == NULL) {
			syslog_priority = gflog_syslog_name_to_priority(
			    GFARM2FS_SYSLOG_PRIORITY_DEBUG);
			gflog_set_priority_level(syslog_priority);
		}
	}
	if (params.loglevel != NULL) {
		syslog_priority =
		    gflog_syslog_name_to_priority(params.loglevel);
		if (syslog_priority == -1) {
			fprintf(stderr, "invalid loglevel: `%s'\n",
			    params.loglevel);
			fprintf(stderr, "see `%s -h' for usage\n",
			    program_name);
			exit(1);
		}
		gflog_set_priority_level(syslog_priority);
	}
	gflog_set_identifier(program_name);
	gflog_auth_set_verbose(1);

	if (params.use_syslog) {
		syslog_facility = gflog_syslog_name_to_facility(
		    params.facility != NULL ? params.facility :
		    GFARM2FS_SYSLOG_FACILITY_DEFAULT);
		if (syslog_facility == -1) {
			fprintf(stderr, "invalid facility: `%s'\n",
				params.facility);
			fprintf(stderr, "see `%s -h' for usage\n",
				program_name);
			exit(1);
		}
	}

	if (params.cache_timeout > 0.0) {
		gfs_stat_cache_expiration_set(params.cache_timeout*1000.0);
	} else if (params.cache_timeout == 0.0) {
		gfs_stat_cache_enable(0); /* disable cache */
		operation_mode = &gfarm2fs_oper;
	}

	if (params.genuine_nlink)
		get_nlink = get_genuine_nlink;

	/* end of setting params */

	gfarm2fs_replicate_init(&params);
	gfarm2fs_open_file_init();
	gfarm2fs_xattr_init(&params);
	gfarm2fs_id_init(&params);

	setup_dumper();

	if (params.use_syslog) /* just before fuse_main */
		gflog_syslog_open(LOG_PID, syslog_facility);

	ret_fuse_main = gfarm2fs_fuse_main(&args, operation_mode);
	fuse_opt_free_args(&args);

	gfarm2fs_replicate_final();
	free(params.subdir);
	free(params.facility);
	free(params.loglevel);

	return (ret_fuse_main);
}
