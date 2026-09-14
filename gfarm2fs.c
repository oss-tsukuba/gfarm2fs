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
#include <sys/time.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <limits.h>
#include <pthread.h>
#include <assert.h>
#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif /* HAVE_SYS_XATTR_H */

#if !defined(S_IFDIR) && defined(__S_IFDIR)
/*
 * XXX Is this really necessary?
 * At least CentOS 5.0 and all NetBSD releases don't need this #define.
 */
#define S_IFDIR	__S_IFDIR
#endif /* !defined(S_IFDIR) && defined(__S_IFDIR) */

/*
 * fuse.h requres that _FILE_OFFSET_BITS is defined in any case, but
 * AC_SYS_LARGEFILE does not define it on a 64bit platform like x86_64
 * since it is not necessary.  To avoid this problem we define it here.
 */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif /* _FILE_OFFSET_BITS */

#ifdef HAVE_FUSE3
#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 1)
#else /* HAVE_FUSE3 */
#define FUSE_USE_VERSION FUSE_MAKE_VERSION(2, 6)
#endif /* HAVE_FUSE3 */
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
		if (ret_errno == EINVAL || &fuse_opname[0] == &OP_RELEASE[0]) { \
			gflog_error(msgNo, syslog_fmt, fuse_opname, \
				gfarm_funcname, mount_point, \
				path_prefix, gfarm_path + path_offset, \
				gfarm_error_string(gfarm_e)); \
		} else if (ret_errno != ENOENT && ret_errno != ENOTSUP) { \
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
#endif /* 0 */
static const char OP_READLINK[] = "READLINK";
static const char OP_OPENDIR[] = "OPENDIR";
static const char OP_READDIR[] = "READDIR";
static const char OP_RELEASEDIR[] = "RELEASEDIR";
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
#define IS_SUBDIR(p)	(strncmp(p, gfarm2fs_subdir, gfarm2fs_subdir_len) == 0)

static void
open_file_lock_init(struct gfarm2fs_file *fp)
{
	int rv;
	rv = pthread_rwlock_init(&fp->lock, NULL);
	assert(rv == 0);
}

static void
open_file_lock_destroy(struct gfarm2fs_file *fp)
{
	int rv;
	rv = pthread_rwlock_destroy(&fp->lock);
	assert(rv == 0);
}

static void
open_file_rdlock(struct gfarm2fs_file *fp)
{
	int rv;
	rv = pthread_rwlock_rdlock(&fp->lock);
	assert(rv == 0);
}

static void
open_file_wrlock(struct gfarm2fs_file *fp)
{
	int rv;
	rv = pthread_rwlock_wrlock(&fp->lock);
	assert(rv == 0);
}

static void
open_file_unlock(struct gfarm2fs_file *fp)
{
	int rv;
	rv = pthread_rwlock_unlock(&fp->lock);
	assert(rv == 0);
}

static void
gfarm2fs_record_mount_point(const char *mpoint, const char *subdir)
{
	char buf[PATH_MAX];
	struct gfs_stat st;
	gfarm_error_t e;

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
		gflog_error(GFARM_MSG_2000113,
		    "no memory to allocate subdir \"%s\"", subdir);
		exit(1);
	}
	if ((e = gfs_stat(gfarm2fs_subdir, &st)) != GFARM_ERR_NO_ERROR) {
		gflog_error(GFARM_MSG_2000125, "%s: %s",
		    gfarm2fs_subdir, gfarm_error_string(e));
		exit(1);
	} else if (!GFARM_S_ISDIR(st.st_mode)) {
		e = GFARM_ERR_NOT_A_DIRECTORY;
		gflog_error(GFARM_MSG_2000126, "%s: %s",
		    gfarm2fs_subdir, gfarm_error_string(e));
		exit(1);
	}
	gfs_stat_free(&st);
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
	const char *start;
	const char *slash;
	size_t len;

	if (IS_SUBDIR(p))
		p += gfarm2fs_subdir_len;
	if (p[0] == '/')
		p++;
	if (strncmp(p, gfarm_path_prefix, GFARM_PATH_PREFIX_LEN) == 0) {
		/* "/.gfarm/host:port/path" -> "gfarm://host:port/path" */
		sz = strlen(p)
		    - GFARM_PATH_PREFIX_LEN + 2 + GFARM_URL_PREFIX_LENGTH + 1;
		GFARM_MALLOC_ARRAY(gfarmized->path, sz);
		if (gfarmized->path == NULL)
			return (GFARM_ERR_NO_MEMORY);
		snprintf(gfarmized->path, sz, "%s//%s",
		    GFARM_URL_PREFIX, p + GFARM_PATH_PREFIX_LEN);
		gfarmized->alloced = 1;

		start = gfarmized->path + GFARM_URL_PREFIX_LENGTH + 2;
		slash = strchr(start, '/');
		len = slash != NULL ? (size_t)(slash - start) : strlen(start);
		GFARM_MALLOC_ARRAY(gfarmized->metadb, len + 1);
		if (gfarmized->metadb == NULL) {
			free(gfarmized->path);
			return (GFARM_ERR_NO_MEMORY);
		}
		memcpy(gfarmized->metadb, start, len);
		gfarmized->metadb[len] = '\0';
		return (GFARM_ERR_NO_ERROR);
	}
	gfarmized->alloced = 0;
	gfarmized->path = (char *)path; /* UNCONST */
	gfarmized->metadb = NULL;
	return (GFARM_ERR_NO_ERROR);
}

void
free_gfarmized_path(struct gfarmized_path *gfarmized)
{
	if (gfarmized->alloced)
		free(gfarmized->path);
	free(gfarmized->metadb);
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

/*
 * convert oldpath for symlink(3) to gfarm://-style URL,
 * but only for the following style:
 *	/MOUNT/POINT/.gfarm/host:port/PATH/NAME
 */
static gfarm_error_t
gfarmize_symlink_old(const char *old, struct gfarmized_path *gfarmized_old)
{
	gfarmized_old->metadb = NULL;
	if (gfarm_is_url(old)) {
		gfarmized_old->path = (char *)old;	/* UNCONST */
		gfarmized_old->alloced = 0;
		return (GFARM_ERR_NO_ERROR);
	}

	/* is "/MOUNT/POINT/.gfarm/host:port/PATH/NAME" ? */
	if (strncmp(old, gfarm2fs_path_prefix, gfarm2fs_path_prefix_len) == 0) {
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
	    strncmp(old, gfarm2fs_realpath_prefix,
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
	struct gfs_stat st_gfmd, *st_gfmdp = st_inp;

	/* assert(st_outp); */

	open_file_rdlock(fp);

	/* get atime, mtime and size from gfsd */
	e = gfs_pio_stat(fp->gf, st_outp); /* include gfs_fstat() */
	if (e != GFARM_ERR_NO_ERROR) {
		open_file_unlock(fp);
		return (e);
	}

	/*
	 * If atime or mtime is updated by UTIMENS, the timestamp is
	 * retrieved from gfmd.
	 *
	 * Do not use the gfsd atime before the file has been read.
	 * Likewise, do not use the gfsd mtime before the file has
	 * been written. Reuse the timestamp from gfmd when the
	 * corresponding I/O has not occurred.
	 */
	if (fp->atime_updated || !fp->read_occurred ||
	    fp->mtime_updated || !fp->write_occurred) {
		/* use atime and mtime from gfmd */
		/* use size from gfsd */

		if (st_gfmdp == NULL) {
			e = gfs_fstat(fp->gf, &st_gfmd); /* from gfmd */
			if (e != GFARM_ERR_NO_ERROR) {
				gfs_stat_free(st_outp);
				open_file_unlock(fp);
				return (e);
			}
			st_gfmdp = &st_gfmd;
		}
		if (fp->atime_updated || !fp->read_occurred)
			st_outp->st_atimespec = st_gfmdp->st_atimespec;
		if (fp->mtime_updated || !fp->write_occurred)
			st_outp->st_mtimespec = st_gfmdp->st_mtimespec;
		if (st_gfmdp == &st_gfmd)
			gfs_stat_free(&st_gfmd);
	}
	open_file_unlock(fp);
	return (GFARM_ERR_NO_ERROR);
}

/***
 *** operations without stat cache invalidation
 ***/

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

	/*
	 * gfarm2fs_getattr and gfarm2fs_release may be called simultaneously
	 * after write-close.
	 * If there is no this lock, the filesize will be wrong.
	 */
	gfarm2fs_open_file_table_rdlock();
	e = gfs_lstat_cached(gfarmized.path, &st);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_open_file_table_unlock();
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
	if ((fp = gfarm2fs_open_file_lookup_unlocked(&gfarmized, st.st_ino))
	    != NULL) {
		struct gfs_stat st2;

		e = gfarm2fs_fstat(fp, &st, &st2);
		if (e != GFARM_ERR_NO_ERROR) {
			gfarm2fs_open_file_table_unlock();
			gfs_stat_free(&st);
			gfarm2fs_check_error(GFARM_MSG_2000046, OP_GETATTR,
				"gfs_pio_stat", gfarmized.path, e);
			free_gfarmized_path(&gfarmized);
			return (-gfarm_error_to_errno(e));
		}
		gfs_stat_free(&st);
		st = st2;
	}
	gfarm2fs_open_file_table_unlock();
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
	struct gfarmized_path gfarmized;
	struct gfs_stat st;
	struct gfarm2fs_file *fp = get_filep(fi);
	gfarm_error_t e;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_FGETATTR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfarm2fs_fstat(fp, NULL, &st);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000002, OP_FGETATTR,
					"gfs_pio_stat", gfarmized.path, e);
		return (-gfarm_error_to_errno(e));
	}

	copy_gfs_stat(gfarmized.path, stbuf, &st);
	gfs_stat_free(&st);
	free_gfarmized_path(&gfarmized);
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
#endif /* 0 */
}

static int
timeval_cmp(const struct timeval *t1, const struct timeval *t2)
{
	if (t1->tv_sec > t2->tv_sec)
		return (1);
	if (t1->tv_sec < t2->tv_sec)
		return (-1);
	if (t1->tv_usec > t2->tv_usec)
		return (1);
	if (t1->tv_usec < t2->tv_usec)
		return (-1);
	return (0);
}

#define SECOND_BY_MICROSEC	1000000

static void
timeval_normalize(struct timeval *t)
{
	long n;

	if (t->tv_usec >= SECOND_BY_MICROSEC) {
		n = t->tv_usec / SECOND_BY_MICROSEC;
		t->tv_usec -= n * SECOND_BY_MICROSEC;
		t->tv_sec += n;
	} else if (t->tv_usec < 0) {
		n = -t->tv_usec / SECOND_BY_MICROSEC + 1;
		t->tv_usec += n * SECOND_BY_MICROSEC;
		t->tv_sec -= n;
	}
}

static void
timeval_add_microsec(struct timeval *t, long microsec)
{
	t->tv_usec += microsec;
	timeval_normalize(t);
}

static int
timeval_is_expired(const struct timeval *expiration)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	return (timeval_cmp(&now, expiration) > 0);
}

static char *readlink_cache_src = NULL;
static char *readlink_cache_path = NULL;
static pthread_mutex_t readlink_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static void
gfarm2fs_readlink_cache_lock(void)
{
	int rv;

	rv = pthread_mutex_lock(&readlink_cache_mutex);
	assert(rv == 0);
}

static void
gfarm2fs_readlink_cache_unlock(void)
{
	int rv;

	rv = pthread_mutex_unlock(&readlink_cache_mutex);
	assert(rv == 0);
}

/*
 * gfarm2fs_readlink_cache_lock() is required.
 *
 * This keeps the cache valid while it is accessed continuously.
 */
static int
readlink_cache_is_expired()
{
	static struct timeval expiration = { 0, 0 };
	long duration = 200000;	/* 200 millisecond */
	int expired = 0;

	if (timeval_is_expired(&expiration))
		expired = 1;
	gettimeofday(&expiration, NULL);
	timeval_add_microsec(&expiration, duration);

	return (expired);
}

static void
gfarm2fs_readlink_cache_set_unlocked(char *path, char *src)
{
	free(readlink_cache_path);
	readlink_cache_path = path;
	free(readlink_cache_src);
	readlink_cache_src = src;

	readlink_cache_is_expired();  /* update expiration */
}

static void
gfarm2fs_readlink_cache_clear_unlocked(void)
{
	gfarm2fs_readlink_cache_set_unlocked(NULL, NULL);
}

static void
gfarm2fs_readlink_cache_set(char *path, char *src)
{
	gfarm2fs_readlink_cache_lock();
	gfarm2fs_readlink_cache_set_unlocked(path, src);
	gfarm2fs_readlink_cache_unlock();
}

static void
gfarm2fs_readlink_cache_clear(void)
{
	gfarm2fs_readlink_cache_lock();
	gfarm2fs_readlink_cache_clear_unlocked();
	gfarm2fs_readlink_cache_unlock();
}

static int
gfarm2fs_readlink(const char *path, char *buf, size_t size)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;
	char *src;
	char *cache_path;
	size_t len;

	gfarm2fs_readlink_cache_lock();
	if (readlink_cache_path != NULL &&
	    strcmp(readlink_cache_path, path) == 0 &&
	    readlink_cache_src != NULL && !readlink_cache_is_expired()) {
		len = strlen(readlink_cache_src);
		if (len >= size)
			len = size - 1;
		memcpy(buf, readlink_cache_src, len);
		gfarm2fs_readlink_cache_unlock();

		buf[len] = '\0';
		return (0);
	}
	/* Cache miss. */
	gfarm2fs_readlink_cache_clear_unlocked();
	gfarm2fs_readlink_cache_unlock();

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000063, OP_READLINK,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfs_readlink(gfarmized.path, &src);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000004, OP_READLINK,
				     "gfs_readlink", gfarmized.path, e);
		free_gfarmized_path(&gfarmized);
		return (-gfarm_error_to_errno(e));
	}
	e = ungfarmize_path(&src, gfarmized.path);
	free_gfarmized_path(&gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000064, OP_READLINK,
		    "ungfarmize_path", src, GFARM_ERR_NO_MEMORY);
		return (-ENOMEM);
	}

	len = strlen(src);
	if (len >= size)
		len = size - 1;
	memcpy(buf, src, len);
	buf[len] = '\0';

	cache_path = strdup(path);
	if (cache_path == NULL) {
		free(src);
		return (-ENOMEM);
	}
	gfarm2fs_readlink_cache_set(cache_path, src);
	/*
	 * Ownership of cache_path and src is transferred to the cache.
	 * Do not free them here.
	 */

	return (0);
}

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

#ifndef HAVE_FUSE3
/* ----- FUSE2 ----- */
/*
 * Define the FUSE3 flags type so gfarm2fs_readdir has the same interface
 * for FUSE2 and FUSE3.
 */
enum fuse_readdir_flags {
	FUSE_READDIR_DEFAULTS = 0,
	FUSE_READDIR_PLUS = (1 << 0)
};
#endif /* HAVE_FUSE3 */

static int option_disable_readdir_plus;

static int
gfarm2fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	off_t offset, struct fuse_file_info *fi,
	enum fuse_readdir_flags flags)
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
		gfarm2fs_check_error(GFARM_MSG_2000114, OP_READDIR,
				     "gfs_seekdir", path, e2);
	}

	while ((e = gfs_readdir(dp, &de)) == GFARM_ERR_NO_ERROR &&
		de != NULL) {
#ifdef HAVE_FUSE3
		enum fuse_fill_dir_flags fill_flags = 0;
		int have_stat = 0;
#endif

		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_fileno;
		st.st_mode = de->d_type << 12;
#ifdef HAVE_FUSE3
		if (!option_disable_readdir_plus &&
		    (flags & FUSE_READDIR_PLUS) &&
		    strcmp(de->d_name, ".") != 0 &&
		    strcmp(de->d_name, "..") != 0) {
			size_t path_len = strlen(path);
			const char *slash = (path_len == 0 ||
				path[path_len - 1] == '/') ? "" : "/";
			size_t len = path_len + strlen(slash) +
				strlen(de->d_name) + 1;
			char *child_path;

			GFARM_MALLOC_ARRAY(child_path, len);
			if (child_path != NULL) {
				snprintf(child_path, len, "%s%s%s", path, slash,
					de->d_name);
				if (gfarm2fs_getattr(child_path, &st) == 0) {
					gflog_debug(GFARM_MSG_UNFIXED,
						    "readdir_plus: %s",
						    child_path);
					have_stat = 1;
				}
				free(child_path);
			}
		}
		if (have_stat) {
			fill_flags |= FUSE_FILL_DIR_PLUS;
		}
#endif /* HAVE_FUSE3 */
		if (seekdir_works) {
			e2 = gfs_telldir(dp, &off);
			gfarm2fs_check_error(GFARM_MSG_2000115, OP_READDIR,
					     "gfs_telldir", path, e2);
		}
#ifdef HAVE_FUSE3
		if (filler(buf, de->d_name, &st, off, fill_flags))
			break;
#else /* HAVE_FUSE3 */
		if (filler(buf, de->d_name, &st, off))
			break;
#endif /* HAVE_FUSE3 */
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

static int
gfarm2fs_mknod_gfarmized(const struct gfarmized_path *gfarmized,
    mode_t mode, dev_t rdev)
{
	GFS_File gf;
	gfarm_error_t e;

	(void) rdev;
	if (!S_ISREG(mode))
		return (-ENOSYS);

	e = gfs_pio_create(gfarmized->path, GFARM_FILE_WRONLY,
	    mode & GFARM_S_ALLPERM, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000011, OP_MKNOD,
					"gfs_pio_create", gfarmized->path, e);
	} else {
		e = gfs_pio_close(gf);
		gfarm2fs_check_error(GFARM_MSG_2000012, OP_MKNOD,
					"gfs_pio_close", gfarmized->path, e);
	}
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_mkdir_gfarmized(const struct gfarmized_path *gfarmized, mode_t mode)
{
	gfarm_error_t e;

	e = gfs_mkdir(gfarmized->path, mode & GFARM_S_ALLPERM);
	gfarm2fs_check_error(GFARM_MSG_2000013, OP_MKDIR,
				"gfs_mkdir", gfarmized->path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_unlink_gfarmized(const struct gfarmized_path *gfarmized)
{
	gfarm_error_t e;

	e = gfs_unlink(gfarmized->path);
	gfarm2fs_check_error(GFARM_MSG_2000014, OP_UNLINK,
			     "gfs_unlink", gfarmized->path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_rmdir_gfarmized(const struct gfarmized_path *gfarmized)
{
	gfarm_error_t e;

	e = gfs_rmdir(gfarmized->path);
	gfarm2fs_check_error(GFARM_MSG_2000015, OP_RMDIR,
			     "gfs_rmdir", gfarmized->path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_symlink_gfarmized(const struct gfarmized_path *gfarmized_old,
    const struct gfarmized_path *gfarmized_new)
{
	gfarm_error_t e;

	e = gfs_symlink(gfarmized_old->path, gfarmized_new->path);
	gfarm2fs_check_error(GFARM_MSG_2000016, OP_SYMLINK,
			     "gfs_symlink", gfarmized_new->path, e);
	return (-gfarm_error_to_errno(e));
}

static int option_directory_quota_rename_error_exdev;

static int
gfarm2fs_rename_gfarmized(const struct gfarmized_path *from,
    const struct gfarmized_path *to)
{
	gfarm_error_t e;
	e = gfs_rename(from->path, to->path);
	gfarm2fs_check_error(GFARM_MSG_2000017, OP_RENAME,
				"gfs_rename", from->path, e);
	if (option_directory_quota_rename_error_exdev &&
	    e == GFARM_ERR_OPERATION_NOT_SUPPORTED)
		e = GFARM_ERR_CROSS_DEVICE_LINK;
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_link_gfarmized(const struct gfarmized_path *from,
    const struct gfarmized_path *to)
{
	gfarm_error_t e;
	e = gfs_link(from->path, to->path);
	gfarm2fs_check_error(GFARM_MSG_2000018, OP_LINK,
			     "gfs_link", to->path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_chmod_gfarmized(const struct gfarmized_path *gfarmized, mode_t mode)
{
	gfarm_error_t e;

	e = gfs_chmod(gfarmized->path, mode & GFARM_S_ALLPERM);
	gfarm2fs_check_error(GFARM_MSG_2000019, OP_CHMOD,
			     "gfs_chmod", gfarmized->path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_chown_gfarmized(const struct gfarmized_path *gfarmized, uid_t uid,
    gid_t gid)
{
	gfarm_error_t e;
	char *user = NULL, *group = NULL;

	/*
	 * workaround to move files from local storage
	 * return with nothing when changing to myself
	 */
	if ((uid == -1 || uid == getuid()) && (gid == -1 || gid == getgid())) {
		gflog_debug(GFARM_MSG_2000131, "chown: same user and group");
		return (0);
	}

	if (uid != -1 &&
	    ((e = gfarm2fs_get_user(gfarmized->path, uid, &user))
	     != GFARM_ERR_NO_ERROR)) {
		gfarm2fs_check_error(GFARM_MSG_2000093, OP_CHOWN,
				     "gfarm2fs_get_user", gfarmized->path, e);
		goto end;
	}

	if (gid != -1 &&
	    ((e = gfarm2fs_get_group(gfarmized->path, gid, &group))
	     != GFARM_ERR_NO_ERROR)) {
		gfarm2fs_check_error(GFARM_MSG_2000094, OP_CHOWN,
				     "gfarm2fs_get_group", gfarmized->path, e);
		goto end;
	}
#ifdef HAVE_GFS_LCHOWN
	e = gfs_lchown(gfarmized->path, user, group);
	gfarm2fs_check_error(GFARM_MSG_2000020, OP_CHOWN,
			     "gfs_lchown", gfarmized->path, e);
#else /* HAVE_GFS_LCHOWN */
	e = gfs_chown(gfarmized->path, user, group);
	gfarm2fs_check_error(GFARM_MSG_2000020, OP_CHOWN,
			     "gfs_chown", gfarmized->path, e);
#endif /* HAVE_GFS_LCHOWN */
end:
	free(user);
	free(group);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_truncate_gfarmized(const struct gfarmized_path *gfarmized, off_t size)
{
	gfarm_error_t e, e2;
	GFS_File gf;
	int flags = GFARM_FILE_WRONLY;

	if (size == 0)
		flags |= GFARM_FILE_TRUNC;
	e = gfs_pio_open(gfarmized->path, flags, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000021, OP_TRUNCATE,
				     "gfs_pio_open", gfarmized->path, e);
		return (-gfarm_error_to_errno(e));
	}

	e = gfs_pio_truncate(gf, size);
	gfarm2fs_check_error(GFARM_MSG_2000022, OP_TRUNCATE,
			     "gfs_pio_truncate", gfarmized->path, e);
	e2 = gfs_pio_close(gf);
	gfarm2fs_check_error(GFARM_MSG_2000023, OP_TRUNCATE,
			     "gfs_pio_close", gfarmized->path, e2);

	return (-gfarm_error_to_errno(e != GFARM_ERR_NO_ERROR ? e : e2));
}

static int
gfarm2fs_ftruncate_gfarmized(const struct gfarmized_path *gfarmized,
			     off_t size, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	struct gfarm2fs_file *fp = get_filep(fi);

	open_file_wrlock(fp);
	e = gfs_pio_truncate(fp->gf, size);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000024, OP_FTRUNCATE,
		    "gfs_pio_ftruncate", gfarmized->path, e);
	} else {
		/* Forget the pending open-file utime update for mtime. */
		fp->mtime_updated = 0;
	}
	open_file_unlock(fp);
	return (-gfarm_error_to_errno(e));
}

static void
timespec_to_gfarm(const struct timespec ts[2],
		  struct gfarm_timespec gt[2])
{
	int i;

	for (i = 0; i < 2; ++i) {
		gt[i].tv_sec = ts[i].tv_sec;

		if (ts[i].tv_nsec == UTIME_OMIT) {
			gt[i].tv_nsec = GFARM_UTIME_OMIT;
		} else if (ts[i].tv_nsec == UTIME_NOW) {
			gt[i].tv_nsec = GFARM_UTIME_NOW;
		} else {
			gt[i].tv_nsec = ts[i].tv_nsec;
		}
	}
}

static int
gfarm2fs_utimens_gfarmized(const struct gfarmized_path *gfarmized,
    const struct timespec ts[2])
{
	struct gfarm_timespec gt[2];
	gfarm_error_t e;
	struct gfarm2fs_file *fp;
	struct gfs_stat gst;
	struct timespec ts_tmp[2];
	const struct timespec *ts_to_apply = ts;
	struct timeval now;

	e = gfs_lstat_cached(gfarmized->path, &gst);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000117, OP_UTIMENS,
		    "gfs_lstat_cached", gfarmized->path, e);
		return (-gfarm_error_to_errno(e));
	}
	gfarm2fs_open_file_table_rdlock();
	if ((fp = gfarm2fs_open_file_lookup_unlocked(gfarmized, gst.st_ino))
	    != NULL) {
		struct gfs_stat gst2;

		/* To get current correct timestamps during open */
		e = gfarm2fs_fstat(fp, &gst, &gst2);
		if (e != GFARM_ERR_NO_ERROR) {
			gfarm2fs_open_file_table_unlock();
			gfs_stat_free(&gst);
			gfarm2fs_check_error(GFARM_MSG_2000002, OP_UTIMENS,
			    "gfs_pio_stat", gfarmized->path, e);
			return (-gfarm_error_to_errno(e));
		}
		gfs_stat_free(&gst);
		gst = gst2;

		/*
		 * Preserve the current atime and mtime so that
		 * UTIME_OMIT can be applied correctly after
		 * gfs_pio_close() in the RELEASE.
		 */
		if (ts[0].tv_nsec == UTIME_NOW ||
		    ts[1].tv_nsec == UTIME_NOW) {
			gettimeofday(&now, NULL);
		}
		/* atime */
		if (ts[0].tv_nsec == UTIME_OMIT) {
			ts_tmp[0].tv_sec = gst.st_atimespec.tv_sec;
			ts_tmp[0].tv_nsec = gst.st_atimespec.tv_nsec;
		} else if (ts[0].tv_nsec == UTIME_NOW) {
			ts_tmp[0].tv_sec = now.tv_sec;
			ts_tmp[0].tv_nsec = now.tv_usec * 1000;
		} else {
			ts_tmp[0] = ts[0];
		}
		/* mtime */
		if (ts[1].tv_nsec == UTIME_OMIT) {
			ts_tmp[1].tv_sec = gst.st_mtimespec.tv_sec;
			ts_tmp[1].tv_nsec = gst.st_mtimespec.tv_nsec;
		} else if (ts[1].tv_nsec == UTIME_NOW) {
			ts_tmp[1].tv_sec = now.tv_sec;
			ts_tmp[1].tv_nsec = now.tv_usec * 1000;
		} else {
			ts_tmp[1] = ts[1];
		}
		open_file_wrlock(fp);

		timespec_to_gfarm(ts_tmp, fp->gt);
		/*
		 * Keep even UTIME_OMIT values pending: fp->gt contains the
		 * timestamp to restore after close.  A subsequent read/write
		 * cancels only the corresponding pending timestamp.
		 */
		fp->atime_updated = 1;
		fp->mtime_updated = 1;
		open_file_unlock(fp);
		ts_to_apply = ts_tmp;
	}
	gfarm2fs_open_file_table_unlock();
	gfs_stat_free(&gst);
	timespec_to_gfarm(ts_to_apply, gt);
#ifdef HAVE_GFS_LUTIMES
	e = gfs_lutimes(gfarmized->path, gt);
#else /* HAVE_GFS_LUTIMES */
	e = gfs_utimes(gfarmized->path, gt);
#endif /* HAVE_GFS_LUTIMES */
	gfarm2fs_check_error(GFARM_MSG_2000118, OP_UTIMENS,
			     "gfs_lutimes", gfarmized->path, e);
	return (-gfarm_error_to_errno(e));
}

#define IS_WRITABLE(x) (((x) & GFARM_FILE_WRONLY) != 0 || \
			((x) & GFARM_FILE_RDWR) != 0)

static int option_unbuffered;

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
#ifdef GFARM_FILE_APPEND
	if ((open_flags & O_APPEND) != 0)
		gfs_flags |= GFARM_FILE_APPEND;
#endif
#ifdef GFARM_FILE_EXCLUSIVE
	if ((open_flags & O_EXCL) != 0)
		gfs_flags |= GFARM_FILE_EXCLUSIVE;
#endif
#ifdef GFARM_FILE_UNBUFFERED
	if (option_unbuffered)
		/* open(2) and creat(2) should be unbuffered */
		gfs_flags |= GFARM_FILE_UNBUFFERED;
#endif
	return (gfs_flags);
}

static gfarm_error_t
gfarm2fs_file_init_gfarmized(const struct gfarmized_path *gfarmized,
    GFS_File gf, struct gfarm2fs_file **fpp, int flags)
{
	gfarm_error_t e;
	struct gfarm2fs_file *fp;
	struct gfs_stat st;

	e = gfs_lstat_cached(gfarmized->path, &st);
	if (e != GFARM_ERR_NO_ERROR)
		return (e);

	GFARM_MALLOC(fp);
	if (fp) {
		fp->flags = flags;
		fp->gf = gf;
		fp->mtime_updated = 0;
		fp->atime_updated = 0;
		fp->write_occurred = 0;
		fp->read_occurred = 0;
		fp->inum = st.st_ino;
		open_file_lock_init(fp);
		*fpp = fp;
		gfs_stat_free(&st);
		return (GFARM_ERR_NO_ERROR);
	} else {
		gfs_stat_free(&st);
		return (GFARM_ERR_NO_MEMORY);
	}
}

static int
gfarm2fs_create_gfarmized(const struct gfarmized_path *gfarmized, mode_t mode,
    struct fuse_file_info *fi)
{
	struct gfarm2fs_file *fp;
	gfarm_error_t e;
	GFS_File gf;
	int flags;

	flags = gfs_hook_open_flags_gfarmize(fi->flags);
	e = gfs_pio_create(gfarmized->path, flags, mode & GFARM_S_ALLPERM, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000026, OP_CREATE,
				     "gfs_pio_create", gfarmized->path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfarm2fs_file_init_gfarmized(gfarmized, gf, &fp, flags);
	if (e != GFARM_ERR_NO_ERROR) {
		(void)gfs_pio_close(gf);
		gfarm2fs_check_error(GFARM_MSG_2000119, OP_CREATE,
		    "gfarm2fs_file_init_gfarmized", gfarmized->path, e);
		return (-gfarm_error_to_errno(e));
	}

	fi->fh = (unsigned long)fp;
	gfarm2fs_open_file_enter(gfarmized, fp, fi->flags|O_CREAT);
	return (0);
}

static int
gfarm2fs_open_gfarmized(const struct gfarmized_path *gfarmized,
    struct fuse_file_info *fi)
{
	struct gfarm2fs_file *fp;
	GFS_File gf;
	int flags;
	gfarm_error_t e;

	flags = gfs_hook_open_flags_gfarmize(fi->flags);
	e = gfs_pio_open(gfarmized->path, flags, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000027, OP_OPEN,
				     "gfs_pio_open", gfarmized->path, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfarm2fs_file_init_gfarmized(gfarmized, gf, &fp, flags);
	if (e != GFARM_ERR_NO_ERROR) {
		(void)gfs_pio_close(gf);
		gfarm2fs_check_error(GFARM_MSG_2000120, OP_OPEN,
		    "gfarm2fs_file_init_gfarmized", gfarmized->path, e);
		return (-gfarm_error_to_errno(e));
	}

	fi->fh = (unsigned long)fp;
	gfarm2fs_open_file_enter(gfarmized, fp, fi->flags);
	return (0);
}

static int
gfarm2fs_read_gfarmized(const struct gfarmized_path *gfarmized,
	char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	int rv;
	struct gfarm2fs_file *fp = get_filep(fi);

	open_file_wrlock(fp);
	e = gfs_pio_pread(fp->gf, buf, size, offset, &rv);
	gfarm2fs_check_error(GFARM_MSG_2000029, OP_READ,
				"gfs_pio_read", gfarmized->path, e);
	if (e != GFARM_ERR_NO_ERROR)
		rv = -gfarm_error_to_errno(e);
	else {
		/* Forget the pending open-file utime update for atime. */
		fp->atime_updated = 0;
		fp->read_occurred = 1;
	}
	open_file_unlock(fp);
	return (rv);
}

static int
gfarm2fs_write_gfarmized(const struct gfarmized_path *gfarmized,
	const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	int rv;
	struct gfarm2fs_file *fp = get_filep(fi);

	open_file_wrlock(fp);
	e = gfs_pio_pwrite(fp->gf, buf, size, offset, &rv);
	gfarm2fs_check_error(GFARM_MSG_2000031, OP_WRITE,
				"gfs_pio_write", gfarmized->path, e);
	if (e != GFARM_ERR_NO_ERROR)
		rv = -gfarm_error_to_errno(e);
	else {
		/* Forget the pending open-file utime update for mtime. */
		fp->mtime_updated = 0;
		fp->write_occurred = 1;
	}
	open_file_unlock(fp);
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

static void
gfarm2fs_file_free(struct gfarm2fs_file *fp)
{
	open_file_lock_destroy(fp);
	free(fp);
}

static void uncache_path_gfarmized(const struct gfarmized_path *);
static void uncache_parent_gfarmized(const struct gfarmized_path *);

static int
gfarm2fs_release_gfarmized(const struct gfarmized_path *gfarmized,
    struct fuse_file_info *fi)
{
	gfarm_error_t e_close, e_utimes = GFARM_ERR_NO_ERROR;
	struct gfarm2fs_file *fp = get_filep(fi);
	struct gfarm_timespec gt[2];

	/*
	 * gfarm2fs_getattr and gfarm2fs_release may be called simultaneously
	 * after write-close.
	 */
	gfarm2fs_open_file_table_wrlock();
	/*
	 * Purge the stat cache while holding the open_file_table lock.
	 * Before close, getattr uses gfarm2fs_fstat() for this open file.
	 * After close, getattr must obtain fresh attributes from gfmd.
	 */
	uncache_path_gfarmized(gfarmized);

	gfarm2fs_open_file_remove_unlocked(gfarmized, fp);

	open_file_wrlock(fp);
	e_close = gfs_pio_close(fp->gf);
	gfarm2fs_check_error(GFARM_MSG_2000033, OP_RELEASE,
				"gfs_pio_close", gfarmized->path, e_close);

	if (fp->atime_updated || fp->mtime_updated) {
		gt[0] = fp->gt[0];
		gt[1] = fp->gt[1];
		if (!fp->atime_updated)
			gt[0].tv_nsec = GFARM_UTIME_OMIT;
		if (!fp->mtime_updated)
			gt[1].tv_nsec = GFARM_UTIME_OMIT;
#ifdef HAVE_GFS_LUTIMES
		e_utimes = gfs_lutimes(gfarmized->path, gt);
#else /* HAVE_GFS_LUTIMES */
		e_utimes = gfs_utimes(gfarmized->path, gt);
#endif /* HAVE_GFS_LUTIMES */
		gfarm2fs_check_error(GFARM_MSG_2000122, OP_RELEASE,
		    "gfs_lutimes", gfarmized->path, e_utimes);
	}
	open_file_unlock(fp);
	gfarm2fs_file_free(fp);
	gfarm2fs_open_file_table_unlock();
	return (-gfarm_error_to_errno(e_close != GFARM_ERR_NO_ERROR ?
				      e_close : e_utimes));
}

static int
gfarm2fs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	struct gfarm2fs_file *fp = get_filep(fi);

	(void) path;
	/* include gfs_pio.c:flush_internal() */
	if (isdatasync) {
		e = gfs_pio_datasync(fp->gf);
		gfarm2fs_check_error(GFARM_MSG_2000034, OP_FSYNC,
					"gfs_pio_datasync", path, e);
	} else {
		e = gfs_pio_sync(fp->gf);
		gfarm2fs_check_error(GFARM_MSG_2000035, OP_FSYNC,
					"gfs_pio_sync", path, e);
	}
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_flush(const char *path, struct fuse_file_info *fi)
{
	int rv = 0;
	gfarm_error_t e;
	struct gfarm2fs_file *fp = get_filep(fi);

	(void) path;
	open_file_rdlock(fp);
	if (IS_WRITABLE(fp->flags)) {
		e = gfs_pio_flush(fp->gf);
		gfarm2fs_check_error(GFARM_MSG_2000123, OP_FLUSH,
		    "gfs_pio_flush", path, e);
		rv = -gfarm_error_to_errno(e);
	}
	open_file_unlock(fp);
	return (rv);
}

#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
static int
gfarm2fs_setxattr_gfarmized(const struct gfarmized_path *gfarmized,
    const char *name, const char *value, size_t size, int flags)
{
	gfarm_error_t e;
	int gflags;

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
	e = gfarm2fs_xattr_set(gfarmized->path, name, value, size, gflags);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_debug(GFARM_MSG_UNFIXED,
			    "SETXATTR(%s, %s): %s", gfarmized->path, name,
			    gfarm_error_string(e));
		if (e == GFARM_ERR_NO_SUCH_OBJECT && flags == XATTR_REPLACE) {
			;
		} else {
			gfarm2fs_check_error(GFARM_MSG_2000036, OP_SETXATTR,
			    "gfs_lsetxattr", gfarmized->path, e);
		}
	}
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
#ifdef ENOATTR /* for macOS, etc */
		return (-ENOATTR);
#else /* ENOATTR */
		return (-ENODATA);
#endif /* ENOATTR */
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
	size_t s = size, local_size = 0;

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
	local_size = gfarm2fs_xattr_list_local(path,
	    size == 0 ? NULL : list + s, size == 0 ? 0 : size - s);
	if (size > 0 && size < s + local_size) {
		free_gfarmized_path(&gfarmized);
		return (-ERANGE);
	}
	s += local_size;
	free_gfarmized_path(&gfarmized);
	return (s);  /* required size when size == 0 */
}

static int
gfarm2fs_removexattr_gfarmized(const struct gfarmized_path *gfarmized,
    const char *name)
{
	gfarm_error_t e;

	/* include gfs_lremovexattr() */
	e = gfarm2fs_xattr_remove(gfarmized->path, name);
	gfarm2fs_check_error(GFARM_MSG_2000039, OP_REMOVEXATTR,
			     "gfs_lremovexattr", gfarmized->path, e);
	if (e == GFARM_ERR_NO_SUCH_OBJECT) {
#ifdef ENOATTR /* for macOS, etc */
		return (-ENOATTR);
#else /* ENOATTR */
		return (-ENODATA);
#endif /* ENOATTR */
	}
	return (-gfarm_error_to_errno(e));
}

#endif /* HAVE_SYS_XATTR_H && ENABLE_XATTR */

static void
gfarm2fs_destroy(void *user_data)
{
	(void)user_data;
	gfarm2fs_readlink_cache_clear();
}

/***
 *** operations requiring stat cache invalidation
 ***/

static void
uncache_parent_gfarmized(const struct gfarmized_path *gfarmized)
{
	char *parent = gfarm_url_dir(gfarmized->path);

	if (parent == NULL) {
		gflog_error(GFARM_MSG_2000086,
			    "gfarm_url_dir(%s): %s", gfarmized->path,
			    gfarm_error_string(GFARM_ERR_NO_MEMORY));
		return;
	}
	gfs_stat_cache_purge(parent);
	free(parent);
}

static void
uncache_path_gfarmized(const struct gfarmized_path *gfarmized)
{
	gfs_stat_cache_purge(gfarmized->path);
}

static int
gfarm2fs_mknod_uncache(const char *path, mode_t mode, dev_t rdev)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	if (!S_ISREG(mode))
		return (-ENOSYS);

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000067, OP_MKNOD,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_mknod_gfarmized(&gfarmized, mode, rdev);
	/* uncache always to avoid race condition */
	uncache_parent_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_mkdir_uncache(const char *path, mode_t mode)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000068, OP_MKDIR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_mkdir_gfarmized(&gfarmized, mode);
	uncache_parent_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_unlink_uncache(const char *path)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000069, OP_UNLINK,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_unlink_gfarmized(&gfarmized);
	uncache_path_gfarmized(&gfarmized);
	uncache_parent_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_rmdir_uncache(const char *path)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000070, OP_RMDIR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_rmdir_gfarmized(&gfarmized);
	uncache_path_gfarmized(&gfarmized);
	uncache_parent_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_symlink_uncache(const char *old, const char *to)
{
	struct gfarmized_path gfarmized_old, gfarmized_to;
	gfarm_error_t e;
	int rv;

	e = gfarmize_symlink_old(old, &gfarmized_old);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000071, OP_SYMLINK,
				     "gfarmize_symlink_old", old, e);
		return (-gfarm_error_to_errno(e));
	}
	e = gfarmize_path(to, &gfarmized_to);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000092, OP_SYMLINK,
				     "gfarmize_path", to, e);
		free_gfarmized_path(&gfarmized_old);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_symlink_gfarmized(&gfarmized_old, &gfarmized_to);

	gfarm2fs_readlink_cache_clear();
	uncache_path_gfarmized(&gfarmized_to);
	uncache_parent_gfarmized(&gfarmized_to);
	free_gfarmized_path(&gfarmized_to);
	free_gfarmized_path(&gfarmized_old);
	return (rv);
}

static int
gfarm2fs_rename_uncache(const char *from, const char *to)
{
	struct gfarmized_path gfarmized_from, gfarmized_to;
	gfarm_error_t e;
	int rv;
	struct gfs_stat st;

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
	rv = gfarm2fs_rename_gfarmized(&gfarmized_from, &gfarmized_to);

	uncache_path_gfarmized(&gfarmized_from);
	uncache_parent_gfarmized(&gfarmized_from);
	uncache_path_gfarmized(&gfarmized_to);
	uncache_parent_gfarmized(&gfarmized_to);
	if (rv == 0 && gfarm2fs_replicate_enabled()) {
		/* try to replicate the destination file just in case */
		if (gfs_lstat_cached(gfarmized_to.path, &st) ==
		    GFARM_ERR_NO_ERROR) {
			if (GFARM_S_ISREG(st.st_mode))
				gfarm2fs_replicate(to);
			gfs_stat_free(&st);
		}
	}
	free_gfarmized_path(&gfarmized_to);
	free_gfarmized_path(&gfarmized_from);
	return (rv);
}

static int
gfarm2fs_link_uncache(const char *from, const char *to)
{
	struct gfarmized_path gfarmized_from, gfarmized_to;
	gfarm_error_t e;
	int rv;

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
	rv = gfarm2fs_link_gfarmized(&gfarmized_from, &gfarmized_to);

	uncache_path_gfarmized(&gfarmized_from); /* link count changed */
	uncache_parent_gfarmized(&gfarmized_to);
	free_gfarmized_path(&gfarmized_to);
	free_gfarmized_path(&gfarmized_from);
	return (rv);
}

static int
gfarm2fs_chmod_uncache(const char *path, mode_t mode)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000076, OP_CHMOD,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_chmod_gfarmized(&gfarmized, mode);
	uncache_path_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_chown_uncache(const char *path, uid_t uid, gid_t gid)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000077, OP_CHOWN,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_chown_gfarmized(&gfarmized, uid, gid);
	uncache_path_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_truncate_uncache(const char *path, off_t size)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000078, OP_TRUNCATE,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_truncate_gfarmized(&gfarmized, size);
	uncache_path_gfarmized(&gfarmized);
	gfarm2fs_replicate(path);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_ftruncate_uncache(const char *path, off_t size,
			struct fuse_file_info *fi)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_FTRUNCATE,
		    "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_ftruncate_gfarmized(&gfarmized, size, fi);
	uncache_path_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_utimens_uncache(const char *path, const struct timespec ts[2])
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000116, OP_UTIMENS,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_utimens_gfarmized(&gfarmized, ts);
	uncache_path_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_create_uncache(const char *path, mode_t mode,
	struct fuse_file_info *fi)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000080, OP_CREATE,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_create_gfarmized(&gfarmized, mode, fi);
	uncache_parent_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_open_uncache(const char *path, struct fuse_file_info *fi)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000081, OP_OPEN,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_open_gfarmized(&gfarmized, fi);
	uncache_path_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_read_uncache(const char *path, char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_READ,
		    "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_read_gfarmized(&gfarmized, buf, size, offset, fi);
	uncache_path_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_write_uncache(const char *path, const char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_UNFIXED, OP_WRITE,
		    "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_write_gfarmized(&gfarmized, buf, size, offset, fi);
	uncache_path_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_release_uncache(const char *path, struct fuse_file_info *fi)
{
	struct gfarmized_path gfarmized;
	gfarm_error_t e;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000121, OP_RELEASE,
		    "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_release_gfarmized(&gfarmized, fi);
	free_gfarmized_path(&gfarmized);
	gfarm2fs_replicate(path);
	return (rv);
}

#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
static int
gfarm2fs_setxattr_uncache(const char *path, const char *name, const char *value,
	size_t size, int flags)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000082, OP_SETXATTR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_setxattr_gfarmized(&gfarmized, name, value,
	    size, flags);
	uncache_path_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

static int
gfarm2fs_removexattr_uncache(const char *path, const char *name)
{
	gfarm_error_t e;
	struct gfarmized_path gfarmized;
	int rv;

	e = gfarmize_path(path, &gfarmized);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000085, OP_REMOVEXATTR,
				     "gfarmize_path", path, e);
		return (-gfarm_error_to_errno(e));
	}
	rv = gfarm2fs_removexattr_gfarmized(&gfarmized, name);
	uncache_path_gfarmized(&gfarmized);
	free_gfarmized_path(&gfarmized);
	return (rv);
}

#endif /* HAVE_SYS_XATTR_H && ENABLE_XATTR */

/***
 *** fuse2/fuse3 switcher
 ***/

#ifdef HAVE_FUSE3
static void *
gfarm2fs_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;
	cfg->use_ino = 1;
#if 0  /*
	* *** From libfuse(v3)/include/fuse.h ***
	* It is recommended that you not use the hard_remove
	* option. When hard_remove is set, the following libc
	* functions fail on unlinked files (returning errno of
	* ENOENT): read(2), write(2), fsync(2), close(2), f*xattr(2),
	* ftruncate(2), fstat(2), fchmod(2), fchown(2)
	*/
	cfg->hard_remove = 1;
#endif
	return (NULL);
}

static int
gfarm2fs_getattr_f3(const char *path, struct stat *stbuf,
	struct fuse_file_info *fi)
{
	if (fi != NULL)
		return (gfarm2fs_fgetattr(path, stbuf, fi));
	return (gfarm2fs_getattr(path, stbuf));
}

static int
gfarm2fs_readdir_f3(const char *path, void *buf, fuse_fill_dir_t filler,
	off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
	return (gfarm2fs_readdir(path, buf, filler, offset, fi, flags));
}

static int
gfarm2fs_rename_f3(const char *from, const char *to, unsigned int flags)
{
	/* XXX gfs_renameat2() */
	if (flags)
		return (-EINVAL);

	return (gfarm2fs_rename_uncache(from, to));
}

static int
gfarm2fs_chmod_f3(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	return (gfarm2fs_chmod_uncache(path, mode));
}

static int
gfarm2fs_chown_f3(const char *path, uid_t uid, gid_t gid,
	struct fuse_file_info *fi)
{
	return (gfarm2fs_chown_uncache(path, uid, gid));
}

static int
gfarm2fs_truncate_f3(const char *path, off_t size, struct fuse_file_info *fi)
{
	if (fi != NULL)
		return (gfarm2fs_ftruncate_uncache(path, size, fi));
	return (gfarm2fs_truncate_uncache(path, size));
}

static int
gfarm2fs_utimens_f3(const char *path, const struct timespec ts[2],
	struct fuse_file_info *fi)
{
	return (gfarm2fs_utimens_uncache(path, ts));
}

#else /* HAVE_FUSE3  */

static int
gfarm2fs_getattr_f2(const char *path, struct stat *stbuf)
{
	return (gfarm2fs_getattr(path, stbuf));
}

static int
gfarm2fs_readdir_f2(const char *path, void *buf, fuse_fill_dir_t filler,
	off_t offset, struct fuse_file_info *fi)
{
	return (gfarm2fs_readdir(path, buf, filler, offset, fi,
				 FUSE_READDIR_DEFAULTS));
}

static int
gfarm2fs_rename_f2(const char *from, const char *to)
{
	return (gfarm2fs_rename_uncache(from, to));
}

static int
gfarm2fs_chmod_f2(const char *path, mode_t mode)
{
	return (gfarm2fs_chmod_uncache(path, mode));
}

static int
gfarm2fs_chown_f2(const char *path, uid_t uid, gid_t gid)
{
	return (gfarm2fs_chown_uncache(path, uid, gid));
}

static int
gfarm2fs_truncate_f2(const char *path, off_t size)
{
	return (gfarm2fs_truncate_uncache(path, size));
}

static int
gfarm2fs_utimens_f2(const char *path, const struct timespec ts[2])
{
	return (gfarm2fs_utimens_uncache(path, ts));
}
#endif /* HAVE_FUSE3 */

static struct fuse_operations gfarm2fs_oper = {
#ifdef HAVE_FUSE3
    /* ----- FUSE3 ----- */
    .init	= gfarm2fs_init,
    .getattr	= gfarm2fs_getattr_f3,
    .readdir	= gfarm2fs_readdir_f3,
    .rename	= gfarm2fs_rename_f3,
    .chmod	= gfarm2fs_chmod_f3,
    .chown	= gfarm2fs_chown_f3,
    .truncate	= gfarm2fs_truncate_f3,
    .utimens	= gfarm2fs_utimens_f3,
#else
    /* ----- FUSE2 ----- */
    .getattr	= gfarm2fs_getattr_f2,
    .fgetattr	= gfarm2fs_fgetattr,
    .readdir	= gfarm2fs_readdir_f2,
    .rename	= gfarm2fs_rename_f2,
    .chmod	= gfarm2fs_chmod_f2,
    .chown	= gfarm2fs_chown_f2,
    .truncate	= gfarm2fs_truncate_f2,
    .ftruncate	= gfarm2fs_ftruncate_uncache,
    .flag_utime_omit_ok = 1,
    .utimens	= gfarm2fs_utimens_f2,
#endif /* HAVE_FUSE3 */
    /* ----- Common for FUSE2 and FUSE3 ----- */
    .destroy	= gfarm2fs_destroy,
    .access	= gfarm2fs_access,
    .readlink	= gfarm2fs_readlink,
    .opendir	= gfarm2fs_opendir,
    .releasedir	= gfarm2fs_releasedir,
    .mknod	= gfarm2fs_mknod_uncache,
    .mkdir	= gfarm2fs_mkdir_uncache,
    .symlink	= gfarm2fs_symlink_uncache,
    .unlink	= gfarm2fs_unlink_uncache,
    .rmdir	= gfarm2fs_rmdir_uncache,
    .link	= gfarm2fs_link_uncache,
    .create	= gfarm2fs_create_uncache,
    .open	= gfarm2fs_open_uncache,
    .read	= gfarm2fs_read_uncache,
    .write	= gfarm2fs_write_uncache,
    .statfs	= gfarm2fs_statfs,
    .release	= gfarm2fs_release_uncache,
    .fsync	= gfarm2fs_fsync,
    .flush	= gfarm2fs_flush,
#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
    .setxattr	= gfarm2fs_setxattr_uncache,
    .getxattr	= gfarm2fs_getxattr,
    .listxattr	= gfarm2fs_listxattr,
    .removexattr = gfarm2fs_removexattr_uncache,
#endif /* HAVE_SYS_XATTR_H && ENABLE_XATTR */
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
	KEY_DIRECTORY_QUOTA_RENAME_ERROR_EXDEV,
	KEY_UNBUFFERED,
	KEY_DISABLE_READDIR_PLUS,
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
	FUSE_OPT_KEY("directory_quota_rename_error_exdev",
	    KEY_DIRECTORY_QUOTA_RENAME_ERROR_EXDEV),
	FUSE_OPT_KEY("unbuffered", KEY_UNBUFFERED),
	FUSE_OPT_KEY("disable_readdir_plus", KEY_DISABLE_READDIR_PLUS),
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
"                            legacy option; use gfncopy instead\n"
"                            -s option is automatically added when N >= 2\n"
"    -o copy_limit=N         maximum number of concurrent copy creations\n"
"                            (default: %d)\n"
"    -o disable_genuine_nlink use faked st_nlink\n"
"    -o directory_quota_rename_error_exdev enable client-side directory move\n"
"    -o unbuffered           do not use buffering in libgfarm\n"
"    -o disable_readdir_plus disable FUSE READDIR_PLUS\n"
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
#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 6)
	return (fuse_main(args->argc, args->argv, fo, NULL));
#else /* FUSE_VERSION >= FUSE_MAKE_VERSION(2, 6) */
	return (fuse_main(args->argc, args->argv, fo));
#endif /* FUSE_VERSION >= FUSE_MAKE_VERSION(2, 6) */
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
		if (strncmp(arg, "subdir=", 7) == 0) {
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
	case KEY_DIRECTORY_QUOTA_RENAME_ERROR_EXDEV:
		paramsp->directory_quota_rename_error_exdev = 1;
		return (0);
	case KEY_UNBUFFERED:
		paramsp->unbuffered = 1;
		return (0);
	case KEY_DISABLE_READDIR_PLUS:
		paramsp->disable_readdir_plus = 1;
		return (0);
	case KEY_VERSION:
		fprintf(stderr, "Gfarm2fs version " VERSION "\n");
#ifdef HAVE_GFARM_VERSION
		fprintf(stderr, "Gfarm version %s\n", gfarm_version());
#endif
#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 5)
		fuse_opt_add_arg(outargs, "--version");
		gfarm2fs_fuse_main(outargs, &gfarm2fs_oper);
#endif
		exit(0);
	case KEY_HELP:
		usage(outargs->argv[0], paramsp);
#ifdef HAVE_FUSE3
		fuse_opt_add_arg(outargs, "--help");
		outargs->argv[0][0] = '\0';
#else /* HAVE_FUSE3 */
		fuse_opt_add_arg(outargs, "-ho");
#endif /* HAVE_FUSE3 */
		gfarm2fs_fuse_main(outargs, &gfarm2fs_oper);
		exit(1);
	default:
		return (0);
	}
}

int
main(int argc, char *argv[])
{
	struct fuse_operations *operation_mode = &gfarm2fs_oper;
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
		.unbuffered = 0,
		.disable_readdir_plus = 0,
		.auto_uid_min = 60000,
		.auto_uid_max = 64999,
		.auto_gid_min = 60000,
		.auto_gid_max = 64999,
#ifdef HAVE_GFS_REPLICATE_FILE_TO
		.copy_limit = 10
#else /* version 2.3.X */
		.copy_limit = 0
#endif /* HAVE_GFS_REPLICATE_FILE_TO */
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
#ifndef HAVE_GFS_PROFILE_LOCK
	/* specify '-s' option to disable multithreaded operations */
	fuse_opt_add_arg(&args, "-s");
#else
	/*
	 * replicate.c is not thread-safe when replication of two or more
	 * copies is requested.  Disable FUSE multithreading in this case.
	 */
	if (params.ncopy >= 2)
		fuse_opt_add_arg(&args, "-s");
#endif

#ifndef HAVE_FUSE3
	/* ----- FUSE2 ----- */
	/* SEE ALSO: gfarm2fs_init() for FUSE3 */
#if FUSE_VERSION >= FUSE_MAKE_VERSION(2, 8)
	/* -o atomic_o_trunc required to overwrite a "lost all replica" file */
	fuse_opt_add_arg(&args, "-oatomic_o_trunc");
#endif
	/* use inum in Gfarm */
	fuse_opt_add_arg(&args, "-ouse_ino");
#if 0  /*
	* *** From libfuse(v3)/include/fuse.h ***
	* It is recommended that you not use the hard_remove
	* option. When hard_remove is set, the following libc
	* functions fail on unlinked files (returning errno of
	* ENOENT): read(2), write(2), fsync(2), close(2), f*xattr(2),
	* ftruncate(2), fstat(2), fchmod(2), fchown(2)
	*/
	/* immediate removal */
	fuse_opt_add_arg(&args, "-ohard_remove");
#endif
#endif /* HAVE_FUSE3 */

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
	}

	if (params.genuine_nlink)
		get_nlink = get_genuine_nlink;

	option_directory_quota_rename_error_exdev =
	    params.directory_quota_rename_error_exdev;

	option_unbuffered = params.unbuffered;
	option_disable_readdir_plus = params.disable_readdir_plus;

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
	e = gfarm_terminate();
	if (e != GFARM_ERR_NO_ERROR)
		gflog_error(GFARM_MSG_2000124, "gfarm_terminate: %s",
			    gfarm_error_string(e));
	free(params.subdir);
	free(params.facility);
	free(params.loglevel);

	return (ret_fuse_main);
}
