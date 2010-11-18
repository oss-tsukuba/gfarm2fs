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
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <stddef.h>
#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

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
#include <replicate.h>
#include <open_file.h>
#include "gfarm2fs_msg_enums.h"

/* for old interface */
#undef USE_GETDIR

/* XXX FIXME */
#define GFS_DEV		((dev_t)-1)
#define GFS_BLKSIZE	8192
#define STAT_BLKSIZ	512	/* for st_blocks */

char *program_name = "gfarm2fs";

static char GFARM2FS_SYSLOG_FACILITY_DEFAULT[] = "local0";
static char GFARM2FS_SYSLOG_PRIORITY_DEFAULT[] = "notice";
static char GFARM2FS_SYSLOG_PRIORITY_DEBUG[] = "debug";

static const char *mount_point;

#define PATH_LEN_LIMIT 200
static char *syslog_fmt = "<%s:%s>[%s]%s%s: %s";
static char *trunc_str = "(...)";

#define gfarm2fs_check_error(msgNo, fuse_opname, gfarm_funcname, \
			     gfarm_path, gfarm_e) \
{ \
	if (gfarm_e != GFARM_ERR_NO_ERROR) { \
		int ret_errno    = gfarm_error_to_errno(gfarm_e); \
		int path_len     = strlen(gfarm_path); \
		int path_offset  = 0; \
		char *path_prefix = ""; \
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

static char OP_GETATTR[] = "GETATTR";
static char OP_FGETATTR[] = "FGETATTR";
#if 0 /* XXX Part of invoking gfs_access() is defined "if 0" now */
static char OP_ACCESS[] = "ACCESS";
#endif
static char OP_READLINK[] = "READLINK";
#ifndef USE_GETDIR
static char OP_OPENDIR[] = "OPENDIR";
static char OP_READDIR[] = "READDIR";
static char OP_RELEASEDIR[] = "RELEASEDIR";
#else /* USE_GETDIR */
static char OP_GETDIR[] = "GETDIR";
#endif /* USE_GETDIR */
static char OP_MKNOD[] = "MKNOD";
static char OP_MKDIR[] = "MKDIR";
static char OP_UNLINK[] = "UNLINK";
static char OP_RMDIR[] = "RMDIR";
static char OP_SYMLINK[] = "SYMLINK";
static char OP_RENAME[] = "RENAME";
static char OP_LINK[] = "LINK";
static char OP_CHMOD[] = "CHMOD";
static char OP_CHOWN[] = "CHOWN";
static char OP_TRUNCATE[] = "TRUNCATE";
static char OP_FTRUNCATE[] = "FTRUNCATE";
static char OP_UTIME[] = "UTIME";
static char OP_CREATE[] = "CREATE";
static char OP_OPEN[] = "OPEN";
static char OP_READ[] = "READ";
static char OP_WRITE[] = "WRITE";
static char OP_STATFS[] = "STATFS";
static char OP_RELEASE[] = "RELEASE";
static char OP_FSYNC[] = "FSYNC";
#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
static char OP_SETXATTR[] = "SETXATTR";
static char OP_GETXATTR[] = "GETXATTR";
static char OP_LISTXATTR[] = "LISTXATTR";
static char OP_REMOVEXATTR[] = "REMOVEXATTR";
#endif /* HAVE_SYS_XATTR_H && ENABLE_XATTR */

static uid_t
get_uid(char *user)
{
	struct passwd *pwd;
	char *luser;

	if (strcmp(gfarm_get_global_username(), user) == 0)
		return (getuid()); /* my own file */

	/*
	 * XXX - this interface will be changed soon to support
	 * multiple gfmds.
	 */
	if (gfarm_global_to_local_username(user, &luser)
	    == GFARM_ERR_NO_ERROR) {
		pwd = getpwnam(luser);
		free(luser);
		if (pwd != NULL)
			return (pwd->pw_uid);
	}
	/* cannot conver to a local account */
	return (0);
}

static int
get_gid(char *group)
{
	struct group *grp;
	char *lgroup;

	/*
	 * XXX - this interface will be changed soon to support
	 * multiple gfmds.
	 */
	if (gfarm_global_to_local_groupname(group, &lgroup)
	    == GFARM_ERR_NO_ERROR) {
		grp = getgrnam(lgroup);
		free(lgroup);
		if (grp != NULL)
			return (grp->gr_gid);
	}
	/* cannot conver to a local group */
	return (0);
}

static int
get_nlink(struct gfs_stat *st)
{
	/* XXX FIXME */
	return (GFARM_S_ISDIR(st->st_mode) ? 32000 : st->st_nlink);
}

static void
copy_gfs_stat(struct stat *dst, struct gfs_stat *src)
{
	memset(dst, 0, sizeof(*dst));
	dst->st_dev = GFS_DEV;
	dst->st_ino = src->st_ino;
	dst->st_mode = src->st_mode;
	dst->st_nlink = get_nlink(src);
	dst->st_uid = get_uid(src->st_user);
	dst->st_gid = get_gid(src->st_group);
	dst->st_size = src->st_size;
	dst->st_blksize = GFS_BLKSIZE;
	dst->st_blocks = (src->st_size + STAT_BLKSIZ - 1) / STAT_BLKSIZ;
	dst->st_atime = src->st_atimespec.tv_sec;
	dst->st_mtime = src->st_mtimespec.tv_sec;
	dst->st_ctime = src->st_ctimespec.tv_sec;
}

static int
gfarm2fs_getattr(const char *path, struct stat *stbuf)
{
	struct gfs_stat st;
	GFS_File gf;
	gfarm_error_t e;

	e = gfs_lstat_cached(path, &st);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000001, OP_GETATTR,
					"gfs_lstat_cached", path, e);
		return (-gfarm_error_to_errno(e));
	}
	if ((gf = gfarm2fs_open_file_lookup(st.st_ino)) != NULL) {
		gfs_stat_free(&st);
		e = gfs_pio_stat(gf, &st);
		if (e != GFARM_ERR_NO_ERROR) {
			gfarm2fs_check_error(GFARM_MSG_2000046, OP_GETATTR,
				"gfs_pio_stat", path, e);
			return (-gfarm_error_to_errno(e));
		}
	}
	copy_gfs_stat(stbuf, &st);
	gfs_stat_free(&st);
	return (0);
}

static inline GFS_File
get_filep(struct fuse_file_info *fi)
{
	return (GFS_File) (uintptr_t) fi->fh;
}

static int
gfarm2fs_fgetattr(const char *path, struct stat *stbuf,
	struct fuse_file_info *fi)
{
	struct gfs_stat st;
	gfarm_error_t e;

	e = gfs_pio_stat(get_filep(fi), &st);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000002, OP_FGETATTR,
					"gfs_pio_stat", path, e);
		return (-gfarm_error_to_errno(e));
	}

	copy_gfs_stat(stbuf, &st);
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

	e = gfs_access(path, mask);
	gfarm2fs_check_error(GFARM_MSG_2000003, OP_ACCESS,
				"gfs_access", path, e);
	return (-gfarm_error_to_errno(e));
#endif
}

static int
gfarm2fs_readlink(const char *path, char *buf, size_t size)
{
	gfarm_error_t e;
	char *src;
	size_t len;

	e = gfs_readlink(path, &src);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000004, OP_READLINK,
					"gfs_readlink", path, e);
		return (-gfarm_error_to_errno(e));
	}

	len = strlen(src);
	if (len >= size)
		len = size - 1;
	memcpy(buf, src, len);
	buf[len] = '\0';
	free(src);
	return (0);
}

#ifndef USE_GETDIR
static int
gfarm2fs_opendir(const char *path, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	GFS_Dir dp;

	e = gfs_opendir_caching(path, &dp);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000005, OP_OPENDIR,
					"gfs_opendir_caching", path, e);
		return (-gfarm_error_to_errno(e));
	}

	fi->fh = (unsigned long) dp;
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
	/* gfarm_off_t off = 0; */
	gfarm_error_t e;

	(void) path;
	/* XXX gfs_seekdir(dp, offset); */
	while ((e = gfs_readdir(dp, &de)) == GFARM_ERR_NO_ERROR &&
		de != NULL) {
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_fileno;
		st.st_mode = de->d_type << 12;
		/* XXX (void)gfs_telldir(dp, &off); */
		if (filler(buf, de->d_name, &st, 0))
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
	GFS_Dir dp;
	struct gfs_dirent *de;

	e = gfs_opendir_caching(path, &dp);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000008, OP_GETDIR,
					"gfs_opendir_caching", path, e);
		return (-gfarm_error_to_errno(e));
	}

	while ((e = gfs_readdir(dp, &de)) == GFARM_ERR_NO_ERROR &&
		de != NULL) {
		if (filler(h, de->d_name, de->d_type << 12, de->d_fileno))
			break;
	}
	gfarm2fs_check_error(GFARM_MSG_2000009, OP_GETDIR,
				"gfs_readdir", path, e);

	e2 = gfs_closedir(dp);
	gfarm2fs_check_error(GFARM_MSG_2000010, OP_GETDIR,
				"gfs_closedir", path, e2);

	if (e == GFARM_ERR_NO_ERROR)
		e = e2;

	return (-gfarm_error_to_errno(e));
}
#endif

static int
gfarm2fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	GFS_File gf;
	gfarm_error_t e;

	if (!S_ISREG(mode))
		return (-ENOSYS);

	e = gfs_pio_create(path, GFARM_FILE_WRONLY, mode & GFARM_S_ALLPERM,
		&gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000011, OP_MKNOD,
					"gfs_pio_create", path, e);
	} else {
		e = gfs_pio_close(gf);
		gfarm2fs_check_error(GFARM_MSG_2000012, OP_MKNOD,
					"gfs_pio_close", path, e);
	}

	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_mkdir(const char *path, mode_t mode)
{
	gfarm_error_t e;

	e = gfs_mkdir(path, mode & GFARM_S_ALLPERM);
	gfarm2fs_check_error(GFARM_MSG_2000013, OP_MKDIR,
				"gfs_mkdir", path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_unlink(const char *path)
{
	gfarm_error_t e;

	e = gfs_unlink(path);
	gfarm2fs_check_error(GFARM_MSG_2000014, OP_UNLINK,
				"gfs_unlink", path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_rmdir(const char *path)
{
	gfarm_error_t e;

	e = gfs_rmdir(path);
	gfarm2fs_check_error(GFARM_MSG_2000015, OP_RMDIR,
				"gfs_rmdir", path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_symlink(const char *from, const char *to)
{
	gfarm_error_t e;

	e = gfs_symlink(from, to);
	gfarm2fs_check_error(GFARM_MSG_2000016, OP_SYMLINK,
				"gfs_symlink", to, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_rename(const char *from, const char *to)
{
	gfarm_error_t e;

	e = gfs_rename(from, to);
	gfarm2fs_check_error(GFARM_MSG_2000017, OP_RENAME,
				"gfs_rename", from, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_link(const char *from, const char *to)
{
	gfarm_error_t e;

	e = gfs_link(from, to);
	gfarm2fs_check_error(GFARM_MSG_2000018, OP_LINK,
				"gfs_link", to, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_chmod(const char *path, mode_t mode)
{
	gfarm_error_t e;

	e = gfs_chmod(path, mode & GFARM_S_ALLPERM);
	gfarm2fs_check_error(GFARM_MSG_2000019, OP_CHMOD,
				"gfs_chmod", path, e);
	return (-gfarm_error_to_errno(e));
}

/* returned string should be free'ed if it is not NULL */
static char *
get_user(uid_t uid)
{
	struct passwd *pwd;
	char *guser;

	if (uid == getuid())
		return (strdup(gfarm_get_global_username()));

	/* use the user map file to identify the global user */
	if ((pwd = getpwuid(uid)) != NULL &&
	    gfarm_local_to_global_username(pwd->pw_name, &guser)
	    == GFARM_ERR_NO_ERROR)
		return (guser);

	return (NULL);
}

/* returned string should be free'ed if it is not NULL */
static char *
get_group(gid_t gid)
{
	struct group *grp;
	char *ggroup;

	/* use the group map file to identify the global group */
	if ((grp = getgrgid(gid)) != NULL &&
	    gfarm_local_to_global_groupname(grp->gr_name, &ggroup)
	    == GFARM_ERR_NO_ERROR)
		return (ggroup);

	return (NULL);
}

static int
gfarm2fs_chown(const char *path, uid_t uid, gid_t gid)
{
	gfarm_error_t e;
	char *user, *group;

	if (uid == -1)
		user = NULL;
	else if ((user = get_user(uid)) == NULL)
		return (-EPERM);

	if (gid == -1)
		group = NULL;
	else if ((group = get_group(gid)) == NULL) {
		if (user != NULL)
			free(user);
		return (-EPERM);
	}
	e = gfs_chown(path, user, group);
	gfarm2fs_check_error(GFARM_MSG_2000020, OP_CHOWN,
				"gfs_chown", path, e);
	if (user != NULL)
		free(user);
	if (group != NULL)
		free(group);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_truncate(const char *path, off_t size)
{
	gfarm_error_t e, e2;
	GFS_File gf;

	e = gfs_pio_open(path, GFARM_FILE_WRONLY, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000021, OP_TRUNCATE,
					"gfs_pio_open", path, e);
		return (-gfarm_error_to_errno(e));
	}

	e = gfs_pio_truncate(gf, size);
	gfarm2fs_check_error(GFARM_MSG_2000022, OP_TRUNCATE,
				"gfs_pio_truncate", path, e);
	e2 = gfs_pio_close(gf);
	gfarm2fs_check_error(GFARM_MSG_2000023, OP_TRUNCATE,
				"gfs_pio_close", path, e2);

	return (-gfarm_error_to_errno(e != GFARM_ERR_NO_ERROR ? e : e2));
}

static int
gfarm2fs_ftruncate(const char *path, off_t size,
		   struct fuse_file_info *fi)
{
	gfarm_error_t e;

	(void) path;
	e = gfs_pio_truncate(get_filep(fi), size);
	gfarm2fs_check_error(GFARM_MSG_2000024, OP_FTRUNCATE,
				"gfs_pio_ftruncate", path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_utime(const char *path, struct utimbuf *buf)
{
	struct gfarm_timespec gt[2];
	gfarm_error_t e;

	if (buf != NULL) {
		gt[0].tv_sec = buf->actime;
		gt[0].tv_nsec = 0;
		gt[1].tv_sec = buf->modtime;
		gt[1].tv_nsec = 0;
	}
	e = gfs_utimes(path, gt);
	gfarm2fs_check_error(GFARM_MSG_2000025, OP_UTIME,
				"gfs_utime", path, e);
	return (-gfarm_error_to_errno(e));
}

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

static int
gfarm2fs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	GFS_File gf;
	int flags;

	flags = gfs_hook_open_flags_gfarmize(fi->flags);
	e = gfs_pio_create(path, flags, mode & GFARM_S_ALLPERM, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000026, OP_CREATE,
					"gfs_pio_create", path, e);
		return (-gfarm_error_to_errno(e));
	}

	fi->fh = (unsigned long) gf;
	gfarm2fs_open_file_enter(gf, fi->flags|O_CREAT);
	return (0);
}

static int
gfarm2fs_open(const char *path, struct fuse_file_info *fi)
{
	GFS_File gf;
	int flags;
	gfarm_error_t e;

	flags = gfs_hook_open_flags_gfarmize(fi->flags);
	e = gfs_pio_open(path, flags, &gf);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000027, OP_OPEN,
					"gfs_pio_open", path, e);
		return (-gfarm_error_to_errno(e));
	}

	fi->fh = (unsigned long) gf;
	gfarm2fs_open_file_enter(gf, fi->flags);
	return (0);
}

static int
gfarm2fs_read(const char *path, char *buf, size_t size, off_t offset,
	struct fuse_file_info *fi)
{
	gfarm_error_t e;
	gfarm_off_t off;
	int rv;

	(void) path;
	e = gfs_pio_seek(get_filep(fi), offset, GFARM_SEEK_SET, &off);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000028, OP_READ,
					"gfs_pio_seek", path, e);
	} else {
		e = gfs_pio_read(get_filep(fi), buf, size, &rv);
		gfarm2fs_check_error(GFARM_MSG_2000029, OP_READ,
					"gfs_pio_read", path, e);
	}

	if (e != GFARM_ERR_NO_ERROR)
		rv = -gfarm_error_to_errno(e);

	return (rv);
}

static int
gfarm2fs_write(const char *path, const char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	gfarm_off_t off;
	int rv;

	(void) path;
	e = gfs_pio_seek(get_filep(fi), offset, GFARM_SEEK_SET, &off);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000030, OP_WRITE,
					"gfs_pio_seek", path, e);
	} else {
		e = gfs_pio_write(get_filep(fi), buf, size, &rv);
		gfarm2fs_check_error(GFARM_MSG_2000031, OP_WRITE,
					"gfs_pio_write", path, e);
	}

	if (e != GFARM_ERR_NO_ERROR)
		rv = -gfarm_error_to_errno(e);

	return (rv);
}

static int
gfarm2fs_statfs(const char *path, struct statvfs *stbuf)
{
	gfarm_error_t e;
	gfarm_off_t used, avail, files;

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

	(void) path;
	gfarm2fs_open_file_remove(get_filep(fi));
	e = gfs_pio_close(get_filep(fi));
	gfarm2fs_check_error(GFARM_MSG_2000033, OP_RELEASE,
				"gfs_pio_close", path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
	gfarm_error_t e;

	(void) path;
	if (isdatasync) {
		e = gfs_pio_datasync(get_filep(fi));
		gfarm2fs_check_error(GFARM_MSG_2000034, OP_FSYNC,
					"gfs_pio_datasync", path, e);
	} else {
		e = gfs_pio_sync(get_filep(fi));
		gfarm2fs_check_error(GFARM_MSG_2000035, OP_FSYNC,
					"gfs_pio_sync", path, e);
	}
	return (-gfarm_error_to_errno(e));
}

#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
static int
gfarm2fs_setxattr(const char *path, const char *name, const char *value,
	size_t size, int flags)
{
	gfarm_error_t e;

	e = gfs_setxattr(path, name, value, size, flags);
	gfarm2fs_check_error(GFARM_MSG_2000036, OP_SETXATTR,
				"gfs_setxattr", path, e);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_getxattr(const char *path, const char *name, char *value, size_t size)
{
	gfarm_error_t e;
	size_t s = size;

	e = gfs_getxattr(path, name, value, &s);
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
		return (-ENODATA);
	}
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000037, OP_GETXATTR,
				     "gfs_getxattr", path, e);
		return (-gfarm_error_to_errno(e));
	} else
		return (s);
}

static int
gfarm2fs_listxattr(const char *path, char *list, size_t size)
{
	gfarm_error_t e;
	size_t s = size;

	e = gfs_listxattr(path, list, &s);
	if (e != GFARM_ERR_NO_ERROR) {
		gfarm2fs_check_error(GFARM_MSG_2000038, OP_LISTXATTR,
					"gfs_listxattr", path, e);
		return (-gfarm_error_to_errno(e));
	} else
		return (s);
}

static int
gfarm2fs_removexattr(const char *path, const char *name)
{
	gfarm_error_t e;

	e = gfs_removexattr(path, name);
	gfarm2fs_check_error(GFARM_MSG_2000039, OP_REMOVEXATTR,
				"gfs_removexattr", path, e);
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
    .utime	= gfarm2fs_utime,
    .create	= gfarm2fs_create,
    .open	= gfarm2fs_open,
    .read	= gfarm2fs_read,
    .write	= gfarm2fs_write,
    .statfs	= gfarm2fs_statfs,
    .release	= gfarm2fs_release,
    .fsync	= gfarm2fs_fsync,
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
	char *p = strdup(path), *b;

	if (p == NULL) {
		gflog_error(GFARM_MSG_2000040, \
			    "strdup(%s): Cannot uncached parent dir " \
			    "because not enough memory", \
			    path);
		return;
	}

	b = (char *)gfarm_path_dir_skip(p); /* UNCONST */
	if (b > p && b[-1] == '/') {
		b[-1] = '\0';
		gfs_stat_cache_purge(p);
	}
	free(p);
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
		gfs_stat_cache_purge(path);
		uncache_parent(path);
	}
	return (rv);
}

static int
gfarm2fs_rmdir_cached(const char *path)
{
	int rv = gfarm2fs_rmdir(path);

	if (rv == 0) {
		gfs_stat_cache_purge(path);
		uncache_parent(path);
	}
	return (rv);
}

static int
gfarm2fs_symlink_cached(const char *from, const char *to)
{
	int rv = gfarm2fs_symlink(from, to);

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
		gfs_stat_cache_purge(from);
		uncache_parent(from);
		gfs_stat_cache_purge(to);
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
		gfs_stat_cache_purge(path);
	return (rv);
}

static int
gfarm2fs_chown_cached(const char *path, uid_t uid, gid_t gid)
{
	int rv = gfarm2fs_chown(path, uid, gid);

	if (rv == 0)
		gfs_stat_cache_purge(path);
	return (rv);
}

static int
gfarm2fs_truncate_cached(const char *path, off_t size)
{
	int rv = gfarm2fs_truncate(path, size);

	if (rv == 0)
		gfs_stat_cache_purge(path);
	gfarm2fs_replicate(path, NULL);
	return (rv);
}

static int
gfarm2fs_ftruncate_cached(const char *path, off_t size,
			struct fuse_file_info *fi)
{
	int rv = gfarm2fs_ftruncate(path, size, fi);

	if (rv == 0)
		gfs_stat_cache_purge(path);
	return (rv);
}

static int
gfarm2fs_utime_cached(const char *path, struct utimbuf *buf)
{
	int rv = gfarm2fs_utime(path, buf);

	if (rv == 0)
		gfs_stat_cache_purge(path);
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
		gfs_stat_cache_purge(path);
	return (rv);
}

static int
gfarm2fs_write_cached(const char *path, const char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	int rv = gfarm2fs_write(path, buf, size, offset, fi);

	if (rv == 0)
		gfs_stat_cache_purge(path);
	return (rv);
}

static int
gfarm2fs_release_cached(const char *path, struct fuse_file_info *fi)
{
	int rv = gfarm2fs_release(path, fi);

	if (rv == 0 && ((fi->flags & O_ACCMODE) == O_WRONLY ||
			(fi->flags & O_ACCMODE) == O_RDWR))
		gfs_stat_cache_purge(path);
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
		gfs_stat_cache_purge(path);
	return (rv);
}

static int
gfarm2fs_removexattr_cached(const char *path, const char *name)
{
	int rv = gfarm2fs_removexattr(path, name);

	if (rv == 0)
		gfs_stat_cache_purge(path);
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
    .utime	= gfarm2fs_utime_cached,
    .create	= gfarm2fs_create_cached,
    .open	= gfarm2fs_open_cached,
    .read	= gfarm2fs_read,
    .write	= gfarm2fs_write_cached,
    .statfs	= gfarm2fs_statfs,
    .release	= gfarm2fs_release_cached,
    .fsync	= gfarm2fs_fsync,
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
	FUSE_OPT_END
};

static void
usage(const char *progname)
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
"    -o loglevel=priority    syslog priority level (default: %s)\n"
"    -E T                    cache timeout for gfs_stat (default: 1.0 sec.)\n"
"    -o gfs_stat_timeout=T   same -E option\n"
"    -o ncopy=N              number of copies (default: 1)\n"
"    -o copy_limit=N         maximum number of concurrent copy creations\n"
#ifdef HAVE_GFS_REPLICATE_FILE_TO
"                            (default: 10)\n"
#else /* version 2.3.X */
"                            (default: 0)\n"
#endif
		"\n", progname,
		GFARM2FS_SYSLOG_FACILITY_DEFAULT,
		GFARM2FS_SYSLOG_PRIORITY_DEFAULT);
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

static int
gfarm2fs_opt_proc(void *data, const char *arg, int key,
			struct fuse_args *outargs)
{
	struct gfarm2fs_param *paramsp = data;

	switch (key) {
	case FUSE_OPT_KEY_OPT: /* -?, -o opt, --opt */
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
	case KEY_VERSION:
		fprintf(stderr, "GFARM2FS version %s\n", VERSION);
#if FUSE_VERSION >= 25
		fuse_opt_add_arg(outargs, "--version");
		gfarm2fs_fuse_main(outargs, NULL);
#endif
		exit(0);
	case KEY_HELP:
		usage(outargs->argv[0]);
		fuse_opt_add_arg(outargs, "-ho");
		gfarm2fs_fuse_main(outargs, NULL);
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
		.foreground = 0,
		.debug = 0,
		.cache_timeout = -1.0,
		.use_syslog = 1,
		.facility = NULL,
		.loglevel = NULL,
		.ncopy = 1,
#ifdef HAVE_GFS_REPLICATE_FILE_TO
		.copy_limit = 10
#else /* version 2.3.X */
		.copy_limit = 0
#endif
	};

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

	if (params.mount_point == NULL) {
		fprintf(stderr, "missing mountpoint\n");
		fprintf(stderr, "see `%s -h' for usage\n", program_name);
		exit(1);
	}
	mount_point = params.mount_point;

	if (params.foreground || params.debug) {
		params.use_syslog = 0; /* use stderr */
		if (params.loglevel == NULL)
			params.loglevel = GFARM2FS_SYSLOG_PRIORITY_DEBUG;
	}

	if (params.loglevel == NULL)
		params.loglevel = GFARM2FS_SYSLOG_PRIORITY_DEFAULT;
	syslog_priority = gflog_syslog_name_to_priority(params.loglevel);
	if (syslog_priority == -1) {
		fprintf(stderr, "invalid loglevel: `%s'\n", params.loglevel);
		fprintf(stderr, "see `%s -h' for usage\n", program_name);
		exit(1);
	}
	gflog_set_priority_level(syslog_priority);

	gflog_set_identifier(program_name);
	gflog_auth_set_verbose(1);

	if (params.use_syslog) {
		if (params.facility == NULL)
			params.facility = GFARM2FS_SYSLOG_FACILITY_DEFAULT;
		syslog_facility = gflog_syslog_name_to_facility(
			params.facility);
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

	/* end of setting params */

	gfarm2fs_replicate_init(&params);
	gfarm2fs_open_file_init();

	setup_dumper();

	if (params.use_syslog) /* just before fuse_main */
		gflog_syslog_open(LOG_PID, syslog_facility);

	ret_fuse_main = gfarm2fs_fuse_main(&args, operation_mode);
	fuse_opt_free_args(&args);

	gfarm2fs_replicate_final();

	return (ret_fuse_main);
}
