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

/* for better scalability */
#define USE_GETDIR

/* XXX FIXME */
#define GFS_DEV		((dev_t)-1)
#define GFS_BLKSIZE	8192
#define STAT_BLKSIZ	512	/* for st_blocks */

char *program_name = "gfarm2fs";

static uid_t
get_uid(char *user)
{
	struct passwd *pwd;

	if (strcmp(gfarm_get_global_username(), user) == 0)
		return getuid(); /* my own file */

	/* assumes that the same username exists on the local system */
	if ((pwd = getpwnam(user)) != NULL)
		return pwd->pw_uid;

	/* XXX FIXME - some other's file */
	return (0);
}

static int
get_gid(char *group)
{
	struct group *grp;

	/* assumes that the same groupname exists on the local system */
	if ((grp = getgrnam(group)) != NULL)
		return grp->gr_gid;

	/* XXX FIXME */
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
	gfarm_error_t e;

	e = gfs_lstat_cached(path, &st);
	if (e != GFARM_ERR_NO_ERROR)
		return (-gfarm_error_to_errno(e));

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
	if (e != GFARM_ERR_NO_ERROR)
		return (-gfarm_error_to_errno(e));

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
	if (e != GFARM_ERR_NO_ERROR)
		return (-gfarm_error_to_errno(e));

	len = strlen(src);
	if (len >= size)
		len = size - 1;
	memcpy(buf, src, len);
	buf[len] = '\0';
	return (0);
}

#ifndef USE_GETDIR
static int
gfarm2fs_opendir(const char *path, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	GFS_Dir dp;

	e = gfs_opendir_caching(path, &dp);
	if (e != GFARM_ERR_NO_ERROR)
		return (-gfarm_error_to_errno(e));

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

	return (0);
}

static int
gfarm2fs_releasedir(const char *path, struct fuse_file_info *fi)
{
	GFS_Dir dp = get_dirp(fi);

	(void) path;
	gfs_closedir(dp);
	return (0);
}
#else /* USE_GETDIR */

static int
gfarm2fs_getdir(const char *path, fuse_dirh_t h, fuse_dirfil_t filler)
{
	gfarm_error_t e, e2;
	GFS_Dir dp;
	struct gfs_dirent *de;

	e = gfs_opendir_caching(path, &dp);
	if (e != GFARM_ERR_NO_ERROR)
		return (-gfarm_error_to_errno(e));

	while ((e = gfs_readdir(dp, &de)) == GFARM_ERR_NO_ERROR &&
		de != NULL) {
		if (filler(h, de->d_name, de->d_type << 12, de->d_fileno))
			break;
	}
	e2 = gfs_closedir(dp);
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
	if (e == GFARM_ERR_NO_ERROR)
		e = gfs_pio_close(gf);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_mkdir(const char *path, mode_t mode)
{
	gfarm_error_t e;

	e = gfs_mkdir(path, mode & GFARM_S_ALLPERM);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_unlink(const char *path)
{
	gfarm_error_t e;

	e = gfs_unlink(path);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_rmdir(const char *path)
{
	gfarm_error_t e;

	e = gfs_rmdir(path);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_symlink(const char *from, const char *to)
{
	gfarm_error_t e;

	e = gfs_symlink(from, to);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_rename(const char *from, const char *to)
{
	gfarm_error_t e;

	e = gfs_rename(from, to);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_link(const char *from, const char *to)
{
	gfarm_error_t e;

	e = gfs_link(from, to);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_chmod(const char *path, mode_t mode)
{
	gfarm_error_t e;

	e = gfs_chmod(path, mode & GFARM_S_ALLPERM);
	return (-gfarm_error_to_errno(e));
}

static char *
get_user(uid_t uid)
{
	struct passwd *pwd;

	if (uid == getuid())
		return gfarm_get_global_username();

	/* assumes that the same username exists on the gfarm filesystem */
	if ((pwd = getpwuid(uid)) != NULL)
		return pwd->pw_name;

	return NULL;
}

static char *
get_group(uid_t gid)
{
	struct group *grp;

	/* assumes that the same groupname exists on the gfarm filesystem */
	if ((grp = getgrgid(gid)) != NULL)
		return grp->gr_name;

	return NULL;
}

static int
gfarm2fs_chown(const char *path, uid_t uid, gid_t gid)
{
	gfarm_error_t e;
	char *user, *group;

	if (uid == -1)
		user = NULL;
	else if ((user = get_user(uid)) == NULL)
		return EINVAL;

	if (gid == -1)
		group = NULL;
	else if ((group = get_group(gid)) == NULL)
		return EINVAL;

	e = gfs_chown(path, user, group);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_truncate(const char *path, off_t size)
{
	gfarm_error_t e, e2;
	GFS_File gf;

	e = gfs_pio_open(path, GFARM_FILE_WRONLY, &gf);
	if (e != GFARM_ERR_NO_ERROR)
		return (-gfarm_error_to_errno(e));

	e = gfs_pio_truncate(gf, size);
	e2 = gfs_pio_close(gf);

	return (-gfarm_error_to_errno(e != GFARM_ERR_NO_ERROR ? e : e2));
}

static int
gfarm2fs_ftruncate(const char *path, off_t size,
                         struct fuse_file_info *fi)
{
	gfarm_error_t e;

	(void) path;
	e = gfs_pio_truncate(get_filep(fi), size);
	return (-gfarm_error_to_errno(e));
}

static int
gfarm2fs_utime(const char *path, struct utimbuf *buf)
{
	struct gfarm_timespec gt[2];
	gfarm_error_t e;

	if (buf != NULL) {
		gt[0].tv_sec = buf->actime;
		gt[0].tv_nsec= 0;
		gt[1].tv_sec = buf->modtime;
		gt[1].tv_nsec= 0;
	}
	e = gfs_utimes(path, gt);
	return (-gfarm_error_to_errno(e));
}

static int
gfs_hook_open_flags_gfarmize(int open_flags)
{
	int gfs_flags;

	switch (open_flags & O_ACCMODE) {
	case O_RDONLY:	gfs_flags = GFARM_FILE_RDONLY; break;
	case O_WRONLY:	gfs_flags = GFARM_FILE_WRONLY; break;
	case O_RDWR:	gfs_flags = GFARM_FILE_RDWR; break;
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
	if (e != GFARM_ERR_NO_ERROR)
		return (-gfarm_error_to_errno(e));

	fi->fh = (unsigned long) gf;
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
	if (e != GFARM_ERR_NO_ERROR)
		return (-gfarm_error_to_errno(e));

	fi->fh = (unsigned long) gf;
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
	if (e == GFARM_ERR_NO_ERROR)
		e = gfs_pio_read(get_filep(fi), buf, size, &rv);
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
	if (e == GFARM_ERR_NO_ERROR)
		e = gfs_pio_write(get_filep(fi), buf, size, &rv);
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
	if (e != GFARM_ERR_NO_ERROR)
		return (-gfarm_error_to_errno(e));
	else {
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
	}
	return (0);
}

static int
gfarm2fs_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	gfs_pio_close(get_filep(fi));

	return (0);
}

static int
gfarm2fs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
	gfarm_error_t e;

	(void) path;
	if (isdatasync)
		e = gfs_pio_datasync(get_filep(fi));
	else
		e = gfs_pio_sync(get_filep(fi));
	return (-gfarm_error_to_errno(e));
}

#if defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR)
static int
gfarm2fs_setxattr(const char *path, const char *name, const char *value,
	size_t size, int flags)
{
	gfarm_error_t e;
	e = gfs_setxattr(path, name, value, size, flags);
	return -gfarm_error_to_errno(e);
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
		 *		open("/", O_RDONLY|O_NONBLOCK|O_LARGEFILE|O_DIRECTORY) = 3
		 *		....
		 *		getxattr("/etc", "system.posix_acl_access"..., 0x0, 0) = -1 ENODATA (No data available)
		 *		getxattr("/etc", "system.posix_acl_default"..., 0x0, 0) = -1 ENODATA (No data available)
		 *  	...
		 */
		return -ENODATA;
	}
	if (e != GFARM_ERR_NO_ERROR)
		return -gfarm_error_to_errno(e);
	else
		return s;
}

static int
gfarm2fs_listxattr(const char *path, char *list, size_t size)
{
	gfarm_error_t e;
	size_t s = size;

	e = gfs_listxattr(path, list, &s);
	if (e == GFARM_ERR_NO_ERROR)
		return s;
	else
		return -gfarm_error_to_errno(e);
}

static int
gfarm2fs_removexattr(const char *path, const char *name)
{
	gfarm_error_t e;
	e = gfs_removexattr(path, name);
	if (e == GFARM_ERR_NO_SUCH_OBJECT)
		return -ENODATA;
	else
		return -gfarm_error_to_errno(e);
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
    .removexattr= gfarm2fs_removexattr,
#endif
};

/***
 *** for cached mode
 ***/

static void
uncache_parent(const char *path)
{
	char *p = strdup(path), *b;

	if (p == NULL) /* XXX should report an error */
		return;

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

	if (rv == 0) {
		gfs_stat_cache_purge(from);
		uncache_parent(from);
		gfs_stat_cache_purge(to);
		uncache_parent(to);
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
    .removexattr= gfarm2fs_removexattr_cached,
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

	gflog_set_identifier(program_name);
	gflog_auth_set_verbose(1);
	gflog_syslog_open(LOG_PID, GFARM_DEFAULT_FACILITY);

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = debug_handler;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGUSR2, &sa, NULL);
#endif
}


int main(int argc, char *argv[])
{
	struct fuse_operations *operation_mode = &gfarm2fs_cached_oper;
	gfarm_error_t e;
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	int i;

	umask(0);
	e = gfarm_initialize(&argc, &argv);
	if (e != GFARM_ERR_NO_ERROR) {
		fprintf(stderr, "%s: %s\n", *argv, gfarm_error_string(e));
		exit(1);
	}

	if (argc > 0)
		fuse_opt_add_arg(&args, argv[0]);

	/*
	 * specify '-s' option to disable multithreaded operations
	 * libgfarm is not thread-safe for now
	 */
	fuse_opt_add_arg(&args, "-s");

	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-' && argv[i][1] == 'E') {
			double timeout;
			char *ep;

			if (i + 1 >= argc) {
				fprintf(stderr, "%s: -E: missing <seconds>\n",
				    program_name);
				exit(EXIT_FAILURE);
			}
			errno = 0;
			timeout = strtod(argv[i + 1], &ep);
			if (ep == optarg || *ep != '\0') {
				fprintf(stderr, "%s: -E %s: %s\n",
				    program_name, argv[i+1],
				    "invalid argument");
				exit(EXIT_FAILURE);
			} else if (errno != 0) {
				fprintf(stderr, "%s: -E %s: %s\n",
				    program_name, argv[i+1], strerror(errno));
				exit(EXIT_FAILURE);
			}
			i++;

			if (timeout == 0.0) {
				gfs_stat_cache_enable(0); /* disable cache */
				operation_mode = &gfarm2fs_oper;
			} else {
				gfs_stat_cache_expiration_set(timeout*1000.0);
			}
		} else {
			fuse_opt_add_arg(&args, argv[i]);
		}
	}

	setup_dumper();

	return (fuse_main(args.argc, args.argv, operation_mode));
}
