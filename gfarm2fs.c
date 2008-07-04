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
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_SETXATTR
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

static uid_t
get_uid(char *user)
{
	if (strcmp(gfarm_get_global_username(), user) == 0)
		return getuid(); /* my own file */

	/* XXX FIXME - some other's file */
	return (0);
}

static int
get_gid(char *group)
{
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

	e = gfs_stat(path, &st);
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
	/* XXX FIXME */
	return (-ENOSYS);
#if 0
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
#endif
}

#ifndef USE_GETDIR
static int
gfarm2fs_opendir(const char *path, struct fuse_file_info *fi)
{
	gfarm_error_t e;
	GFS_Dir dp;

	e = gfs_opendir(path, &dp);
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

	e = gfs_opendir(path, &dp);
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
	/* XXX FIXME */
	return (-ENOSYS);
#if 0
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
#endif
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

#if 0
static char *
get_user(uid_t uid)
{
	/* XXX FIXME */
	return "user";
}

static char *
get_group(uid_t gid)
{
	/* XXX FIXME */
	return "group";
}
#endif

static int
gfarm2fs_chown(const char *path, uid_t uid, gid_t gid)
{
	struct gfs_stat st;
	gfarm_error_t e;

	/* XXX FIXME */
	if (uid == getuid()) {
		e = gfs_stat(path, &st);
		if (e != GFARM_ERR_NO_ERROR)
			return (-gfarm_error_to_errno(e));
		if (strcmp(st.st_user, gfarm_get_global_username()) == 0) {
			gfs_stat_free(&st);
			return (0);
		}
		gfs_stat_free(&st);
	}		
	return (-ENOSYS);
#if 0
	gfarm_error_t e;
	char *user, *group;

	user = get_user(uid);
	group = get_group(gid);

	e = gfs_chown(path, user, group);
	return (-gfarm_error_to_errno(e));
#endif
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

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int
gfarm2fs_setxattr(const char *path, const char *name, const char *value,
	size_t size, int flags)
{
	/* XXX FIXME */
	return (-ENOSYS);
#if 0
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
#endif
}

static int
gfarm2fs_getxattr(const char *path, const char *name, char *value, size_t size)
{
	/* XXX FIXME */
	return (-ENOSYS);
#if 0
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
#endif
}

static int
gfarm2fs_listxattr(const char *path, char *list, size_t size)
{
	/* XXX FIXME */
	return (-ENOSYS);
#if 0
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
#endif
}

static int
gfarm2fs_removexattr(const char *path, const char *name)
{
	/* XXX FIXME */
	return (-ENOSYS);
#if 0
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
#endif
}
#endif /* HAVE_SETXATTR */

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
#ifdef HAVE_SETXATTR
    .setxattr	= gfarm2fs_setxattr,
    .getxattr	= gfarm2fs_getxattr,
    .listxattr	= gfarm2fs_listxattr,
    .removexattr= gfarm2fs_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	gfarm_error_t e;
	char **nargv;

	umask(0);
	e = gfarm_initialize(&argc, &argv);
	if (e != GFARM_ERR_NO_ERROR) {
		fprintf(stderr, "%s: %s\n", *argv, gfarm_error_string(e));
		exit(1);
	}

	/*
	 * specify '-s' option to disable multithreaded operations
	 * libgfarm is not thread-safe for now
	 */
	++argc;
	nargv = malloc(sizeof(*argv) * (argc + 1));
	if (nargv == NULL) {
		fprintf(stderr, "%s: no memory\n", *argv);
		exit(1);
	}
	memcpy(nargv, argv, sizeof(*argv) * (argc - 1));
	nargv[argc - 1] = "-s";
	nargv[argc] = "";

	return (fuse_main(argc, nargv, &gfarm2fs_oper));
}
