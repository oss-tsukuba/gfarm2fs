#ifndef HAVE_GFS_GETXATTR_CACHED
#define	gfs_getxattr_cached	gfs_getxattr
#endif

struct gfarm2fs_param {
	const char *mount_point;
	char *subdir;
	int foreground;
	int debug;
	double cache_timeout;
	int use_syslog;
	char *facility;
	char *loglevel;
	int ncopy;
	int copy_limit;
	int fix_acl;
	int disable_acl;
	int enable_cached_id;
	int auto_uid_min;
	int auto_uid_max;
	int auto_gid_min;
	int auto_gid_max;
	int genuine_nlink;
	int directory_quota_rename_error_exdev;
};

struct gfarmized_path {
	int alloced;
	char *path;
};

gfarm_error_t gfarmize_path(const char *, struct gfarmized_path *);
void free_gfarmized_path(struct gfarmized_path *);

struct gfarm2fs_file {
	int flags;
	GFS_File gf;
	gfarm_ino_t inum;
	int time_updated;
	struct gfarm_timespec gt[2];
};

/* support nanosecond */
#if defined(HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC)
#define gfarm2fs_stat_mtime_nsec_set(st, v) ((st)->st_mtim.tv_nsec = (v))
#define gfarm2fs_stat_atime_nsec_set(st, v) ((st)->st_atim.tv_nsec = (v))
#define gfarm2fs_stat_ctime_nsec_set(st, v) ((st)->st_ctim.tv_nsec = (v))
#else
#define gfarm2fs_stat_mtime_nsec_set(st, v) do {} while (0)
#define gfarm2fs_stat_atime_nsec_set(st, v) do {} while (0)
#define gfarm2fs_stat_ctime_nsec_set(st, v) do {} while (0)
#endif
