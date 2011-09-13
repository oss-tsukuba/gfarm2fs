#ifndef HAVE_GFS_GETXATTR_CACHED
#define	gfs_getxattr_cached	gfs_getxattr
#endif

struct gfarm2fs_param {
	const char *mount_point;
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
};

struct gfarmized_path {
	int alloced;
	char *path;
};

gfarm_error_t gfarmize_path(const char *, struct gfarmized_path *);
void free_gfarmized_path(struct gfarmized_path *);
