/*
 * $Id$
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>

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
#include "acl.h"
#include "xattr.h"
#include "gfarm_config.h"

struct gfarm2fs_xattr_sw {
	gfarm_error_t (*set)(const char *path, const char *name,
			     const void *value, size_t size, int flags);
	gfarm_error_t (*get)(const char *path, const char *name,
			     void *value, size_t *sizep);
	gfarm_error_t (*remove)(const char *path, const char *name);
};

#define XATTR_IS_SUPPORTED(name) \
	(strncmp(name, "gfarm.", 6) == 0 || \
	 strncmp(name, "gfarm_root.", 11) == 0 || \
	 strncmp(name, "user.", 5) == 0)

static const char LOCAL_XATTR_PREFIX[] = "gfarm2fs.";
#define LOCAL_XATTR_PREFIX_LENGTH 9 /* sizeof(LOCAL_XATTR_PREFIX) - 1 */
#define PROFILE_XATTR_PREFIX "profile."
#define PROFILE_XATTR_PREFIX_LENGTH 8
#define GFARM2FS_IS_MOUNT_ROOT(path) (strcmp((path), "/") == 0)
#define XATTR_IS_LOCALLY_SUPPORTED(name) \
	(strncmp(name, LOCAL_XATTR_PREFIX, LOCAL_XATTR_PREFIX_LENGTH) == 0)

#ifdef ENABLE_ACL
/* ------------------------------- */

static gfarm_error_t
normal_set(const char *path, const char *name,
	   const void *value, size_t size, int flags)
{
	if (strcmp(name, ACL_EA_ACCESS) == 0)
		return (gfarm2fs_acl_set(path, GFARM_ACL_TYPE_ACCESS,
					 value, size));
	else if (strcmp(name, ACL_EA_DEFAULT) == 0)
		return (gfarm2fs_acl_set(path, GFARM_ACL_TYPE_DEFAULT,
					 value, size));
	else if (XATTR_IS_SUPPORTED(name))
		return (gfs_lsetxattr(path, name, value, size, flags));
	else
		return (GFARM_ERR_OPERATION_NOT_SUPPORTED); /* EOPNOTSUPP */
}

static gfarm_error_t
normal_get(const char *path, const char *name, void *value, size_t *sizep)
{
	if (strcmp(name, ACL_EA_ACCESS) == 0)
		return (gfarm2fs_acl_get(path, GFARM_ACL_TYPE_ACCESS,
					 value, sizep));
	else if (strcmp(name, ACL_EA_DEFAULT) == 0)
		return (gfarm2fs_acl_get(path, GFARM_ACL_TYPE_DEFAULT,
					value, sizep));
	else if (XATTR_IS_SUPPORTED(name))
		return (gfs_lgetxattr_cached(path, name, value, sizep));
	else
		return (GFARM_ERR_NO_SUCH_OBJECT); /* ENODATA */
}

static gfarm_error_t
normal_remove(const char *path, const char *name)
{
	if (strcmp(name, ACL_EA_ACCESS) == 0)
		return (gfs_lremovexattr(path, GFARM_ACL_EA_ACCESS));
	else if (strcmp(name, ACL_EA_DEFAULT) == 0)
		return (gfs_lremovexattr(path, GFARM_ACL_EA_DEFAULT));
	else if (XATTR_IS_SUPPORTED(name))
		return (gfs_lremovexattr(path, name));
	else
		return (GFARM_ERR_OPERATION_NOT_SUPPORTED); /* EOPNOTSUPP */
}

static struct gfarm2fs_xattr_sw sw_normal = {
	normal_set,
	normal_get,
	normal_remove,
};

/* ------------------------------- */

/* for gfarm2fs_fix_acl command */

const char FIX_ACL_ACCESS[] = "gfarm2fs.fix_acl_access";
const char FIX_ACL_DEFAULT[] = "gfarm2fs.fix_acl_default";

static gfarm_error_t
fix_acl_set(const char *path, const char *name,
	    const void *value, size_t size, int flags)
{
	if (strcmp(name, FIX_ACL_ACCESS) == 0 ||
	    strcmp(name, FIX_ACL_DEFAULT) == 0)
		return (GFARM_ERR_OPERATION_NOT_SUPPORTED); /* EOPNOTSUPP */
	else if (strcmp(name, ACL_EA_ACCESS) == 0)
		return (gfarm2fs_acl_set(path, GFARM_ACL_TYPE_ACCESS,
					 value, size));
	else if (strcmp(name, ACL_EA_DEFAULT) == 0)
		return (gfarm2fs_acl_set(path, GFARM_ACL_TYPE_DEFAULT,
					 value, size));
	else if (XATTR_IS_SUPPORTED(name))
		return (gfs_lsetxattr(path, name, value, size, flags));
	else
		return (GFARM_ERR_OPERATION_NOT_SUPPORTED); /* EOPNOTSUPP */
}

static gfarm_error_t
fix_acl_get(const char *path, const char *name, void *value, size_t *sizep)
{
	if (strcmp(name, FIX_ACL_ACCESS) == 0)
		return (gfs_lgetxattr_cached(path, ACL_EA_ACCESS,
					     value, sizep));
	else if (strcmp(name, FIX_ACL_DEFAULT) == 0)
		return (gfs_lgetxattr_cached(path, ACL_EA_DEFAULT,
					     value, sizep));
	else if (strcmp(name, ACL_EA_ACCESS) == 0)
		return (gfarm2fs_acl_get(path, GFARM_ACL_TYPE_ACCESS,
					 value, sizep));
	else if (strcmp(name, ACL_EA_DEFAULT) == 0)
		return (gfarm2fs_acl_get(path, GFARM_ACL_TYPE_DEFAULT,
					 value, sizep));
	else if (XATTR_IS_SUPPORTED(name))
		return (gfs_lgetxattr_cached(path, name, value, sizep));
	else
		return (GFARM_ERR_NO_SUCH_OBJECT); /* ENODATA */
}

static gfarm_error_t
fix_acl_remove(const char *path, const char *name)
{
	if (strcmp(name, FIX_ACL_ACCESS) == 0)
		return (gfs_lremovexattr(path, ACL_EA_ACCESS));
	else if (strcmp(name, FIX_ACL_DEFAULT) == 0)
		return (gfs_lremovexattr(path, ACL_EA_DEFAULT));
	else if (strcmp(name, ACL_EA_ACCESS) == 0)
		return (gfs_lremovexattr(path, GFARM_ACL_EA_ACCESS));
	else if (strcmp(name, ACL_EA_DEFAULT) == 0)
		return (gfs_lremovexattr(path, GFARM_ACL_EA_DEFAULT));
	else if (XATTR_IS_SUPPORTED(name))
		return (gfs_lremovexattr(path, name));
	else
		return (GFARM_ERR_OPERATION_NOT_SUPPORTED); /* EOPNOTSUPP */
}

static struct gfarm2fs_xattr_sw sw_fix_acl = {
	fix_acl_set,
	fix_acl_get,
	fix_acl_remove,
};

#endif /* ENABLE_ACL */

/* ------------------------------- */

static gfarm_error_t
disable_acl_set(const char *path, const char *name,
		const void *value, size_t size, int flags)
{
	if (XATTR_IS_SUPPORTED(name))
		return (gfs_lsetxattr(path, name, value, size, flags));
	else
		return (GFARM_ERR_OPERATION_NOT_SUPPORTED); /* EOPNOTSUPP */
}

static gfarm_error_t
disable_acl_get(const char *path, const char *name, void *value, size_t *sizep)
{
	if (XATTR_IS_SUPPORTED(name))
		return (gfs_lgetxattr_cached(path, name, value, sizep));
	else
		return (GFARM_ERR_NO_SUCH_OBJECT); /* ENODATA */
}

static gfarm_error_t
disable_acl_remove(const char *path, const char *name)
{
	if (XATTR_IS_SUPPORTED(name))
		return (gfs_lremovexattr(path, name));
	else
		return (GFARM_ERR_OPERATION_NOT_SUPPORTED); /* EOPNOTSUPP */
}

static struct gfarm2fs_xattr_sw sw_disable_acl = {
	disable_acl_set,
	disable_acl_get,
	disable_acl_remove,
};

/* ------------------------------- */

static gfarm_error_t
gfarm2fs_xattr_copy(const char *src, const char *name, void *dst, size_t *sizep)
{
	size_t len;

	if (name != NULL && name[0] != '\0')
		return (GFARM_ERR_NO_SUCH_OBJECT);
	len = strlen(src);
	if (*sizep >= len)
		memcpy(dst, src, len);
	else if (*sizep != 0)
		return (GFARM_ERR_RESULT_OUT_OF_RANGE);
	*sizep = len;
	return (GFARM_ERR_NO_ERROR);
}

static gfarm_error_t
local_xattr_version(const char *version, const char *name, void *value,
	size_t *sizep)
{
	return (gfarm2fs_xattr_copy(version, name, value, sizep));
}

static gfarm_error_t
local_xattr_gfarm2fs_version(const char *path, const char *name, void *value,
	size_t *sizep)
{
	(void) path;
	return (local_xattr_version(VERSION, name, value, sizep));
}

static gfarm_error_t
local_xattr_gfarm_version(const char *path, const char *name, void *value,
	size_t *sizep)
{
	(void) path;
#ifdef HAVE_GFARM_VERSION
	return (local_xattr_version(gfarm_version(), name, value, sizep));
#else /* HAVE_GFARM_VERSION */
	return (local_xattr_version("unknown", name, value, sizep));
#endif /* HAVE_GFARM_VERSION */
}

static gfarm_error_t
local_xattr_fuse_version(const char *path, const char *name, void *value,
	size_t *sizep)
{
#ifdef HAVE_FUSE3
	(void) path;

	return (local_xattr_version(fuse_pkgversion(), name, value, sizep));
#else /* HAVE_FUSE3 */
	char version[32];
	int v = fuse_version();

	(void) path;
	snprintf(version, sizeof(version), "%d.%d", v / 10, v % 10);
	return (local_xattr_version(version, name, value, sizep));
#endif /* HAVE_FUSE3 */
}

static gfarm_error_t
local_xattr_pid(const char *path, const char *name, void *value, size_t *sizep)
{
	char pid[32];

	(void) path;
	snprintf(pid, sizeof(pid), "%ld", (long) getpid());
	return (local_xattr_version(pid, name, value, sizep));
}

static gfarm_error_t
local_xattr_exe(const char *path, const char *name, void *value, size_t *sizep)
{
	char exe[PATH_MAX];
	ssize_t len;

	(void) path;
	len = readlink("/proc/self/exe", exe, sizeof(exe));
	if (len < 0)
		return (gfarm_errno_to_error(errno));
	if ((size_t) len > *sizep && *sizep != 0)
		return (GFARM_ERR_RESULT_OUT_OF_RANGE);
	if (*sizep != 0)
		memcpy(value, exe, len);
	*sizep = len;
	return (GFARM_ERR_NO_ERROR);
}

static int
port_size(int port)
{
	int s;

	if (port == 0)
		return (1);
	for (s = 0; port > 0; ++s, port /= 10)
		;
	return (s);
}

static void
port_to_string(int port, char *dst)
{
	int s, size = port_size(port);

	for (s = size - 1; s >= 0; --s) {
		dst[s] = port % 10 + '0';
		port /= 10;
	}
}

static gfarm_error_t
local_xattr_url(const char *path, const char *name, void *value, size_t *sizep)
{
	gfarm_error_t e;
	const char *metadb;
	size_t len, metadb_len, port_len, path_len;
	int port;

	if (name != NULL && name[0] != '\0')
		return (GFARM_ERR_NO_SUCH_OBJECT);
	if (gfarm_is_url(path))
		return (gfarm2fs_xattr_copy(path, name, value, sizep));
	e = gfarm_config_metadb_server(path, &metadb, &port);
	if (e != GFARM_ERR_NO_ERROR)
		return (e);
	metadb_len = strlen(metadb);
	port_len = port_size(port);
	path_len = strlen(path);
	len = GFARM_URL_PREFIX_LENGTH + 2 + metadb_len + 1 + port_len +
	    path_len;
	if (*sizep >= len) {
		snprintf(value, len, "%s//%s:%d", GFARM_URL_PREFIX, metadb,
		    port);
		value += GFARM_URL_PREFIX_LENGTH + 2 + metadb_len + 1 +
		    port_len;
		memcpy(value, path, path_len);
	} else if (*sizep != 0)
		return (GFARM_ERR_RESULT_OUT_OF_RANGE);
	*sizep = len;
	return (GFARM_ERR_NO_ERROR);
}

static gfarm_error_t
local_xattr_metadb(const char *path, const char *name, void *value,
	size_t *sizep)
{
	gfarm_error_t e;
	const char *metadb;
	size_t len, metadb_len, port_len;
	int port;

	if (name != NULL && name[0] != '\0')
		return (GFARM_ERR_NO_SUCH_OBJECT);
	e = gfarm_config_metadb_server(path, &metadb, &port);
	if (e != GFARM_ERR_NO_ERROR)
		return (e);
	metadb_len = strlen(metadb);
	port_len = port_size(port);
	len = metadb_len + 1 + port_len;
	if (*sizep >= len) {
		snprintf(value, len, "%s:", metadb);
		value += metadb_len + 1;
		port_to_string(port, value);
	} else if (*sizep != 0)
		return (GFARM_ERR_RESULT_OUT_OF_RANGE);
	*sizep = len;
	return (GFARM_ERR_NO_ERROR);
}

static gfarm_error_t
local_xattr_gsi_common(void *value, size_t *sizep, gfarm_error_t (*op)(char **))
{
	char *gsivalue = NULL;
	gfarm_error_t e;

	if ((e = (op)(&gsivalue)) == GFARM_ERR_NO_ERROR) {
		e = gfarm2fs_xattr_copy(gsivalue, NULL, value, sizep);
		free(gsivalue);
	}
	return (e);
}

static gfarm_error_t
local_xattr_gsi_proxy_info(const char *path, const char *name, void *value,
	size_t *sizep)
{
	if (name != NULL && name[0] != '\0')
		return (GFARM_ERR_NO_SUCH_OBJECT);
	return (local_xattr_gsi_common(value, sizep,
	    gfarm_config_gsi_proxy_info));
}

static gfarm_error_t
local_xattr_gsi_path(const char *path, const char *name, void *value,
	size_t *sizep)
{
	if (name != NULL && name[0] != '\0')
		return (GFARM_ERR_NO_SUCH_OBJECT);
	return (local_xattr_gsi_common(value, sizep,
	    gfarm_config_gsi_path));
}

static gfarm_error_t
local_xattr_gsi_timeleft(const char *path, const char *name, void *value,
	size_t *sizep)
{
	if (name != NULL && name[0] != '\0')
		return (GFARM_ERR_NO_SUCH_OBJECT);
	return (local_xattr_gsi_common(value, sizep,
	    gfarm_config_gsi_timeleft));
}

#ifdef HAVE_GFS_STAT_CKSUM
static gfarm_error_t
copy_cksum(struct gfs_stat_cksum *c, void *dst, size_t *sizep)
{
	size_t len;

	if (c == NULL || c->len == 0)
		return (gfarm2fs_xattr_copy("", NULL, dst, sizep));
	len = c->len + 2 + strlen(c->type) + 2 + port_size(c->flags);
	if (*sizep == 0) {
		*sizep = len;
		return (GFARM_ERR_NO_ERROR);
	} else if (len > *sizep)
		return (GFARM_ERR_RESULT_OUT_OF_RANGE);
	*sizep = len;
	snprintf(dst, len, "%.*s (%s) ", (int)c->len, c->cksum, c->type);
	dst += len - port_size(c->flags);
	port_to_string(c->flags, dst);
	return (GFARM_ERR_NO_ERROR);
}

static gfarm_error_t
stat_cksum(const char *p, const char *name, void *dst, size_t *sizep)
{
	struct gfs_stat_cksum c;
	struct gfs_stat st;
	gfarm_error_t e;

	if (name != NULL && name[0] != '\0')
		return (GFARM_ERR_NO_SUCH_OBJECT);
	e = gfs_lstat_cached(p, &st);
	if (e != GFARM_ERR_NO_ERROR)
		return (e);
	gfs_stat_free(&st);
	if (!GFARM_S_ISREG(st.st_mode))
		return (GFARM_ERR_NO_SUCH_OBJECT);
	if ((e = gfs_stat_cksum(p, &c)) != GFARM_ERR_NO_ERROR)
		return (e);
	e = copy_cksum(&c, dst, sizep);
	gfs_stat_cksum_free(&c);
	return (e);
}
#endif /* HAVE_GFS_STAT_CKSUM */

#ifdef HAVE_GFARM_CONFIG_PROFILE_VALUE
static gfarm_error_t
local_xattr_profile(const char *p, const char *name, void *value, size_t *sizep)
{
	return (gfarm_config_profile_value(name, value, sizep));
}

static const char *profile_xattr_keys[] = {
	/* From gfs_pio.c */
	"create_time",
	"create_count",
	"open_time",
	"open_count",
	"close_time",
	"close_count",
	"seek_time",
	"seek_count",
	"truncate_time",
	"truncate_count",
	"read_time",
	"read_size",
	"read_count",
	"write_time",
	"write_size",
	"write_count",
	"sync_time",
	"sync_count",
	"datasync_time",
	"datasync_count",
	"getline_time",
	"getline_count",
	"getc_time",
	"getc_count",
	"putc_time",
	"putc_count",
	/* From gfs_pio_local.c */
	"local_read_time",
	"local_read_size",
	"local_read_count",
	"local_write_time",
	"local_write_size",
	"local_write_count",
	/* From gfs_pio_section.c */
	"set_view_section",
	"open_local_count",
	"open_remote_count",
	/* From gfs_stat.c */
	"stat_time",
	"stat_count",
	/* From gfs_unlink.c */
	"unlink_time",
	"unlink_count",
	/* From gfs_xattr.c */
	"xattr_time",
	"xattr_count",
	/* From gfs_pio_remote.c */
	"remote_read_time",
	"remote_read_size",
	"remote_read_count",
	"remote_write_time",
	"remote_write_size",
	"remote_write_count",
	"rdma_read_time",
	"rdma_read_size",
	"rdma_read_count",
	"rdma_write_time",
	"rdma_write_size",
	"rdma_write_count",
};
#endif /* HAVE_GFARM_CONFIG_PROFILE_VALUE */

struct {
	char *attr;
	gfarm_error_t (*op)(const char *, const char *, void *, size_t *);
} local_xattr[] = {
	{ "path", gfarm2fs_xattr_copy },
	{ "version", local_xattr_gfarm2fs_version },
	{ "gfarm_version", local_xattr_gfarm_version },
	{ "fuse_version", local_xattr_fuse_version },
	{ "pid", local_xattr_pid },
	{ "exe", local_xattr_exe },
	{ "url", local_xattr_url },
	{ "metadb", local_xattr_metadb },
	{ "gsiproxyinfo", local_xattr_gsi_proxy_info },
	{ "gsipath", local_xattr_gsi_path },
	{ "gsitimeleft", local_xattr_gsi_timeleft },
#ifdef HAVE_GFS_STAT_CKSUM
	{ "cksum", stat_cksum },
#endif /* HAVE_GFS_STAT_CKSUM */
#ifdef HAVE_GFARM_CONFIG_PROFILE_VALUE
	{ PROFILE_XATTR_PREFIX, local_xattr_profile },
#endif /* HAVE_GFARM_CONFIG_PROFILE_VALUE */
};

static gfarm_error_t
gfarm2fs_xattr_get_local(const char *path, const char *name, void *value,
	size_t *sizep)
{
	const char *n = name + LOCAL_XATTR_PREFIX_LENGTH;
	int i, len;

	for (i = 0; i < GFARM_ARRAY_LENGTH(local_xattr); ++i) {
		len = strlen(local_xattr[i].attr);
		if (strncmp(n, local_xattr[i].attr, len) == 0)
			return (local_xattr[i].op(path, n + len, value, sizep));
	}
	return (GFARM_ERR_NO_SUCH_OBJECT); /* ENODATA */
}

size_t
gfarm2fs_xattr_list_local(const char *path, char *list, size_t size)
{
	size_t len, total = 0, used = 0;
	int i;

	for (i = 0; i < GFARM_ARRAY_LENGTH(local_xattr); ++i) {
		if (strcmp(local_xattr[i].attr, PROFILE_XATTR_PREFIX) == 0)
			continue;
		len = strlen(LOCAL_XATTR_PREFIX) + strlen(local_xattr[i].attr)
		  + 1;
		total += len;
	}
#ifdef HAVE_GFARM_CONFIG_PROFILE_VALUE
	if (GFARM2FS_IS_MOUNT_ROOT(path)) {
		for (i = 0; i < GFARM_ARRAY_LENGTH(profile_xattr_keys); ++i)
			total += strlen(LOCAL_XATTR_PREFIX) +
			    strlen(PROFILE_XATTR_PREFIX) +
			    strlen(profile_xattr_keys[i]) + 1;
	}
#endif /* HAVE_GFARM_CONFIG_PROFILE_VALUE */

	/* Return the needed size */
	if (list == NULL || size < total)
		return (total);

	for (i = 0; i < GFARM_ARRAY_LENGTH(local_xattr); ++i) {
		if (strcmp(local_xattr[i].attr, PROFILE_XATTR_PREFIX) == 0)
			continue;
		len = snprintf(list + used, size - used, "%s%s",
		    LOCAL_XATTR_PREFIX, local_xattr[i].attr) + 1;
		used += len;
	}
#ifdef HAVE_GFARM_CONFIG_PROFILE_VALUE
	if (GFARM2FS_IS_MOUNT_ROOT(path)) {
		for (i = 0; i < GFARM_ARRAY_LENGTH(profile_xattr_keys); ++i) {
			len = snprintf(list + used, size - used, "%s%s%s",
			    LOCAL_XATTR_PREFIX, PROFILE_XATTR_PREFIX,
			    profile_xattr_keys[i]) + 1;
			used += len;
		}
	}
#endif /* HAVE_GFARM_CONFIG_PROFILE_VALUE */
	return (total);
}

/* ------------------------------- */

static struct gfarm2fs_xattr_sw *funcs = &sw_disable_acl;

gfarm_error_t
gfarm2fs_xattr_set(const char *path, const char *name,
		   const void *value, size_t size, int flags)
{
	if (XATTR_IS_LOCALLY_SUPPORTED(name))
		return (GFARM_ERR_NO_ERROR);
	return ((*funcs->set)(path, name, value, size, flags));
}

gfarm_error_t
gfarm2fs_xattr_get(const char *path, const char *name,
		   void *value, size_t *sizep)
{
	if (XATTR_IS_LOCALLY_SUPPORTED(name))
		return (gfarm2fs_xattr_get_local(path, name, value, sizep));
	return ((*funcs->get)(path, name, value, sizep));
}

gfarm_error_t
gfarm2fs_xattr_remove(const char *path, const char *name)
{
	if (XATTR_IS_LOCALLY_SUPPORTED(name))
		return (GFARM_ERR_NO_ERROR);
	return ((*funcs->remove)(path, name));
}

void
gfarm2fs_xattr_init(struct gfarm2fs_param *params)
{
#ifdef ENABLE_ACL
	if (params->disable_acl)
		funcs = &sw_disable_acl;
	else if (params->fix_acl)
		funcs = &sw_fix_acl;
	else {
		funcs = &sw_normal;
		gfarm_xattr_caching_pattern_add(GFARM_ACL_EA_ACCESS);
		gfarm_xattr_caching_pattern_add(GFARM_ACL_EA_DEFAULT);
	}
#endif
}
