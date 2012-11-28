/*
 * $Id$
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
gfarm2fs_xattr_copy(const char *src, void *dst, size_t *sizep)
{
	size_t len;

	len = strlen(src);
	if (*sizep == 0) {
		*sizep = len;
		return (GFARM_ERR_NO_ERROR);
	} else if (len > *sizep)
		return (GFARM_ERR_RESULT_OUT_OF_RANGE);
	*sizep = len;
	memcpy(dst, src, len);
	return (GFARM_ERR_NO_ERROR);
}

static int
port_size(int port)
{
	int s;

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
gfarm2fs_xattr_get_local(const char *path, const char *name, void *value,
	size_t *sizep)
{
	const char *n, *metadb;
	char *gsivalue = NULL;
	size_t len, metadb_len, port_len, path_len;
	int port;
	gfarm_error_t e;

	n = name + LOCAL_XATTR_PREFIX_LENGTH;
	if (strcmp(n, "path") == 0)
		return (gfarm2fs_xattr_copy(path, value, sizep));
	else if (strcmp(n, "url") == 0) {
		if (gfarm_is_url(path))
			return (gfarm2fs_xattr_copy(path, value, sizep));
		e = gfarm_config_metadb_server(path, &metadb, &port);
		if (e != GFARM_ERR_NO_ERROR)
			return (e);
		metadb_len = strlen(metadb);
		port_len = port_size(port);
		path_len = strlen(path);
		len = GFARM_URL_PREFIX_LENGTH + 2 + metadb_len + 1 +
			port_len + path_len;
		if (*sizep == 0) {
			*sizep = len;
			return (GFARM_ERR_NO_ERROR);
		} else if (len > *sizep)
			return (GFARM_ERR_RESULT_OUT_OF_RANGE);
		*sizep = len;
		snprintf(value, len, "%s//%s:%d", GFARM_URL_PREFIX,
		    metadb, port);
		value += GFARM_URL_PREFIX_LENGTH + 2 + metadb_len + 1 +
			port_len;
		memcpy(value, path, path_len);
		return (GFARM_ERR_NO_ERROR);
	} else if (strcmp(n, "metadb") == 0) {
		e = gfarm_config_metadb_server(path, &metadb, &port);
		if (e != GFARM_ERR_NO_ERROR)
			return (e);
		metadb_len = strlen(metadb);
		port_len = port_size(port);
		len = metadb_len + 1 + port_len;
		if (*sizep == 0) {
			*sizep = len;
			return (GFARM_ERR_NO_ERROR);
		} else if (len > *sizep)
			return (GFARM_ERR_RESULT_OUT_OF_RANGE);
		*sizep = len;
		snprintf(value, len, "%s:", metadb);
		value += metadb_len + 1;
		port_to_string(port, value);
		return (GFARM_ERR_NO_ERROR);
	} else if (strcmp(n, "gsiproxyinfo") == 0) {
		e = gfarm_config_gsi_proxy_info(&gsivalue);
		if (e == GFARM_ERR_NO_ERROR) {
			e = gfarm2fs_xattr_copy(gsivalue, value, sizep);
			free(gsivalue);
		}
		return (e);
	} else if (strcmp(n, "gsipath") == 0) {
		e = gfarm_config_gsi_path(&gsivalue);
		if (e == GFARM_ERR_NO_ERROR) {
			e = gfarm2fs_xattr_copy(gsivalue, value, sizep);
			free(gsivalue);
		}
		return (e);
	} else if (strcmp(n, "gsitimeleft") == 0) {
		e = gfarm_config_gsi_timeleft(&gsivalue);
		if (e == GFARM_ERR_NO_ERROR) {
			e = gfarm2fs_xattr_copy(gsivalue, value, sizep);
			free(gsivalue);
		}
		return (e);
	} else
		return (GFARM_ERR_NO_SUCH_OBJECT); /* ENODATA */
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
