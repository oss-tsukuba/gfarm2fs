/*
 * $Id$
 */

#include "config.h"

#include <string.h>

#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <gfarm/gfarm.h>

#include "gfarm2fs.h"
#include "acl.h"
#include "xattr.h"

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

#ifdef ENABLE_GFARM_ACL
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

#endif /* ENABLE_GFARM_ACL */

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

static struct gfarm2fs_xattr_sw *funcs = &sw_disable_acl;

gfarm_error_t
gfarm2fs_xattr_set(const char *path, const char *name,
		   const void *value, size_t size, int flags)
{
	return ((*funcs->set)(path, name, value, size, flags));
}

gfarm_error_t
gfarm2fs_xattr_get(const char *path, const char *name,
		   void *value, size_t *sizep)
{
	return ((*funcs->get)(path, name, value, sizep));
}

gfarm_error_t
gfarm2fs_xattr_remove(const char *path, const char *name)
{
	return ((*funcs->remove)(path, name));
}

void
gfarm2fs_xattr_init(struct gfarm2fs_param *params)
{
#ifdef ENABLE_GFARM_ACL
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
