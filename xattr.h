/*
 * $Id$
 */

void gfarm2fs_xattr_init(struct gfarm2fs_param *);
gfarm_error_t gfarm2fs_xattr_set(const char *, const char *,
				 const void *, size_t, int);
gfarm_error_t gfarm2fs_xattr_get(const char *, const char *, void *, size_t *);
gfarm_error_t gfarm2fs_xattr_remove(const char *, const char *);

static const char FIX_ACL_ACCESS[] = "gfarm2fs.fix_acl_access";
static const char FIX_ACL_DEFAULT[] = "gfarm2fs.fix_acl_default";
