/*
 * $Id$
 */

#if defined(HAVE_SYS_ACL_H) && defined(GFARM_ACL_READ) &&  \
	defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR) && \
	defined(HAVE_GFARM_XATTR_CACHING) && \
	defined(HAVE_GFARM_XATTR_CACHING_PATTERN_ADD)
#define ENABLE_GFARM_ACL
#endif

void gfarm2fs_acl_init(struct gfarm2fs_param *);
gfarm_error_t gfarm2fs_acl_setxattr(const char *, const char *,
				    const void *, size_t, int);
gfarm_error_t gfarm2fs_acl_getxattr(const char *, const char *,
				    void *, size_t *);
gfarm_error_t gfarm2fs_acl_removexattr(const char *, const char *);
