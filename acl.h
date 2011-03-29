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

static const char ACL_EA_ACCESS[] = "system.posix_acl_access";
static const char ACL_EA_DEFAULT[] = "system.posix_acl_default";

#define ACL_EA_VERSION  (0x0002) /* Linux ACL Version */

static const char FIX_ACL_ACCESS[] = "gfarm2fs.fix_acl_access";
static const char FIX_ACL_DEFAULT[] = "gfarm2fs.fix_acl_default";
