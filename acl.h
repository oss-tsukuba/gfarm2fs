/*
 * $Id$
 */

#if defined(HAVE_SYS_ACL_H) && defined(GFARM_ACL_READ) &&  \
	defined(HAVE_SYS_XATTR_H) && defined(ENABLE_XATTR) && \
	defined(HAVE_GFARM_XATTR_CACHING) && \
	defined(HAVE_GFARM_XATTR_CACHING_PATTERN_ADD)
#define ENABLE_GFARM_ACL
gfarm_error_t gfarm2fs_acl_set(const char *, gfarm_acl_type_t type,
			       const void *, size_t);
gfarm_error_t gfarm2fs_acl_get(const char *, gfarm_acl_type_t type,
			       void *, size_t *);
#endif


static const char ACL_EA_ACCESS[] = "system.posix_acl_access";
static const char ACL_EA_DEFAULT[] = "system.posix_acl_default";

#define ACL_EA_VERSION  (0x0002) /* Linux ACL Version */
