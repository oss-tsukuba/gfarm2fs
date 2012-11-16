/*
 * $Id$
 */

#ifdef ENABLE_ACL
gfarm_error_t gfarm2fs_acl_set(const char *, gfarm_acl_type_t type,
			       const void *, size_t);
gfarm_error_t gfarm2fs_acl_get(const char *, gfarm_acl_type_t type,
			       void *, size_t *);

extern const char ACL_EA_ACCESS[];
extern const char ACL_EA_DEFAULT[];

#define ACL_EA_VERSION  (0x0002) /* Linux ACL Version */
#endif
