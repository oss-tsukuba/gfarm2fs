/*
 * $Id$
 */

void gfarm2fs_xattr_init(struct gfarm2fs_param *);
gfarm_error_t gfarm2fs_xattr_set(const char *, const char *,
				 const void *, size_t, int);
gfarm_error_t gfarm2fs_xattr_get(const char *, const char *, void *, size_t *);
gfarm_error_t gfarm2fs_xattr_remove(const char *, const char *);
size_t gfarm2fs_xattr_list_local(const char *, char *, size_t);

#ifdef ENABLE_ACL
extern const char FIX_ACL_ACCESS[];
extern const char FIX_ACL_DEFAULT[];
#endif
