/*
 * $Id$
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <gfarm/gfarm.h>
#include "gfarm2fs.h"
#include "id.h"
#include "acl.h"
#include "gfarm2fs_msg_enums.h"

const char ACL_EA_ACCESS[] = "system.posix_acl_access";
const char ACL_EA_DEFAULT[] = "system.posix_acl_default";

#ifdef ENABLE_ACL  /* with HAVE_SYS_ACL_H */
#include <sys/acl.h>

#define ADD_BUF(src, size) \
	do { \
		if (nowlen + size > bufsize) { \
			/* unexpected */ \
			gflog_error(GFARM_MSG_2000095, \
				    "unexpected acl entries size"); \
			free(buf); \
			return (GFARM_ERR_INVALID_ARGUMENT); \
		} \
		memcpy(buf + nowlen, src, size); \
		nowlen += size; \
	} while (0)

/* size: version=4 + (tag=2, perm=2, id=4) * num of entries */
#define ACL_BUFSIZE(acl) (4 + gfs_acl_entries(acl) * 8)

/* to get ACL */
static gfarm_error_t
gfarm2fs_gfarm_acl_to_posix_acl_xattr(
	const char *url, const gfarm_acl_t acl,
	void **posix_xattr_value_p, size_t *sizep)
{
	gfarm_error_t e;
	void *buf;
	int nowlen = 0, bufsize;
	gfarm_uint32_t i32;
	gfarm_uint16_t i16;
	gfarm_acl_tag_t tag;
	gfarm_acl_perm_t perm;
	uid_t uid;
	gid_t gid;
	gfarm_acl_entry_t ent;
	gfarm_acl_permset_t pset;
	char *s;
	int bool;

	if (acl == NULL || posix_xattr_value_p == NULL || sizep == NULL) {
		gflog_debug(GFARM_MSG_2000096,
			    "invalid argument of "
			    "gfarm2fs_gfarm_acl_to_posix_acl_xattr()");
		return (GFARM_ERR_INVALID_ARGUMENT);
	}

	bufsize = ACL_BUFSIZE(acl);
	GFARM_MALLOC_ARRAY(buf, bufsize);
	if (buf == NULL) {
		gflog_debug(GFARM_MSG_2000097, "no memory for getting ACL");
		return (GFARM_ERR_NO_MEMORY);
	}

	i32 = gfarm_htol_32(ACL_EA_VERSION);
	ADD_BUF(&i32, sizeof(i32));

	e = gfs_acl_get_entry(acl, GFARM_ACL_FIRST_ENTRY, &ent);
	while (e == GFARM_ERR_NO_ERROR) {
		gfs_acl_get_tag_type(ent, &tag);
		/* gfarm_acl_tag to posix_acl_tag */
		i16 = gfarm_htol_16((gfarm_uint16_t)tag);
		ADD_BUF(&i16, sizeof(i16));

		/* gfarm_acl_perm to posix_acl_perm */
		perm = 0;
		gfs_acl_get_permset(ent, &pset);
		gfs_acl_get_perm(pset, GFARM_ACL_READ, &bool);
		if (bool)
			perm |= ACL_READ;
		gfs_acl_get_perm(pset, GFARM_ACL_WRITE, &bool);
		if (bool)
			perm |= ACL_WRITE;
		gfs_acl_get_perm(pset, GFARM_ACL_EXECUTE, &bool);
		if (bool)
			perm |= ACL_EXECUTE;

		i16 = gfarm_htol_16((gfarm_uint16_t)perm);
		ADD_BUF(&i16, sizeof(i16));

		gfs_acl_get_qualifier(ent, &s);

		if (tag == GFARM_ACL_USER) {
			e = gfarm2fs_get_uid(url, s, &uid);
			if (e != GFARM_ERR_NO_ERROR) {
				free(buf);
				return (e);
			}
			i32 = gfarm_htol_32((gfarm_uint32_t)uid);
		} else if (tag == GFARM_ACL_GROUP) {
			e = gfarm2fs_get_gid(url, s, &gid);
			if (e != GFARM_ERR_NO_ERROR) {
				free(buf);
				return (e);
			}
			i32 = gfarm_htol_32((gfarm_uint32_t)gid);
		} else
			i32 = gfarm_htol_32((gfarm_uint32_t)ACL_UNDEFINED_ID);
		ADD_BUF(&i32, sizeof(i32));

		e = gfs_acl_get_entry(acl, GFARM_ACL_NEXT_ENTRY, &ent);
	}
	if (e == GFARM_ERR_NO_SUCH_OBJECT)
		e = GFARM_ERR_NO_ERROR;
	if (e != GFARM_ERR_NO_ERROR) {
		free(buf);
		return (e);
	}

	if (nowlen == 0) {
		free(buf);
		*posix_xattr_value_p = NULL;
		*sizep = 0;
	} else {
		*posix_xattr_value_p = buf;
		*sizep = nowlen;
	}
	return (GFARM_ERR_NO_ERROR);
}

/* to set ACL */
static gfarm_error_t
gfarm2fs_gfarm_acl_from_posix_acl_xattr(
	const char *url, const void *posix_xattr_value,
	size_t size, gfarm_acl_t *acl_p)
{
	gfarm_error_t e;
	gfarm_acl_t acl;
	gfarm_acl_entry_t ent;
	gfarm_acl_permset_t pset;
	const void *p = posix_xattr_value;
	const void *endp = p + size;
	gfarm_uint32_t version, id;
	gfarm_uint16_t tag, perm;
	char *qual;
	gfarm_acl_tag_t tag2;
	uid_t uid;
	gid_t gid;

	memcpy(&version, p, sizeof(version));
	p += sizeof(version);
	if (p > endp)
		return (GFARM_ERR_INVALID_ARGUMENT);
	if (gfarm_ltoh_32(version) != ACL_EA_VERSION)
		return (GFARM_ERR_INVALID_ARGUMENT);
	e = gfs_acl_init(5, &acl);
	if (e != GFARM_ERR_NO_ERROR)
		return (e);
	while (p < endp) {
		memcpy(&tag, p, sizeof(tag));
		p += sizeof(tag);
		memcpy(&perm, p, sizeof(perm));
		p += sizeof(perm);
		memcpy(&id, p, sizeof(id));
		p += sizeof(id);

		e = gfs_acl_create_entry(&acl, &ent);
		if (e != GFARM_ERR_NO_ERROR)
			goto fail;

		tag2 = gfarm_ltoh_16(tag);
		/* posix_acl_tag to gfarm_acl_tag */
		gfs_acl_set_tag_type(ent, tag2);

		gfs_acl_get_permset(ent, &pset);
		/* posix_acl_perm to gfarm_acl_perm */
		gfs_acl_add_perm(pset, gfarm_ltoh_16(perm));
		gfs_acl_set_permset(ent, pset);

		switch (tag2) {
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			qual = NULL;
			gfs_acl_set_qualifier(ent, NULL);
			break;
		case ACL_USER:
			uid = (uid_t) gfarm_ltoh_32(id);
			e = gfarm2fs_get_user(url, uid, &qual);
			if (e != GFARM_ERR_NO_ERROR)
				goto fail;
			gfs_acl_set_qualifier(ent, qual);
			break;
		case ACL_GROUP:
			gid = (gid_t) gfarm_ltoh_32(id);
			e = gfarm2fs_get_group(url, gid, &qual);
			if (e != GFARM_ERR_NO_ERROR)
				goto fail;
			gfs_acl_set_qualifier(ent, qual);
			break;
		default:
			e = GFARM_ERR_INVALID_ARGUMENT;
			goto fail;
		}
	}
	*acl_p = acl;
	return (GFARM_ERR_NO_ERROR);
fail:
	gfs_acl_free(acl);
	return (e);
}

/* ------------------------------- */

gfarm_error_t
gfarm2fs_acl_set(const char *path, gfarm_acl_type_t type,
		 const void *value, size_t size)
{
	gfarm_error_t e;
	gfarm_acl_t acl;

	e = gfarm2fs_gfarm_acl_from_posix_acl_xattr(path, value, size, &acl);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_debug(GFARM_MSG_2000098,
			"gfarm2fs_gfarm_acl_from_posix_acl_xattr(%s) failed"
			": %s", path, gfarm_error_string(e));
		return (e);
	}
	gfs_acl_sort(acl);
	e = gfs_acl_set_file(path, type, acl);
	if (e != GFARM_ERR_NO_ERROR)
		gflog_debug(GFARM_MSG_2000099,
			    "gfs_acl_set_file(%s) failed: %s",
			    path, gfarm_error_string(e));
	gfs_acl_free(acl);

	return (e);
}

gfarm_error_t
gfarm2fs_acl_get(const char *path, gfarm_acl_type_t type,
		 void *value, size_t *sizep)
{
	gfarm_error_t e;
	gfarm_acl_t acl;
	size_t size;
	void *posix;

	e = gfs_acl_get_file_cached(path, type, &acl);
	if (e != GFARM_ERR_NO_ERROR)
		return (e);

	if (*sizep == 0) {
		*sizep = ACL_BUFSIZE(acl);
		goto free_acl;
	}

	e = gfarm2fs_gfarm_acl_to_posix_acl_xattr(path, acl, &posix, &size);
	if (e != GFARM_ERR_NO_ERROR) {
		gflog_debug(GFARM_MSG_2000100,
			"gfarm2fs_gfarm_acl_to_posix_acl_xattr() failed: %s",
			gfarm_error_string(e));
		goto free_acl;
	}
	if (size > *sizep) {
		e = GFARM_ERR_RESULT_OUT_OF_RANGE;
		gflog_error(GFARM_MSG_2000101,
			    "unexpected error: acl size > buf size");
		goto free_posix;
	}
	if (value != NULL)
		memcpy(value, posix, size);
free_posix:
	*sizep = size;
	free(posix);
free_acl:
	gfs_acl_free(acl);

	return (e);
}

#endif /* ENABLE_ACL */
