/*
 * $Id$
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>

#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <gfarm/gfarm.h>

#ifdef ENABLE_ACL
#include <attr/xattr.h>
#include <sys/acl.h>

#include "gfarm2fs.h"
#include "acl.h"
#include "xattr.h"

static char *progname = "gfarm2fs_fix_acl";

static gfarm_error_t
mode_from_posix_acl_xattr(const char *path, const void *posix_xattr_value,
			  size_t size, mode_t *modep)
{
	gfarm_error_t e;
	const void *p = posix_xattr_value;
	const void *endp = p + size;
	gfarm_uint32_t version, id;
	gfarm_uint16_t tag, perm;
	mode_t mode = 0;

	memcpy(&version, p, sizeof(version));
	p += sizeof(version);
	if (p > endp)
		return (GFARM_ERR_INVALID_ARGUMENT);
	if (gfarm_ltoh_32(version) != ACL_EA_VERSION)
		return (GFARM_ERR_INVALID_ARGUMENT);
	e = GFARM_ERR_NO_ERROR;
	while (p < endp) {
		memcpy(&tag, p, sizeof(tag));
		p += sizeof(tag);
		memcpy(&perm, p, sizeof(perm));
		p += sizeof(perm);
		memcpy(&id, p, sizeof(id));
		p += sizeof(id);

		tag = gfarm_ltoh_16(tag);
		perm = gfarm_ltoh_16(perm);

		switch (tag) {
		case ACL_USER_OBJ:
			mode |= perm << 6;
			break;
		case ACL_GROUP_OBJ:
			mode |= perm << 3;
			break;
		case ACL_OTHER:
			mode |= perm;
			break;
		case ACL_USER:
		case ACL_GROUP:
		case ACL_MASK:
			/* do nothing */
			break;
		default:
			e = GFARM_ERR_INVALID_ARGUMENT;
			break;
		}
	}
	*modep = mode;

	return (e);
}

static int
check_acl_access(const char *path, struct stat *stbufp,
		 int do_chmod, int do_remove)
{
	gfarm_error_t e;
	ssize_t size, size2;
	void *value;
	mode_t mode;
	int res;

	size = lgetxattr(path, FIX_ACL_ACCESS, NULL, 0);
	if (size == -1) {
		if (errno == ENODATA || errno == ENOATTR)
			return (0); /* ignore */
		fprintf(stderr, "%s: lgetxattr(): %s\n",
			path, strerror(errno));
		return (-1);
	}

	if (!S_ISLNK(stbufp->st_mode)) {
		GFARM_MALLOC_ARRAY(value, size);
		if (value == NULL) {
			fprintf(stderr, "%s: error: no memory\n", path);
			return (-1);
		}
		size2 = lgetxattr(path, FIX_ACL_ACCESS, value, size);
		if (size2 == -1) {
			fprintf(stderr, "%s: lgetxattr(): %s\n",
				path, strerror(errno));
			free(value);
			return (-1);
		} else if (size != size2) {
			fprintf(stderr,
				"%s: lgetxattr(): unexpected size\n", path);
			free(value);
			return (-1);
		}
		e = mode_from_posix_acl_xattr(path, value, size, &mode);
		if (e != GFARM_ERR_NO_ERROR) {
			fprintf(stderr,
				"%s: mode_from_posix_acl_xattr(): %s\n",
				path, gfarm_error_string(e));
			free(value);
			return (-1);
		}
		free(value);
		mode = (stbufp->st_mode & 07000) | mode;
		printf("%s (%o): %s\n", ACL_EA_ACCESS, mode, path);
		if (do_chmod) {
			res = chmod(path, mode);
			if (res == -1) {
				fprintf(stderr, "%s: chmod(): %s\n",
					path, strerror(errno));
				return (-1);
			}
			printf("change mode: %o -> %o\n",
			       stbufp->st_mode & 07777, mode);
		}
	} else
		printf("%s (symlink): %s\n", ACL_EA_ACCESS, path);

	if (do_remove) {
		res = lremovexattr(path, FIX_ACL_ACCESS);
		if (res == -1) {
			fprintf(stderr, "%s: lremovexattr(): %s\n",
				path, strerror(errno));
			return (-1);
		}
	}

	return (0);
}

static int
check_acl_default(const char *path, struct stat *stbufp, int do_remove)
{
	ssize_t size;
	int res;

	size = lgetxattr(path, FIX_ACL_DEFAULT, NULL, 0);
	if (size == -1) {
		if (errno == ENODATA || errno == ENOATTR)
			return (0); /* ignore */
		fprintf(stderr, "%s: lgetxattr(): %s\n",
			path, strerror(errno));
		return (-1);
	}
	printf("%s: %s\n", ACL_EA_DEFAULT, path);
	if (do_remove) {
		res = lremovexattr(path, FIX_ACL_DEFAULT);
		if (res == -1) {
			fprintf(stderr, "%s: lremovexattr(): %s\n",
				path, strerror(errno));
			return (-1);
		}
	}

	return (0);
}

static void
usage(FILE *out)
{
	fprintf(out,
"Fix the ACL extended attribute (xattr) problem on gfarm2fs-1.2.2 or older.\n"
"The wrong xattr exists if 'cp -p' or 'mv' have been used on gfarm2fs.\n"
"Usage: %s [-cr] filename\n"
"    default: Print paths which have wrong xattrs. (do nothing)\n"
"    -c: Do chmod() using system.posix_acl_access xattr.\n"
"    -r: Remove useless system.posix_acl_{access,default} xattrs.\n"
"        (Not remove gfarm.acl_{access,default} xattrs.)\n"
"Example: find . -exec %s -cr {} \\;\n",
		progname, progname);
}

int
main(int argc, char **argv)
{
	struct stat stbuf;
	int i, c, res;
	int do_chmod = 0, do_remove = 0, error = 0;

	if (argc > 0)
		progname = basename(argv[0]);
	while ((c = getopt(argc, argv, "crh?")) != -1) {
		switch (c) {
		case 'c':
			do_chmod = 1;
			break;
		case 'r':
			do_remove = 1;
			break;
		case 'h':
		case '?':
			usage(stdout);
			return (0);
		default:
			usage(stderr);
			return (1);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc <= 0) {
		usage(stderr);
		return (1);
	}

	for (i = 0; i < argc; i++) {
		char *path = argv[i];

		res = lstat(path, &stbuf);
		if (res == -1) {
			fprintf(stderr, "%s: lstat(): %s\n",
				path, strerror(errno));
			error++;
			continue;
		}
		res = check_acl_access(path, &stbuf, do_chmod, do_remove);
		if (res == 0)
			res = check_acl_default(path, &stbuf, do_remove);
		if (res == -1)
			error++;
	}

	return (error);
}

#else
int main() { return (1); }
#endif
