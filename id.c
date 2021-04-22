/*
 * $Id$
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>

#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <gfarm/gfarm.h>
#include "gfarm2fs.h"
#include "id.h"
#include "hash.h"
#include "gfarm2fs_msg_enums.h"

static struct gfarm_hash_table *hash_uid_to_user;
static struct gfarm_hash_table *hash_gid_to_group;
static struct gfarm_hash_table *hash_user_to_uid;
static struct gfarm_hash_table *hash_group_to_gid;

#include <signal.h>
static volatile sig_atomic_t next_auto_uid;
static volatile sig_atomic_t next_auto_gid;

static uid_t auto_uid_min;
static uid_t auto_uid_max;
static gid_t auto_gid_min;
static gid_t auto_gid_max;

static int enable_cached_id = 0; /* for debug */

static pthread_mutex_t mutex_group = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mutex_user = PTHREAD_MUTEX_INITIALIZER;

static size_t bufsiz_grp = 1024; /* default */
static size_t bufsiz_pwd = 1024; /* default */

static void
id_mutex_lock(pthread_mutex_t *mutex)
{
	int rv;
	rv = pthread_mutex_lock(mutex);
	assert(rv == 0);
}

static void
id_mutex_unlock(pthread_mutex_t *mutex)
{
	int rv;
	rv = pthread_mutex_unlock(mutex);
	assert(rv == 0);
}

static int
id_hash_index(const void *k, int l)
{
	return (*(int *)k);
}

static int
id_hash_equal(const void *k1, int k1len, const void *k2, int k2len)
{
	return (*(gfarm_uint32_t *)k1 == *(gfarm_uint32_t *)k2);
}

static int primes[] = {
	5,
	11,
	19,
	37,
	67,
	131,
	257,
	521,
	1031,
	2053,
	4099,
	8209,
	16411,
	32771
};

static int
next_prime(int n)
{
	int i, nprimes = sizeof(primes) / sizeof(int);

	for (i = 0; i < nprimes; i++)
		if (primes[i] > n)
			return (primes[i]);

	return (primes[nprimes - 1]);
}

void
gfarm2fs_id_init(struct gfarm2fs_param *params)
{
	int auto_uid_hash_size, auto_gid_hash_size;
	size_t size;

	enable_cached_id = params->enable_cached_id; /* for debug */

	auto_uid_min = params->auto_uid_min;
	auto_uid_max = params->auto_uid_max;
	auto_gid_min = params->auto_gid_min;
	auto_gid_max = params->auto_gid_max;

	if (auto_uid_min >= auto_uid_max) {
		gflog_error(GFARM_MSG_2000102,
			    "illegal parameter: "
			    "auto_uid_min(%d) >= auto_uid_max(%d)",
			    auto_uid_min, auto_uid_max);
		exit(1);
	}
	if (auto_gid_min >= auto_gid_max) {
		gflog_error(GFARM_MSG_2000103,
			    "illegal parameter: "
			    "auto_gid_min(%d) >= auto_gid_max(%d)",
			    auto_gid_min, auto_gid_max);
		exit(1);
	}
	auto_uid_hash_size = next_prime((auto_uid_max - auto_uid_min) / 8);
	auto_gid_hash_size = next_prime((auto_gid_max - auto_gid_min) / 8);

	hash_uid_to_user = gfarm_hash_table_alloc(
		auto_uid_hash_size, id_hash_index, id_hash_equal);
	hash_gid_to_group = gfarm_hash_table_alloc(
		auto_gid_hash_size, id_hash_index, id_hash_equal);
	hash_user_to_uid = gfarm_hash_table_alloc(
		auto_uid_hash_size, gfarm_hash_strptr,
		gfarm_hash_key_equal_strptr);
	hash_group_to_gid = gfarm_hash_table_alloc(
		auto_gid_hash_size, gfarm_hash_strptr,
		gfarm_hash_key_equal_strptr);
	if (hash_uid_to_user == NULL || hash_gid_to_group == NULL ||
	    hash_user_to_uid == NULL || hash_group_to_gid == NULL)
		gflog_fatal(GFARM_MSG_2000104, "no memory for id hashtab");

	next_auto_uid = (sig_atomic_t) auto_uid_min;
	next_auto_gid = (sig_atomic_t) auto_gid_min;

	size = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (size > 0)
		bufsiz_grp = size;
	size = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (size > 0)
		bufsiz_pwd = size;
}

static gfarm_error_t
user_name_to_uid(const char *name, gfarm_uint32_t *uidp)
{
	struct passwd pwd, *result;
	char *buf;
	int rv;
	gfarm_error_t e;

	for (;;) {
		if ((buf = malloc(bufsiz_pwd)) == NULL) {
			gflog_error(GFARM_MSG_2000127,
			    "no memory for user %s(size=%zu)",
			    name, bufsiz_pwd);
			return (GFARM_ERR_NO_MEMORY);
		}
		rv = getpwnam_r(name, &pwd, buf, bufsiz_pwd, &result);
		if (rv == ERANGE) {
			free(buf);
			bufsiz_pwd *= 2;
			continue;
		}
		break;
	}
	if (result != NULL) {
		*uidp = (gfarm_uint32_t) result->pw_uid;
		e = GFARM_ERR_NO_ERROR;
	} else
		e = GFARM_ERR_NO_SUCH_OBJECT;
	free(buf);
	return (e);
}

static gfarm_error_t
group_name_to_gid(const char *name, gfarm_uint32_t *gidp)
{
	struct group grp, *result;
	char *buf;
	int rv;
	gfarm_error_t e;

	for (;;) {
		if ((buf = malloc(bufsiz_grp)) == NULL) {
			gflog_error(GFARM_MSG_2000128,
			    "no memory for group %s(size=%zu)",
			    name, bufsiz_grp);
			return (GFARM_ERR_NO_MEMORY);
		}
		rv = getgrnam_r(name, &grp, buf, bufsiz_grp, &result);
		if (rv == ERANGE) {
			free(buf);
			bufsiz_grp *= 2;
			continue;
		}
		break;
	}
	if (result != NULL) {
		*gidp = (gfarm_uint32_t) result->gr_gid;
		e = GFARM_ERR_NO_ERROR;
	} else
		e = GFARM_ERR_NO_SUCH_OBJECT;
	free(buf);
	return (e);
}

/* If *bufp is not NULL, *bufp must be free()ed later. */
static gfarm_error_t
user_uid_to_name(gfarm_uint32_t uid, char **namep, char **bufp)
{
	struct passwd pwd, *result;
	char *buf;
	int rv;

	*bufp = NULL;
	for (;;) {
		if ((buf = malloc(bufsiz_pwd)) == NULL) {
			gflog_error(GFARM_MSG_2000129,
			    "no memory for uid %d(size=%zu)",
			    uid, bufsiz_pwd);
			return (GFARM_ERR_NO_MEMORY);
		}
		rv = getpwuid_r(uid, &pwd, buf, bufsiz_pwd, &result);
		if (rv == ERANGE) {
			free(buf);
			bufsiz_pwd *= 2;
			continue;
		}
		break;
	}
	if (result != NULL) {
		*bufp = buf;
		*namep = pwd.pw_name;
		return (GFARM_ERR_NO_ERROR);
	} else {
		free(buf);
		return (GFARM_ERR_NO_SUCH_OBJECT);
	}
}

/* If *bufp is not NULL, *bufp must be free()ed later. */
static gfarm_error_t
group_gid_to_name(gfarm_uint32_t gid, char **namep, char **bufp)
{
	struct group grp, *result;
	char *buf;
	int rv;

	*bufp = NULL;
	for (;;) {
		if ((buf = malloc(bufsiz_grp)) == NULL) {
			gflog_error(GFARM_MSG_2000130,
			    "no memory for gid %d(size=%zu)",
			    gid, bufsiz_grp);
			return (GFARM_ERR_NO_MEMORY);
		}
		rv = getgrgid_r(gid, &grp, buf, bufsiz_grp, &result);
		if (rv == ERANGE) {
			free(buf);
			bufsiz_grp *= 2;
			continue;
		}
		break;
	}
	if (result != NULL) {
		*bufp = buf;
		*namep = grp.gr_name;
		return (GFARM_ERR_NO_ERROR);
	} else {
		free(buf);
		return (GFARM_ERR_NO_SUCH_OBJECT);
	}
}

static gfarm_error_t
global_user_to_local_uid(
	const char *url, const char *user, gfarm_uint32_t *uidp)
{
	gfarm_error_t e;
	char *luser, *guser;

	if ((e = gfarm_get_global_username_by_url(url, &guser))
	    != GFARM_ERR_NO_ERROR) {
		gflog_debug(GFARM_MSG_2000105,
			    "gfarm_get_global_username_by_url() failed: %s",
			    gfarm_error_string(e));
		return (e);
	}
	if (strcmp(guser, user) == 0) {
		free(guser);
		*uidp = (gfarm_uint32_t) getuid(); /* my own file */
		return (GFARM_ERR_NO_ERROR);
	}
	free(guser);
	if (gfarm_global_to_local_username_by_url(url, user, &luser)
	    == GFARM_ERR_NO_ERROR) {
		e = user_name_to_uid(luser, uidp);
		free(luser);
		return (e);
	}
	return (GFARM_ERR_NO_SUCH_OBJECT); /* unknown local user */
}

static gfarm_error_t
global_group_to_local_gid(
	const char *url, const char *group, gfarm_uint32_t *gidp)
{
	gfarm_error_t e;
	char *lgroup;

	if (gfarm_global_to_local_groupname_by_url(url, group, &lgroup)
	    == GFARM_ERR_NO_ERROR) {
		e = group_name_to_gid(lgroup, gidp);
		free(lgroup);
		return (e);
	}
	return (GFARM_ERR_NO_SUCH_OBJECT); /* unknown local group */
}

/* returned string should be free'ed if it is not NULL */
static gfarm_error_t
local_uid_to_global_user(const char *url, gfarm_uint32_t uid, char **userp)
{
	gfarm_error_t e;
	char *buf, *name;

	*userp = NULL;
	if (uid == (gfarm_uint32_t)getuid()) {
		e = gfarm_get_global_username_by_url(url, userp);
		if (e != GFARM_ERR_NO_ERROR)
			gflog_error(GFARM_MSG_2000106,
			    "gfarm_get_global_username_by_url() failed: %s",
			    gfarm_error_string(e));
		return (e);
	}
	/* use the user map file to identify the global user */
	e = user_uid_to_name(uid, &name, &buf);
	if (e == GFARM_ERR_NO_ERROR)
		e = gfarm_local_to_global_username_by_url(
		    url, name, userp);
	free(buf);
	return (e);
}

/* returned string should be free'ed if it is not NULL */
static gfarm_error_t
local_gid_to_global_group(const char *url, gfarm_uint32_t gid, char **groupp)
{
	gfarm_error_t e;
	char *buf, *name;

	*groupp = NULL;
	/* use the group map file to identify the global group */
	e = group_gid_to_name(gid, &name, &buf);
	if (e == GFARM_ERR_NO_ERROR)
		e = gfarm_local_to_global_groupname_by_url(
		    url, name, groupp);
	free(buf);
	return (e);
}

static gfarm_error_t
auto_name_to_id(struct gfarm_hash_table *name_to_id,
		const char *name, gfarm_uint32_t *idp)
{
	struct gfarm_hash_entry *entry;

	entry = gfarm_hash_lookup(name_to_id, &name, sizeof(name));
	if (entry != NULL) {
		*idp = *(gfarm_uint32_t *)gfarm_hash_entry_data(entry);
		return (GFARM_ERR_NO_ERROR);
	}
	return (GFARM_ERR_NO_SUCH_OBJECT);
}

/* returned string should be free'ed if it is not NULL */
static gfarm_error_t
auto_id_to_name(struct gfarm_hash_table *id_to_name,
		gfarm_uint32_t id, char **namep)
{
	struct gfarm_hash_entry *entry;

	*namep = NULL;
	entry = gfarm_hash_lookup(id_to_name, &id, sizeof(id));
	if (entry != NULL) {
		*namep = strdup(*(char **)gfarm_hash_entry_data(entry));
		if (*namep == NULL) {
			gflog_error(GFARM_MSG_2000107,
				    "no memory for auto uid/gid");
			return (GFARM_ERR_NO_MEMORY);
		}
		return (GFARM_ERR_NO_ERROR);
	}
	return (GFARM_ERR_NO_SUCH_OBJECT);
}

static gfarm_error_t
id_and_name_enter(gfarm_uint32_t id, const char *name,
		  struct gfarm_hash_table *hash_id_to_name,
		  struct gfarm_hash_table *hash_name_to_id)
{
	struct gfarm_hash_entry *entry1, *entry2;
	int created;
	char *str;
	char *type = (hash_id_to_name == hash_uid_to_user ? "uid" : "gid");

	str = strdup(name);
	if (str == NULL)
		goto nomem;
	/* uid to user */
	entry1 = gfarm_hash_enter(hash_id_to_name, &id, sizeof(gfarm_uint32_t),
				 sizeof(char *), &created);
	if (entry1 == NULL) {
		free(str);
		goto nomem;
	}
	if (!created) {
		free(str);
		return (GFARM_ERR_ALREADY_EXISTS);
	}
	/* user to uid */
	entry2 = gfarm_hash_enter(hash_name_to_id, &str, sizeof(str),
				  sizeof(gfarm_uint32_t), &created);
	if (entry2 == NULL) {
		free(str);
		gfarm_hash_purge(hash_id_to_name, &id, sizeof(gfarm_uint32_t));
		goto nomem;
	}
	if (!created) {
		gfarm_hash_purge(hash_id_to_name, &id, sizeof(gfarm_uint32_t));
		gfarm_hash_purge(hash_name_to_id, &str, sizeof(str));
		free(str);
		gflog_error(GFARM_MSG_2000108,
			    "unexpected: inconsistent auto %s(name=%s)",
			    type, name);
		return (GFARM_ERR_ALREADY_EXISTS);
	}

	*(char **)gfarm_hash_entry_data(entry1) = str;
	*(gfarm_uint32_t *)gfarm_hash_entry_data(entry2) = id;

#if 0  /* for debug */
	{
		gfarm_uint32_t i;
		char *s;
		printf("----- start of debug id.c -----\n");
		for (i = auto_uid_min; i <= next_auto_uid; i++) {
			auto_id_to_name(hash_uid_to_user, i, &s);
			if (s != NULL) {
				printf("uid[%d]: user=%s\n", i, s);
				free(s);
			}
		}
		for (i = auto_gid_min; i <= next_auto_gid; i++) {
			auto_id_to_name(hash_gid_to_group, i, &s);
			if (s != NULL) {
				printf("gid[%d]: group=%s\n", i, s);
				free(s);
			}
		}
		printf("----- end of debug id.c -----\n");
	}
#endif
	return (GFARM_ERR_NO_ERROR);
nomem:
	gflog_error(GFARM_MSG_2000109,
		    "no memory for auto %s(name=%s)", type, name);
	return (GFARM_ERR_NO_MEMORY);
}

static gfarm_error_t
global_name_to_local_id(
	const char *url, const char *name,
	struct gfarm_hash_table *hash_id_to_name,
	struct gfarm_hash_table *hash_name_to_id,
	gfarm_error_t (*global_name_to_local_id_func)(
		const char *, const char *, gfarm_uint32_t *),
	gfarm_error_t (*local_id_to_global_name_func)(
		const char *, gfarm_uint32_t, char **),
	volatile sig_atomic_t *next_auto_id_p, const gfarm_uint32_t *id_max_p,
	gfarm_uint32_t *return_id_p)
{
	gfarm_error_t e;
	int checked_cache = 0;

	if (enable_cached_id) { /* for debug: use cached id any time */
		if (auto_name_to_id(hash_name_to_id, name, return_id_p)
		    == GFARM_ERR_NO_ERROR)
			return (GFARM_ERR_NO_ERROR);
		checked_cache = 1;
	}

	/*
	 * Assuming a new local user/group is added, getpwnam() or
	 * getgrnam() are checked every time.
	 */
	if (global_name_to_local_id_func(url, name, return_id_p)
	    == GFARM_ERR_NO_ERROR) {
		if (enable_cached_id) /* for debug: cache all mapping */
			id_and_name_enter(*return_id_p, name,
					  hash_id_to_name, hash_name_to_id);
		return (GFARM_ERR_NO_ERROR);
	}

	if (checked_cache == 0 &&
	    auto_name_to_id(hash_name_to_id, name, return_id_p)
	    == GFARM_ERR_NO_ERROR)
		return (GFARM_ERR_NO_ERROR);

	/* search unused id number */
	do {
		char *str;

		do {
			*return_id_p = (gfarm_uint32_t) *next_auto_id_p;
			(*next_auto_id_p)++;
		} while (*return_id_p + 1 != *next_auto_id_p);

		if (*return_id_p >= *id_max_p) {
			char *type = (hash_id_to_name == hash_uid_to_user ?
				      "uid" : "gid");
			gflog_warning(GFARM_MSG_2000110,
				      "lack of auto_%s: name=%s", type, name);
			return (GFARM_ERR_OPERATION_NOT_PERMITTED); /* EPERM */
		}
		e = local_id_to_global_name_func(url, *return_id_p, &str);
		if (e != GFARM_ERR_NO_ERROR && e != GFARM_ERR_NO_SUCH_OBJECT)
			return (e);
		if (str == NULL) /* found unused uid/gid */
			break;
		free(str);
	} while (1);

	/*
	 * If globaluser1@gfmd1 and globaluser2@gfmd2 are the same
	 * name, they have the same id.
	 */
	e = id_and_name_enter(*return_id_p, name,
			      hash_id_to_name, hash_name_to_id);
	if (e != GFARM_ERR_NO_ERROR)
		return (e);

	return (GFARM_ERR_NO_ERROR);
}

/* --------------------------------------------------------------------- */

gfarm_error_t
gfarm2fs_get_uid(const char *url, const char *user, uid_t *uidp)
{

	gfarm_uint32_t id;
	gfarm_error_t e;

	id_mutex_lock(&mutex_user);
	e = global_name_to_local_id(url, user,
				    hash_uid_to_user, hash_user_to_uid,
				    global_user_to_local_uid,
				    local_uid_to_global_user,
				    &next_auto_uid, &auto_uid_max, &id);
	if (e == GFARM_ERR_NO_ERROR)
		*uidp = (uid_t) id;
	id_mutex_unlock(&mutex_user);

	return (e);
}

gfarm_error_t
gfarm2fs_get_gid(const char *url, const char *group, gid_t *gidp)
{
	gfarm_uint32_t id;
	gfarm_error_t e;

	id_mutex_lock(&mutex_group);
	e = global_name_to_local_id(url, group,
				    hash_gid_to_group, hash_group_to_gid,
				    global_group_to_local_gid,
				    local_gid_to_global_group,
				    &next_auto_gid, &auto_gid_max, &id);
	if (e == GFARM_ERR_NO_ERROR)
		*gidp = (gid_t) id;
	id_mutex_unlock(&mutex_group);

	return (e);
}

/* returned string should be free'ed if it is not NULL */
gfarm_error_t
gfarm2fs_get_user(const char *url, uid_t uid, char **userp)
{
	gfarm_error_t e;

	/*
	 * Assuming a new local user/group is added, getpwuid() is
	 * checked every time.
	 */
	e = local_uid_to_global_user(url, (gfarm_uint32_t)uid, userp);
	if (e != GFARM_ERR_NO_SUCH_OBJECT)
		return (e);  /* success or error */

	id_mutex_lock(&mutex_user);
	e = auto_id_to_name(hash_uid_to_user, (gfarm_uint32_t)uid, userp);
	id_mutex_unlock(&mutex_user);
	if (e == GFARM_ERR_NO_SUCH_OBJECT) {
		gflog_debug(GFARM_MSG_2000111,
			    "cannot convert uid(%d) to gfarm username", uid);
		return (GFARM_ERR_OPERATION_NOT_PERMITTED); /* EPERM */
	} else
		return (e);
}

/* returned string should be free'ed if it is not NULL */
gfarm_error_t
gfarm2fs_get_group(const char *url, gid_t gid, char **groupp)
{
	gfarm_error_t e;

	/*
	 * Assuming a new local user/group is added, getgrgid() is
	 * checked every time.
	 */
	e = local_gid_to_global_group(url, (gfarm_uint32_t)gid, groupp);
	if (e != GFARM_ERR_NO_SUCH_OBJECT)
		return (e);  /* success or error */

	id_mutex_lock(&mutex_group);
	e = auto_id_to_name(hash_gid_to_group, (gfarm_uint32_t)gid, groupp);
	id_mutex_unlock(&mutex_group);
	if (e == GFARM_ERR_NO_SUCH_OBJECT) {
		gflog_debug(GFARM_MSG_2000112,
			    "cannot convert gid(%d) to gfarm groupname", gid);
		return (GFARM_ERR_OPERATION_NOT_PERMITTED); /* EPERM */
	} else
		return (e);
}

uid_t
gfarm2fs_get_nobody_uid()
{
	gfarm_error_t e;
	uid_t uid;

	id_mutex_lock(&mutex_user); /* protect bufsiz_pwd */
	e = user_name_to_uid("nobody", &uid);
	id_mutex_unlock(&mutex_user);

	if (e == GFARM_ERR_NO_ERROR)
		return (uid);
	else
		return (auto_uid_max);
}

gid_t
gfarm2fs_get_nogroup_gid()
{
	gfarm_error_t e;
	gid_t gid;

	id_mutex_lock(&mutex_group); /* protect bufsiz_grp */
	e = group_name_to_gid("nogroup", &gid);
	id_mutex_unlock(&mutex_group);

	if (e == GFARM_ERR_NO_ERROR)
		return (gid);
	else
		return (auto_gid_max);
}
