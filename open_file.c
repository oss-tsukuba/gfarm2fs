/*
 * $Id$
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gfarm/gfarm.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <stddef.h>

#include "gfarm2fs_msg_enums.h"
#include "gfarm2fs.h"
#include "hash.h"

struct opening {
	struct opening *next;
	struct gfarm2fs_file *fp;
	int writing;
};

struct inode_openings {
	struct opening *openings;
	struct gfarm2fs_file *fp_cached;
};

struct open_file_key {
	gfarm_ino_t inum;

	/*
	 * Variable-length member.  This must be the last member.
	 */
	char metadb[1];
};

static struct open_file_key *
open_file_key_alloc(const struct gfarmized_path *gp,
	 gfarm_ino_t inum, int *keylenp)
{
	const char *metadb = gp->metadb != NULL ? gp->metadb : "";
	size_t len = strlen(metadb) + 1;
	size_t keylen = offsetof(struct open_file_key, metadb) + len;
	struct open_file_key *key = malloc(keylen);

	if (key == NULL) {
		gflog_error(GFARM_MSG_UNFIXED,
		    "no memory to allocate key for inode %lld",
		    (unsigned long long)inum);
		return (NULL);
	}
	key->inum = inum;
	memcpy(key->metadb, metadb, len);
	*keylenp = (int)keylen;
	return (key);
}

static struct gfarm_hash_table *open_file_table;
#define OPEN_FILE_TABLE_SIZE	256

static int open_file_hash(const void *k, int l)
{
	const struct open_file_key *key = k;
	int hash;

	hash = gfarm_hash_default(key->metadb, strlen(key->metadb));
	hash = gfarm_hash_add(hash, &key->inum, sizeof(key->inum));

	return (hash);
}

static int open_file_hash_equal(
	const void *k1, int k1len, const void *k2, int k2len)
{
	const struct open_file_key *a = k1, *b = k2;

	return (k1len == k2len && a->inum == b->inum &&
	    strcmp(a->metadb, b->metadb) == 0);
}

static pthread_rwlock_t open_file_table_rwlock;
static pthread_mutex_t open_file_cached_mutex;

static void
open_file_table_lock_init(void)
{
	int rv;

	rv = pthread_rwlock_init(&open_file_table_rwlock, NULL);
	assert(rv == 0);
	rv = pthread_mutex_init(&open_file_cached_mutex, NULL);
	assert(rv == 0);
}

void
gfarm2fs_open_file_table_rdlock(void)
{
	int rv;

	rv = pthread_rwlock_rdlock(&open_file_table_rwlock);
	assert(rv == 0);
}

void
gfarm2fs_open_file_table_wrlock(void)
{
	int rv;

	rv = pthread_rwlock_wrlock(&open_file_table_rwlock);
	assert(rv == 0);
}

void
gfarm2fs_open_file_table_unlock(void)
{
	int rv;

	rv = pthread_rwlock_unlock(&open_file_table_rwlock);
	assert(rv == 0);
}

void
gfarm2fs_open_file_init()
{
	open_file_table = gfarm_hash_table_alloc(
		OPEN_FILE_TABLE_SIZE, open_file_hash, open_file_hash_equal);
	if (open_file_table == NULL)
		gflog_fatal(GFARM_MSG_2000051, "no memory");
	open_file_table_lock_init();
}

struct gfarm2fs_file *
gfarm2fs_open_file_lookup_unlocked(const struct gfarmized_path *gp,
	 gfarm_ino_t inum)
{
	struct open_file_key *key;
	int keylen;
	struct gfarm_hash_entry *entry;
	struct inode_openings *ios;
	struct opening *o;
	struct gfarm2fs_file *rv = NULL;

	key = open_file_key_alloc(gp, inum, &keylen);
	if (key == NULL)
		return (NULL);

	entry = gfarm_hash_lookup(open_file_table, key, keylen);
	free(key);
	if (entry == NULL)
		goto finish;
	ios = gfarm_hash_entry_data(entry);
	pthread_mutex_lock(&open_file_cached_mutex);
	if (ios->fp_cached != NULL) {
		rv = ios->fp_cached;
		pthread_mutex_unlock(&open_file_cached_mutex);
		goto finish;
	}
	for (o = ios->openings; o != NULL; o = o->next) {
		if (o->writing) {
			ios->fp_cached = o->fp;
			rv = ios->fp_cached;
			pthread_mutex_unlock(&open_file_cached_mutex);
			goto finish;
		}
	}
	ios->fp_cached = ios->openings->fp;
	rv = ios->fp_cached;
	pthread_mutex_unlock(&open_file_cached_mutex);
 finish:
	return (rv);
}

void
gfarm2fs_open_file_enter(const struct gfarmized_path *gp,
	struct gfarm2fs_file *fp, int flags)
{
	struct open_file_key *key;
	int keylen;
	gfarm_ino_t inum = fp->inum;
	struct gfarm_hash_entry *entry;
	struct inode_openings *ios;
	struct opening *o;
	int created;

	key = open_file_key_alloc(gp, inum, &keylen);
	if (key == NULL) {
		return;
	}
	o = malloc(sizeof(*o));
	if (o == NULL) {
		gflog_error(GFARM_MSG_2000053,
		    "no memory to cache an opening for inode %lld",
		    (unsigned long long)inum);
		free(key);
		return;
	}

	gfarm2fs_open_file_table_wrlock();
	entry = gfarm_hash_enter(open_file_table, key, keylen,
	    sizeof(*ios), &created);
	free(key);
	if (entry == NULL) {
		gflog_error(GFARM_MSG_2000054,
		    "no memory to insert inode %lld to open file table",
		    (unsigned long long)inum);
		gfarm2fs_open_file_table_unlock();
		return;
	}
	o->fp = fp;
	o->writing =
	    ((flags & O_TRUNC) != 0 || (flags & O_ACCMODE) != O_RDONLY);

	ios = gfarm_hash_entry_data(entry);
	if (!created) {
		o->next = ios->openings;
	} else {
		o->next = NULL;
		pthread_mutex_lock(&open_file_cached_mutex);
		ios->fp_cached = NULL;
		pthread_mutex_unlock(&open_file_cached_mutex);
	}
	ios->openings = o;
	if (o->writing) {
		pthread_mutex_lock(&open_file_cached_mutex);
		ios->fp_cached = fp;
		pthread_mutex_unlock(&open_file_cached_mutex);
	}
	gfarm2fs_open_file_table_unlock();
}

static int
open_file_remove_opening(struct inode_openings *ios, struct gfarm2fs_file *fp)
{
	struct opening *o, **prev;

	for (prev = &ios->openings; (o = *prev) != NULL; prev = &o->next) {
		if (o->fp == fp)
			break;
	}
	if (o == NULL)
		return (1);

	*prev = o->next;
	free(o);
	return (0);
}

void
gfarm2fs_open_file_remove_unlocked(const struct gfarmized_path *gp,
	struct gfarm2fs_file *fp)
{
	struct open_file_key *key;
	int keylen;
	gfarm_ino_t inum = fp->inum;
	struct gfarm_hash_entry *entry;
	struct inode_openings *ios = NULL;

	key = open_file_key_alloc(gp, inum, &keylen);
	if (key == NULL)
		return;

	entry = gfarm_hash_lookup(open_file_table, key, keylen);
	if (entry == NULL) {
		gflog_warning(GFARM_MSG_2000056,
		    "inode %lld is not found in open file table",
		    (unsigned long long)inum);
		free(key);
		return;
	}
	ios = gfarm_hash_entry_data(entry);
	if (open_file_remove_opening(ios, fp) != 0)
		gflog_warning(GFARM_MSG_2000057,
		    "file %p is not found in the inode %lld openings",
		    fp, (unsigned long long)inum);
	pthread_mutex_lock(&open_file_cached_mutex);
	if (ios->fp_cached == fp)
		ios->fp_cached = NULL;
	pthread_mutex_unlock(&open_file_cached_mutex);
	if (ios->openings == NULL)
		(void)gfarm_hash_purge(open_file_table, key, keylen);
	free(key);
}
