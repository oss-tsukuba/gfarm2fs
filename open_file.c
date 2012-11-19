/*
 * $Id$
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gfarm/gfarm.h>

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

static struct gfarm_hash_table *open_file_table;
#define OPEN_FILE_TABLE_SIZE	256

static int open_file_hash(const void *k, int l)
{
	gfarm_ino_t h = *(gfarm_ino_t *)k;
	int i = (int)h;

	return (i);
}

static int open_file_hash_equal(
	const void *k1, int k1len, const void *k2, int k2len)
{
	gfarm_ino_t h1 = *(gfarm_ino_t *)k1, h2 = *(gfarm_ino_t *)k2;

	return (h1 == h2);
}

void
gfarm2fs_open_file_init()
{
	open_file_table = gfarm_hash_table_alloc(
		OPEN_FILE_TABLE_SIZE, open_file_hash, open_file_hash_equal);
	if (open_file_table == NULL)
		gflog_fatal(GFARM_MSG_2000051, "no memory");
}

struct gfarm2fs_file *
gfarm2fs_open_file_lookup(gfarm_ino_t ino)
{
	struct gfarm_hash_entry *entry;
	struct inode_openings *ios;
	struct opening *o;

	entry = gfarm_hash_lookup(open_file_table, &ino, sizeof(ino));
	if (entry == NULL)
		return (NULL);
	ios = gfarm_hash_entry_data(entry);
	if (ios->fp_cached != NULL)
		return (ios->fp_cached);
	for (o = ios->openings; o != NULL; o = o->next) {
		if (o->writing) {
			ios->fp_cached = o->fp;
			return (ios->fp_cached);
		}
	}
	ios->fp_cached = ios->openings->fp;
	return (ios->fp_cached);
}

void
gfarm2fs_open_file_enter(struct gfarm2fs_file *fp, int flags)
{
	gfarm_ino_t ino = fp->inum;
	struct gfarm_hash_entry *entry;
	struct inode_openings *ios;
	struct opening *o;
	int created;

	o = malloc(sizeof(*o));
	if (o == NULL) {
		gflog_error(GFARM_MSG_2000053,
		    "no memory to cache an opening for inode %lld",
		    (unsigned long long)ino);
		return;
	}
	entry = gfarm_hash_enter(open_file_table, &ino, sizeof(ino),
	    sizeof(*ios), &created);
	if (entry == NULL) {
		gflog_error(GFARM_MSG_2000054,
		    "no memory to insert inode %lld to open file table",
		    (unsigned long long)ino);
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
		ios->fp_cached = NULL;
	}
	ios->openings = o;
	if (o->writing)
		ios->fp_cached = fp;
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
gfarm2fs_open_file_remove(struct gfarm2fs_file *fp)
{
	gfarm_ino_t ino = fp->inum;
	struct gfarm_hash_entry *entry;
	struct inode_openings *ios = NULL;

	entry = gfarm_hash_lookup(open_file_table, &ino, sizeof(ino));
	if (entry == NULL) {
		gflog_warning(GFARM_MSG_2000056,
		    "inode %lld is not found in open file table",
		    (unsigned long long)ino);
		return;
	}
	ios = gfarm_hash_entry_data(entry);
	if (open_file_remove_opening(ios, fp) != 0)
		gflog_warning(GFARM_MSG_2000057,
		    "file %p is not found in the inode %lld openings",
		    fp, (unsigned long long)ino);
	if (ios->fp_cached == fp)
		ios->fp_cached = NULL;
	if (ios->openings == NULL)
		(void)gfarm_hash_purge(open_file_table, &ino, sizeof(ino));
}
