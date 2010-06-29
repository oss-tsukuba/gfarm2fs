/*
 * $Id$
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gfarm/gfarm.h>

#include "gfarm2fs_msg_enums.h"

/* hash.h in libgfarm */
struct gfarm_hash_table;
struct gfarm_hash_table *gfarm_hash_table_alloc(int,
	int (*)(const void *, int),
	int (*)(const void *, int, const void *, int));
struct gfarm_hash_entry *gfarm_hash_lookup(struct gfarm_hash_table *,
	const void *, int);
struct gfarm_hash_entry *gfarm_hash_enter(struct gfarm_hash_table *,
	const void *, int, int, int *);
int gfarm_hash_purge(struct gfarm_hash_table *,
	const void *, int);
void *gfarm_hash_entry_key(struct gfarm_hash_entry *);
void *gfarm_hash_entry_data(struct gfarm_hash_entry *);

struct gfarm_hash_iterator {
	struct gfarm_hash_table *table;
	int bucket_index;
	struct gfarm_hash_entry **pp;
};
void gfarm_hash_iterator_begin(struct gfarm_hash_table *,
	struct gfarm_hash_iterator *);
void gfarm_hash_iterator_next(struct gfarm_hash_iterator *);
int gfarm_hash_iterator_is_end(struct gfarm_hash_iterator *);
struct gfarm_hash_entry *gfarm_hash_iterator_access(
	struct gfarm_hash_iterator *);

#include "gfarm2fs.h"

struct opening {
	struct opening *next;
	GFS_File gf;
	int writing;
};

struct inode_openings {
	struct opening *openings;
	GFS_File gf_cached;
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

GFS_File
gfarm2fs_open_file_lookup(gfarm_ino_t ino)
{
	struct gfarm_hash_entry *entry;
	struct inode_openings *ios;
	struct opening *o;

	entry = gfarm_hash_lookup(open_file_table, &ino, sizeof(ino));
	if (entry == NULL)
		return (NULL);
	ios = gfarm_hash_entry_data(entry);
	if (ios->gf_cached != NULL)
		return (ios->gf_cached);
	for (o = ios->openings; o != NULL; o = o->next) {
		if (o->writing) {
			ios->gf_cached = o->gf;
			return (ios->gf_cached);
		}
	}
	ios->gf_cached = ios->openings->gf;
	return (ios->gf_cached);
}

static int
get_ino(GFS_File gf, gfarm_ino_t *ino)
{
	struct gfs_stat st;
	gfarm_error_t e;

	e = gfs_pio_stat(gf, &st);
	if (e == GFARM_ERR_NO_ERROR) {
		*ino = st.st_ino;
		gfs_stat_free(&st);
		return (0);
	}
	return (-gfarm_error_to_errno(e));
}

void
gfarm2fs_open_file_enter(GFS_File gf, int flags)
{
	gfarm_ino_t ino;
	struct gfarm_hash_entry *entry;
	struct inode_openings *ios;
	struct opening *o;
	int created;

	if (get_ino(gf, &ino) != 0) {
		gflog_debug(GFARM_MSG_2000052,
		    "file %p does not exist", gf);
		return;
	}
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
	o->gf = gf;
	o->writing =
	    ((flags & O_TRUNC) != 0 || (flags & O_ACCMODE) != O_RDONLY);

	ios = gfarm_hash_entry_data(entry);
	if (!created) {
		o->next = ios->openings;
	} else {
		o->next = NULL;
		ios->gf_cached = NULL;
	}
	ios->openings = o;
	if (o->writing)
		ios->gf_cached = gf;
}

static int
open_file_remove_opening(struct inode_openings *ios, GFS_File gf)
{
	struct opening *o, **prev;

	for (prev = &ios->openings; (o = *prev) != NULL; prev = &o->next) {
		if (o->gf == gf)
			break;
	}
	if (o == NULL)
		return (1);

	*prev = o->next;
	free(o);
	return (0);
}

static int
get_ino_and_remove_opening_from_open_table(GFS_File gf,
	gfarm_ino_t *inop, struct inode_openings **iosp)
{
	struct gfarm_hash_iterator it;
	struct gfarm_hash_entry *entry = NULL;
	struct inode_openings *ios = NULL;

	for (gfarm_hash_iterator_begin(open_file_table, &it);
	    !gfarm_hash_iterator_is_end(&it); gfarm_hash_iterator_next(&it)) {
		entry = gfarm_hash_iterator_access(&it);
		ios = gfarm_hash_entry_data(entry);

		if (open_file_remove_opening(ios, gf) == 0)
			break;
	}
	if (gfarm_hash_iterator_is_end(&it))
		return (1);

	*inop = *(gfarm_ino_t *)gfarm_hash_entry_key(entry);
	*iosp = ios;
	return (0);
}

void
gfarm2fs_open_file_remove(GFS_File gf)
{
	gfarm_ino_t ino;
	struct gfarm_hash_entry *entry;
	struct inode_openings *ios = NULL;

	if (get_ino(gf, &ino) != 0) {
		if (get_ino_and_remove_opening_from_open_table(gf, &ino, &ios)
		    != 0) {
			gflog_warning(GFARM_MSG_2000055,
			    "file %p does not exist in open file table", gf);
			return;
		}
		/* the opening entry removed */
	} else {
		entry = gfarm_hash_lookup(open_file_table, &ino, sizeof(ino));
		if (entry == NULL) {
			gflog_warning(GFARM_MSG_2000056,
			    "inode %lld is not found in open file table",
			    (unsigned long long)ino);
			return;
		}
		ios = gfarm_hash_entry_data(entry);
		if (open_file_remove_opening(ios, gf) != 0)
			gflog_warning(GFARM_MSG_2000057,
			    "file %p is not found in the inode %lld openings",
			    gf, (unsigned long long)ino);
	}
	if (ios->gf_cached == gf)
		ios->gf_cached = NULL;
	if (ios->openings == NULL)
		(void)gfarm_hash_purge(open_file_table, &ino, sizeof(ino));
}
