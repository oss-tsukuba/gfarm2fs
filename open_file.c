/*
 * $Id$
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <gfarm/gfarm.h>

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
void *gfarm_hash_entry_data(struct gfarm_hash_entry *);

#include "gfarm2fs.h"

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
		gflog_fatal(GFARM_MSG_UNFIXED, "no memory");
}

GFS_File
gfarm2fs_open_file_lookup(gfarm_ino_t ino)
{
	struct gfarm_hash_entry *entry;

	entry = gfarm_hash_lookup(open_file_table, &ino, sizeof(gfarm_ino_t));
	return (entry == NULL ? NULL :
	    *(GFS_File *)gfarm_hash_entry_data(entry));
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
gfarm2fs_open_file_enter(GFS_File gf)
{
	gfarm_ino_t ino;
	struct gfarm_hash_entry *entry;
	int created;

	if (get_ino(gf, &ino) != 0) {
		gflog_debug(GFARM_MSG_UNFIXED,
		    "file %p does not exist in the open file table", gf);
		return;
	}
	entry = gfarm_hash_enter(open_file_table, &ino, sizeof(gfarm_ino_t),
	    sizeof(GFS_File), &created);
	if (entry == NULL) {
		gflog_debug(GFARM_MSG_UNFIXED,
		    "inode %lld cannot be inserted to the open file table",
		    ino);
		return;
	}
	if (!created) {
		gflog_debug(GFARM_MSG_UNFIXED,
		    "inode %lld already exists in the open file table", ino);
		return;
	}
	*(GFS_File *)gfarm_hash_entry_data(entry) = gf;
}

void
gfarm2fs_open_file_remove(GFS_File gf)
{
	gfarm_ino_t ino;

	if (get_ino(gf, &ino) != 0) {
		gflog_debug(GFARM_MSG_UNFIXED,
		    "file %p does not exist in the open file table", gf);
		return;
	}
	(void)gfarm_hash_purge(open_file_table, &ino, sizeof(gfarm_ino_t));
}

