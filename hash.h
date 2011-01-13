/*
 * $Id$
 */

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

int gfarm_hash_strptr(const void *, int);
int gfarm_hash_key_equal_strptr(const void *, int, const void *, int);
