void gfarm2fs_open_file_init(void);
struct gfarm2fs_file *gfarm2fs_open_file_lookup_unlocked(
	const struct gfarmized_path *, gfarm_ino_t);
void gfarm2fs_open_file_enter(const struct gfarmized_path *,
	struct gfarm2fs_file *, int);
void gfarm2fs_open_file_remove_unlocked(const struct gfarmized_path *,
	struct gfarm2fs_file *);
void gfarm2fs_open_file_table_rdlock(void);
void gfarm2fs_open_file_table_wrlock(void);
void gfarm2fs_open_file_table_unlock(void);
