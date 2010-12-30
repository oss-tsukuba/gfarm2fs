void gfarm2fs_open_file_init(void);
GFS_File gfarm2fs_open_file_lookup(gfarm_ino_t);
void gfarm2fs_open_file_enter(GFS_File, int);
void gfarm2fs_open_file_remove(GFS_File);
