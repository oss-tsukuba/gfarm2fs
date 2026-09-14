# README.MT-safe of gfarm2fs

## locks and locking order

The following locks are implemented:

- `id.c`: `mutex_group` and `mutex_user` (`pthread_mutex_t`, static)
- `open_file.c`: `open_file_table_rwlock` (`pthread_rwlock_t`, static)
- `open_file.c`: `open_file_cached_mutex` (`pthread_mutex_t`, static)
- `gfarm2fs.h`: `struct gfarm2fs_file.lock` (`pthread_rwlock_t`)
- `gfarm2fs.c`: `readlink_cache_mutex` (`pthread_mutex_t`, static)

`open_file_table_rwlock` protects the inode-to-openings hash table and
the inode-to-openings lists. The `open_file_cached_mutex` protects the
`inode_openings.fp_cached` entries. The `*_lookup_unlocked()` and
`*_remove_unlocked()` functions require the caller to hold the table lock;
they acquire `open_file_cached_mutex` when accessing `fp_cached`.
`gfarm2fs_open_file_enter()` acquires the write lock itself.

When both locks are needed, acquire them in this order:

`open_file_table_rwlock -> open_file_cached_mutex`

Release them in reverse order. The table lock still protects the hash
table and opening lists, while the separate mutex is necessary because
lookups may run concurrently under the table read lock and update
`fp_cached`.

When both the open-file table and a `struct gfarm2fs_file` must be locked,
acquire them in this order:

`open_file_table_rwlock -> gfarm2fs_file.lock`

Release them in reverse order. This order is used by `getattr`,
`utimens`, and `release` while coordinating the open-file table with
the per-file state and `gfs_pio_close()`.

The file lock protects the per-open state `time_updated` and `gt`, and
serializes gfarm2fs operations on the same `GFS_File`, including
`gfs_pio_pread()`, `gfs_pio_pwrite()`, `gfs_pio_truncate()`,
`gfs_pio_flush()`, and `gfs_pio_stat()`. FUSE normally does not invoke
`release` concurrently with operations using the same file handle, but
the file lock also provides the exclusion required by the libgfarm close
contract.

The file lock may be acquired without the table lock when a file handle is
available directly and the open-file table is not accessed. This is the
case for operations such as `read`, `write`, `ftruncate`, and `flush`.

`mutex_user` and `mutex_group` protect the user/group ID caches and
related buffers. They are independent of the other locks; no locking order
between them is defined.

`readlink_cache_mutex` protects `readlink_cache_src` and
`readlink_cache_path`. Functions ending in `_unlocked()` (for example,
`gfarm2fs_readlink_cache_clear_unlocked()`) require the caller to hold
this mutex.

## directory iteration

`gfarm2fs_readdir()` does not acquire a gfarm2fs lock around a
`GFS_Dir`. It calls `gfs_seekdir(dp, offset)` and
`gfs_readdir(dp, ...)`. libgfarm serializes operations on the
directory object, but does not provide an atomic seek-and-read
operation.

The example FUSE passthrough_fh.c implementation also does not make
those calls atomic.
