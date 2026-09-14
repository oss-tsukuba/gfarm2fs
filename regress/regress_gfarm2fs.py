import os
import os.path
import sys
import shutil
import argparse
import subprocess
import random
import tempfile
import atexit
import signal
import threading
import concurrent.futures
import time
import errno
import ctypes
import ctypes.util
import traceback
import stat

LOG_LEVEL = "WARNING"
CLEANED_UP = False
INTERRUPTED_BY_SIGNAL = False

active_dirs_lock = threading.Lock()
active_dirs = set()
failed_tests_lock = threading.Lock()
failed_tests_global = []
failed_tests_seen = set()
print_lock = threading.Lock()
stop_event = threading.Event()
thread_local = threading.local()
fuse_version_cache = {}

XFAIL = "XFAIL"
SKIP = "SKIP"


def current_time_ns():
    """Return the current time in nanoseconds on all supported Pythons."""
    if hasattr(time, "time_ns"):
        return time.time_ns()
    return int(time.time() * 1000000000)


# .fuse-hidden files might not be deleted.
def rmtree_with_retry(path, retry_count=5, retry_interval=1.0):
    last_error = None
    attempt = 0

    def check():
        nonlocal attempt, last_error
        attempt += 1
        try:
            shutil.rmtree(path)
            return True
        except FileNotFoundError:
            return True
        except OSError as e:
            last_error = e
            if attempt < retry_count and e.errno in (
                errno.ENOTEMPTY,
                errno.EBUSY,
                errno.EIO,
            ):
                try:
                    entries = sorted(os.listdir(path))
                except OSError as list_error:
                    entries = [
                        f"<listdir failed: {format_os_error(list_error)}>"
                    ]
                warn(
                    "rmtree failed; retrying transient failure: "
                    f"path={path} attempt={attempt}/{retry_count} "
                    f"error={format_os_error(e)} entries={entries}"
                )
                return None
            raise

    if retry_until(
        retry_count * retry_interval + 0.001,
        retry_interval,
        check,
    ) is None and last_error is not None:
        raise last_error


def register_active_dir(dpath):
    with active_dirs_lock:
        active_dirs.add(dpath)


def unregister_active_dir(dpath):
    with active_dirs_lock:
        active_dirs.discard(dpath)


def cleanup_all_test_dirs():
    global CLEANED_UP
    if CLEANED_UP:
        return
    CLEANED_UP = True
    with active_dirs_lock:
        for dpath in list(active_dirs):
            if os.path.exists(dpath):
                rmtree_with_retry(dpath)
        active_dirs.clear()


def cleanup_test_dir():
    cleanup_all_test_dirs()


def register_failed_test(name):
    with failed_tests_lock:
        if name not in failed_tests_seen:
            failed_tests_seen.add(name)
            failed_tests_global.append(name)


def get_failed_tests():
    with failed_tests_lock:
        return list(failed_tests_global)


def reset_failed_tests():
    with failed_tests_lock:
        failed_tests_global.clear()
        failed_tests_seen.clear()


def handle_signal(signum, frame):
    global INTERRUPTED_BY_SIGNAL
    INTERRUPTED_BY_SIGNAL = True
    stop_event.set()
    raise KeyboardInterrupt


atexit.register(cleanup_all_test_dirs)
for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    try:
        signal.signal(_sig, handle_signal)
    except (AttributeError, ValueError):
        pass


thread_counter_lock = threading.Lock()
thread_counter = 0
thread_ids = {}


def get_thread_id():
    global thread_counter
    t_ident = threading.get_ident()
    with thread_counter_lock:
        if t_ident not in thread_ids:
            thread_counter += 1
            thread_ids[t_ident] = thread_counter
        return thread_ids[t_ident]


def get_run_prefix():
    run_id = getattr(thread_local, "run_id", None)
    if run_id is not None:
        thread_id = get_thread_id()
        return f"[ID{run_id}-T{thread_id}] "
    return ""


def safe_print(msg):
    prefix = get_run_prefix()
    with print_lock:
        sys.stdout.write(f"{prefix}{msg}\n")
        sys.stdout.flush()


def debug(msg):
    if LOG_LEVEL == "DEBUG":
        safe_print(f"[DEBUG] {msg}")


def info(msg):
    if LOG_LEVEL in ["INFO", "DEBUG"]:
        safe_print(f"[INFO] {msg}")


def warn(msg):
    if LOG_LEVEL in ["INFO", "DEBUG", "WARNING"]:
        safe_print(f"[WARNING] {msg}")


def expected_error(msg):
    if LOG_LEVEL in ["INFO", "DEBUG"]:
        safe_print(f"[EXPECTED] {msg}")


def error(msg):
    safe_print(f"[ERROR] {msg}")


def format_os_error(err):
    return f"{err.__class__.__name__}: {err}"


def retry_until(timeout_sec, interval_sec, check_fn):
    """Retry a check until it succeeds or the timeout expires."""
    deadline = time.monotonic() + timeout_sec
    while True:
        result = check_fn()
        if result is not None:
            return result
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_sec)


def getxattr_equals_retry(os_getxattr, path, key, expected, timeout_sec=5.0):
    """Get xattr, retrying until it returns the expected value."""
    last_error = None

    def check():
        nonlocal last_error
        try:
            value = os_getxattr(path, key)
            if value == expected:
                return value
            warn(
                "xattr value not ready yet; retrying: "
                f"path={path} key={key} expected={expected!r} got={value!r}"
            )
        except OSError as e:
            last_error = e
            info(
                "xattr read failed; retrying: "
                f"path={path} key={key} expected={expected!r} "
                f"error={format_os_error(e)}"
            )
        return None

    value = retry_until(timeout_sec, 0.05, check)
    if value is None and last_error is not None:
        error(
            "xattr retry timed out: "
            f"path={path} key={key} expected={expected!r} "
            f"last_error={format_os_error(last_error)}"
        )
    return value


def getxattr_missing_retry(os_getxattr, path, key, timeout_sec=5.0):
    """Get xattr, retrying until it raises OSError for a missing xattr."""
    last_error = None

    def check():
        nonlocal last_error
        try:
            value = os_getxattr(path, key)
            warn(
                "xattr still present during retry; retrying: "
                f"path={path} key={key} got={value!r}"
            )
        except OSError as e:
            last_error = e
            return e
        return None

    err = retry_until(timeout_sec, 0.05, check)
    if err is None and last_error is not None:
        error(
            "xattr missing retry timed out: "
            f"path={path} key={key} "
            f"last_error={format_os_error(last_error)}"
        )
    return err


def getxattr_equals(os_getxattr, path, key, expected, timeout_sec=0):
    """Get xattr once, or retry when timeout_sec is positive."""
    if timeout_sec > 0:
        return getxattr_equals_retry(
            os_getxattr, path, key, expected, timeout_sec
        )
    try:
        value = os_getxattr(path, key)
        if value != expected:
            return None
        return value
    except OSError:
        return None


def getxattr_missing(os_getxattr, path, key, timeout_sec=0):
    """Check missing xattr once, or retry when timeout_sec is positive."""
    if timeout_sec > 0:
        return getxattr_missing_retry(os_getxattr, path, key, timeout_sec)
    try:
        os_getxattr(path, key)
    except OSError as e:
        return e
    return None


def get_fuse_version(path):
    """Return the mounted gfarm2fs libfuse version as a tuple."""
    if path in fuse_version_cache:
        return fuse_version_cache[path]
    try:
        value = os.getxattr(path, "gfarm2fs.fuse_version")
        parts = value.decode().split(".")
        if len(parts) < 3:
            executable = os.getxattr(path, "gfarm2fs.exe").decode()
            output = subprocess.check_output(
                [executable, "--version"],
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            fuse_version = None
            for line in output.splitlines():
                if "FUSE library version" in line:
                    fuse_version = line.split()[-1].split(".")
                    break
            if fuse_version is None:
                return None
            parts = fuse_version
        version = tuple(
            int(part) for part in (parts + ["0", "0"])[:3]
        )
        fuse_version_cache[path] = version
        return version
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def get_gfmd_from_gfmdhost():
    """Return the active gfmd as reported by ``gfmdhost -l``."""
    output = subprocess.check_output(
        ["gfmdhost", "-l"], universal_newlines=True
    )
    for line in output.splitlines():
        if line.strip().startswith("+ master"):
            parts = line.split()
            if len(parts) >= 5:
                gfmd_host = parts[5]
                if len(parts) >= 6:
                    gfmd_host = gfmd_host + ":" + parts[6]
                return gfmd_host
    raise RuntimeError("active gfmd is not found in gfmdhost output")


def get_gfmd_from_xattr(path):
    """Return the gfmd endpoint from the gfarm2fs.metadb xattr."""
    value = os.getxattr(path, "gfarm2fs.metadb").decode().strip()
    if not value or ":" not in value:
        raise ValueError("invalid gfarm2fs.metadb xattr value: %r" % value)
    return value


def print_gfarm2fs_versions(path):
    """Print versions reported by gfarm2fs local extended attributes."""
    keys = (
        "gfarm2fs.version",
        "gfarm2fs.gfarm_version",
        "gfarm2fs.fuse_version",
        "gfarm2fs.pid",
        "gfarm2fs.exe",
    )
    safe_print("gfarm2fs versions:")
    for key in keys:
        if key == "gfarm2fs.fuse_version":
            version = get_fuse_version(path)
            if version is not None:
                safe_print(f"  {key}={'.'.join(map(str, version))}")
                continue
        try:
            value = os.getxattr(path, key).decode(errors="replace")
            safe_print(f"  {key}={value}")
        except OSError as e:
            warn(f"  {key}: {format_os_error(e)}")


def parse_test_filter(spec):
    if spec is None:
        return None
    names = [name.strip() for name in spec.split(",") if name.strip()]
    if not names:
        return set()
    return set(names)


def build_test_entries(xattr=False, gfarm2fs=False, fuse=False):
    test_list = [
        # Directory operations
        ("create_dir", test_create_dir),
        ("remove_dir", test_remove_dir),
        ("rename_dir", test_rename_dir),
        ("readdir_inode_consistency", test_readdir_inode_consistency),
        ("parallel_opendir", test_parallel_opendir),
        ("seekdir", test_seekdir),
        # File operations (creation/deletion)
        ("create_file", test_create_file),
        ("mknod", test_mknod),
        ("remove_file", test_remove_file),
        ("creat_excl", test_creat_excl),
        # File operations (I/O)
        ("random_read", test_random_read),
        ("random_write", test_random_write),
        ("parallel_open", test_parallel_open),
        ("parallel_write", test_parallel_write),
        ("open_read_write", test_open_read_write),
        ("open_unlink_read_write", test_open_unlink_read_write),
        ("open_parent_unlink_read_write",
         (lambda base_dir: test_open_parent_unlink_read_write(
             base_dir, use_xfail=fuse))),
        ("open_unlink_utime", test_open_unlink_utime),
        ("open_unlink_ftruncate", test_open_unlink_ftruncate),
        ("open_rename_read_write", test_open_rename_read_write),
        ("open_rename_utime", test_open_rename_utime),
        ("append", test_append),
        ("seek", test_seek),
        ("copy_file_range", test_copy_file_range),
        # Links
        ("symlink", test_symlink),
        ("hardlink", test_hardlink),
        # Metadata/Permissions
        ("chmod", test_chmod),
        ("chown", test_chown),
        ("utime", test_utime),
        ("utime_omit", test_utime_omit),
        ("open_utime_omit", test_open_utime_omit),
        ("open_utime_cancel", test_open_utime_cancel),
        ("utime_now", test_utime_now),
        ("statvfs", test_statvfs),
        # File size/truncation
        ("truncate", test_truncate),
        ("ftruncate", test_ftruncate),
        # Others/Edge cases
        ("negative_lookup_recreate", test_negative_lookup_recreate),
        ("errors", test_errors),
    ]
    if xattr:
        test_list.append(("xattr",
                          lambda base_dir: test_xattr(base_dir, gfarm2fs)))
    if gfarm2fs:
        test_list.extend([
            ("gfarm2fs_ungfarmize_path", test_gfarm2fs_ungfarmize_path),
            ("gfarm2fs_effective_perm", test_gfarm2fs_effective_perm),
            ("gfarm2fs_cksum", test_gfarm2fs_cksum),
            ("gfarm2fs_local_xattr", test_gfarm2fs_local_xattr),
            ("gfarm2fs_listxattr_profile", test_gfarm2fs_listxattr_profile),
        ])
    return test_list


def list_test_names(xattr=False, gfarm2fs=False, fuse=False):
    return [
        name
        for name, _ in build_test_entries(
            xattr=xattr, gfarm2fs=gfarm2fs, fuse=fuse
        )
    ]


def get_mount_point(path):
    """Resolve the mount point that contains the given path."""
    real_path = os.path.abspath(os.path.realpath(path))
    best_mount = ""
    try:
        with open("/proc/self/mountinfo", "r") as f:
            for line in f:
                fields = line.split()
                if len(fields) < 5:
                    continue
                mount_point = fields[4]
                if real_path == mount_point or real_path.startswith(
                    mount_point.rstrip("/") + "/"
                ):
                    if len(mount_point) > len(best_mount):
                        best_mount = mount_point
    except OSError as e:
        debug(
            "get_mount_point fallback for "
            f"{real_path}: {format_os_error(e)}"
        )
    return best_mount or real_path


def run_gfstat(path):
    """Return gfstat output for a path below a gfarm2fs mount point."""
    try:
        result = subprocess.run(
            ["gfstat", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )
        output = result.stdout.rstrip()
        return (
            f"gfstat path={path!r} returncode={result.returncode}: "
            f"{output or '<no output>'}"
        )
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return (f"gfstat diagnostic failed for path={path!r}: "
                f"{format_os_error(e)}")


def test_create_dir(base_dir):
    """Test directory creation."""
    target = os.path.join(base_dir, "new_dir")
    debug(f"test_create_dir: target={target}")
    if os.path.exists(target):
        rmtree_with_retry(target)
    os.mkdir(target)
    info(f"Created directory: {target}")
    return os.path.isdir(target)


def test_remove_dir(base_dir):
    """Test directory removal."""
    target = os.path.join(base_dir, "rem_dir")
    debug(f"test_remove_dir: target={target}")
    if os.path.exists(target):
        rmtree_with_retry(target)
    os.mkdir(target)
    try:
        os.rmdir(target)
        info(f"Removed directory: {target}")
        return not os.path.exists(target)
    except Exception as e:
        error(f"test_remove_dir exception: {format_os_error(e)}")
        return False


def test_rename_dir(base_dir):
    """Test directory renaming."""
    old = os.path.join(base_dir, "old_dir")
    new = os.path.join(base_dir, "new_dir")
    debug(f"test_rename_dir: old={old}, new={new}")
    if os.path.exists(old):
        rmtree_with_retry(old)
    if os.path.exists(new):
        rmtree_with_retry(new)
    os.mkdir(old)
    try:
        os.rename(old, new)
    except OSError as e:
        error(f"rename_dir failed: {format_os_error(e)}")
        return False
    info(f"Renamed {old} -> {new}")
    if not os.path.isdir(new):
        error("rename_dir target is not a directory after rename")
        return False
    if os.path.exists(old):
        error("rename_dir source still exists after rename")
        return False
    return True


def test_create_file(base_dir):
    """Test file creation."""
    fpath = os.path.join(base_dir, "test_file")
    debug(f"test_create_file: fpath={fpath}")
    if os.path.exists(fpath):
        os.remove(fpath)
    try:
        with open(fpath, 'w') as _:
            pass
    except OSError as e:
        error(f"create_file failed: {format_os_error(e)}")
        return False
    info(f"Created file: {fpath}")
    if not os.path.isfile(fpath):
        error("create_file target is not a file after creation")
        return False
    return True


def test_mknod(base_dir):
    """Test file creation through os.mknod."""
    fpath = os.path.join(base_dir, "mknod_file")
    debug(f"test_mknod: fpath={fpath}")
    if os.path.exists(fpath):
        os.remove(fpath)
    try:
        mode = 0o644
        os.mknod(fpath, 0o100000 | mode)
    except AttributeError:
        warn("test_mknod skipped: os.mknod is not available")
        return SKIP
    except PermissionError as e:
        warn(f"test_mknod skipped: {format_os_error(e)}")
        return SKIP
    except OSError as e:
        error(f"mknod failed: {format_os_error(e)}")
        return False

    try:
        st = os.stat(fpath)
        if not stat.S_ISREG(st.st_mode):
            error("mknod target is not a regular file: "
                  f"mode={oct(st.st_mode)}")
            return False
        with open(fpath, 'rb') as f:
            if f.read() != b"":
                error("mknod target is not empty")
                return False
        return True
    except Exception as e:
        error(f"test_mknod exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_remove_file(base_dir):
    """Test file removal."""
    fpath = os.path.join(base_dir, "rem_file")
    debug(f"test_remove_file: fpath={fpath}")
    with open(fpath, 'w') as _:
        pass
    try:
        os.remove(fpath)
        info(f"Removed file: {fpath}")
        if os.path.exists(fpath):
            error("remove_file target still exists after removal")
            return False
        return True
    except Exception as e:
        error(f"test_remove_file exception: {format_os_error(e)}")
        return False


def test_random_read(base_dir):
    """Test random reading from a file."""
    fpath = os.path.join(base_dir, "rand_read_file")
    size = 10 * 1024 * 1024
    data = os.urandom(size)
    debug(f"test_random_read: fpath={fpath}, size={size}")

    try:
        with open(fpath, 'wb') as f:
            f.write(data)
        info(f"Wrote {size} bytes to {fpath}")

        with open(fpath, 'rb') as f:
            for _ in range(10):
                pos = random.randint(0, size - 1)
                debug(f"Seeking to pos={pos}")
                f.seek(pos)
                read_byte = f.read(1)
                if read_byte != data[pos:pos + 1]:
                    error(
                        "Mismatch at "
                        f"{pos}: expected {data[pos:pos + 1]}, got {read_byte}"
                    )
                    return False
        return True
    except Exception as e:
        error(f"test_random_read exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_random_write(base_dir):
    """Test random writing to a file."""
    fpath = os.path.join(base_dir, "rand_write_file")
    size = 10 * 1024 * 1024
    data = bytearray(os.urandom(size))
    debug(f"test_random_write: fpath={fpath}, size={size}")

    try:
        with open(fpath, 'wb') as f:
            f.write(data)
        info(f"Wrote {size} bytes to {fpath}")

        positions = [size // 4, size // 2, (3 * size) // 4]
        new_values = [0xAA, 0xBB, 0xCC]

        with open(fpath, 'rb+') as f:
            for i in range(len(positions)):
                pos = positions[i]
                val = new_values[i]
                debug(f"Writing {val} at pos={pos}")
                f.seek(pos)
                f.write(bytes([val]))
                data[pos] = val

        info(f"Reading back file from {fpath}")
        with open(fpath, 'rb') as f:
            read_data = f.read()

        if read_data != data:
            error("Data mismatch after writes")
            return False
        return True
    except Exception as e:
        error(f"test_random_write exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_parallel_open(base_dir):
    """Test concurrent writes from multiple handles to one file."""
    fpath = os.path.join(base_dir, "parallel_open")
    thread_count = 8
    # Use a size that does not align with the libgfarm buffer size
    # boundary
    block_size = 500 * 1000
    # block_size = 512 * 1024
    size = thread_count * block_size
    expected = [
        bytes([65 + thread_no]) * block_size
        for thread_no in range(thread_count)
    ]
    debug(
        "test_parallel_open: "
        f"fpath={fpath}, threads={thread_count}, block_size={block_size}"
    )

    barrier = threading.Barrier(thread_count)

    def write_block(thread_no):
        barrier.wait()
        with open(fpath, "r+b", buffering=0) as f:
            f.seek(thread_no * block_size)
            written = f.write(expected[thread_no])
            if written != block_size:
                raise OSError(
                    f"short write: expected={block_size} got={written}"
                )
            os.fsync(f.fileno())

    try:
        with open(fpath, "wb") as f:
            f.truncate(size)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=thread_count
        ) as executor:
            futures = [
                executor.submit(write_block, thread_no)
                for thread_no in range(thread_count)
            ]
            for future in futures:
                future.result()

        with open(fpath, "rb") as f:
            actual = f.read()
        expected_data = b"".join(expected)
        if actual != expected_data:
            error(
                "parallel_open data mismatch: "
                f"expected_size={len(expected_data)} actual_size={len(actual)}"
            )
            return False
        return True
    except Exception as e:
        error(
            "test_parallel_open exception: "
            f"{format_os_error(e)}"
        )
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_parallel_opendir(base_dir):
    """Test concurrent opendir/readdir operations on one directory."""
    dpath = os.path.join(base_dir, "parallel_opendir")
    thread_count = 8
    entry_count = 16
    expected_names = {
        f"entry_{entry_no}" for entry_no in range(entry_count)
    }
    debug(
        "test_parallel_opendir: "
        f"dpath={dpath}, threads={thread_count}, entries={entry_count}"
    )

    barrier = threading.Barrier(thread_count)

    def read_directory():
        barrier.wait()
        with os.scandir(dpath) as entries:
            return {
                entry.name: entry.inode()
                for entry in entries
            }

    try:
        os.mkdir(dpath)
        for name in expected_names:
            with open(os.path.join(dpath, name), "wb"):
                pass

        expected_inodes = {
            name: os.stat(os.path.join(dpath, name)).st_ino
            for name in expected_names
        }

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=thread_count
        ) as executor:
            futures = [
                executor.submit(read_directory)
                for _ in range(thread_count)
            ]
            results = [future.result() for future in futures]

        for thread_no, actual in enumerate(results):
            if actual != expected_inodes:
                error(
                    "parallel_opendir result mismatch: "
                    f"thread={thread_no} expected={expected_inodes} "
                    f"got={actual}"
                )
                return False
        return True
    except Exception as e:
        error(
            "test_parallel_opendir exception: "
            f"{format_os_error(e)}"
        )
        return False
    finally:
        if os.path.exists(dpath):
            rmtree_with_retry(dpath)


def test_parallel_write(base_dir):
    """Test concurrent writes issued through one open file descriptor."""
    fpath = os.path.join(base_dir, "parallel_write")
    thread_count = 8
    # Use a size that does not align with the libgfarm buffer size boundary.
    block_size = 500 * 1000
    expected = [
        bytes([65 + thread_no]) * block_size
        for thread_no in range(thread_count)
    ]
    debug(
        "test_parallel_write: "
        f"fpath={fpath}, threads={thread_count}, block_size={block_size}"
    )

    barrier = threading.Barrier(thread_count)
    fd = -1

    def write_block(thread_no):
        barrier.wait()
        written = os.write(fd, expected[thread_no])
        if written != block_size:
            raise OSError(
                f"short write: expected={block_size} got={written}"
            )

    try:
        fd = os.open(fpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=thread_count
        ) as executor:
            futures = [
                executor.submit(write_block, thread_no)
                for thread_no in range(thread_count)
            ]
            for future in futures:
                future.result()
        os.fsync(fd)
        os.close(fd)
        fd = -1

        with open(fpath, "rb") as f:
            actual = f.read()
        if len(actual) != thread_count * block_size:
            error(
                "parallel_write size mismatch: "
                f"expected={thread_count * block_size} actual={len(actual)}"
            )
            return False

        actual_blocks = [
            actual[offset:offset + block_size]
            for offset in range(0, len(actual), block_size)
        ]
        if sorted(actual_blocks) != sorted(expected):
            error("parallel_write data mismatch")
            return False
        return True
    except Exception as e:
        error(
            "test_parallel_write exception: "
            f"{format_os_error(e)}"
        )
        return False
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(fpath):
            os.remove(fpath)


def test_open_read_write(base_dir):
    """Test read and write operations while a file is open."""
    fpath = os.path.join(base_dir, "open_rw_file")
    debug(f"test_open_read_write: fpath={fpath}")
    try:
        with open(fpath, 'wb') as f:
            f.write(b"alpha")

        with open(fpath, 'rb+') as first, open(fpath, 'rb+') as second:
            first.seek(0, os.SEEK_END)
            first.write(b"beta")
            first.flush()
            os.fsync(first.fileno())

            expected_size = len(b"alphabeta")
            for name, fd in (("first", first), ("second", second)):
                st = os.fstat(fd.fileno())
                if st.st_size != expected_size:
                    error(
                        f"open_read_write {name} fstat size mismatch: "
                        f"expected={expected_size} got={st.st_size}"
                    )
                    return False
            st = os.stat(fpath)
            if st.st_size != expected_size:
                error(
                    "open_read_write stat size mismatch: "
                    f"expected={expected_size} got={st.st_size}"
                )
                return False

            second.seek(0)
            if second.read() != b"alphabeta":
                error("open_read_write second handle content mismatch")
                return False

            first.seek(0)
            if first.read() != b"alphabeta":
                error("open_read_write first handle content mismatch")
                return False

        with open(fpath, 'rb') as f:
            data = f.read()
            if data != b"alphabeta":
                error(
                    "open_read_write final content mismatch: "
                    f"expected={b'alphabeta'!r} got={data!r}"
                )
                return False
            return True
    except Exception as e:
        error(f"test_open_read_write exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_open_unlink_read_write(base_dir):
    """Test read and write operations after unlinking an open file."""
    fpath = os.path.join(base_dir, "open_unlink_file")
    debug(f"test_open_unlink_read_write: fpath={fpath}")
    try:
        with open(fpath, 'wb') as f:
            f.write(b"start")

        with open(fpath, 'rb+') as f:
            expected_size = len(b"start")
            st = os.fstat(f.fileno())
            if st.st_size != expected_size:
                error(
                    "open_unlink_read_write initial fstat size mismatch: "
                    f"expected={expected_size} got={st.st_size}"
                )
                return False
            st = os.stat(fpath)
            if st.st_size != expected_size:
                error(
                    "open_unlink_read_write initial stat size mismatch: "
                    f"expected={expected_size} got={st.st_size}"
                )
                return False

            os.remove(fpath)
            if os.path.exists(fpath):
                return False

            # NOTE: When the hard_remove option is used, fstat() after
            # unlink() will fail with an error
            # https://libfuse.github.io/doxygen/structfuse__config.html#ae78b050abb9e687b69dcd722e9b10789
            try:
                st = os.fstat(f.fileno())
                if st.st_size != len(b"start"):
                    error(
                        "fstat size mismatch after unlink: "
                        f"expected={len(b'start')} got={st.st_size}"
                    )
                    return False
            except OSError as e:
                error(f"fstat failed after unlink: {format_os_error(e)}")
                return False

            try:
                os.stat(fpath)
                error("stat unexpectedly succeeded after unlink")
                return False
            except OSError as e:
                expected_error(
                    "stat failed as expected after unlink: "
                    f"{format_os_error(e)}"
                )
                pass

            f.seek(0, os.SEEK_END)
            f.write(b"-middle")
            f.flush()
            os.fsync(f.fileno())

            expected_size = len(b"start-middle")
            st = os.fstat(f.fileno())
            if st.st_size != expected_size:
                error(
                    "open_unlink_read_write middle fstat size mismatch: "
                    f"expected={expected_size} got={st.st_size}"
                )
                return False

            f.seek(0)
            if f.read() != b"start-middle":
                return False

            f.seek(0, os.SEEK_END)
            f.write(b"-end")
            f.flush()
            os.fsync(f.fileno())

            expected_size = len(b"start-middle-end")
            st = os.fstat(f.fileno())
            if st.st_size != expected_size:
                error(
                    "open_unlink_read_write final fstat size mismatch: "
                    f"expected={expected_size} got={st.st_size}"
                )
                return False

            f.seek(0)
            data = f.read()
            if data != b"start-middle-end":
                error(
                    "content mismatch after unlink: "
                    f"expected={b'start-middle-end'!r} got={data!r}"
                )
                return False
            return True
    except Exception as e:
        error(f"test_open_unlink_read_write exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_open_parent_unlink_read_write(base_dir, use_xfail=False):
    """Test I/O after removing the directory of an open file."""
    dpath = os.path.join(base_dir, "open_parent_unlink_dir")
    fpath = os.path.join(dpath, "open_parent_unlink_file")
    debug(f"test_open_parent_unlink_read_write: fpath={fpath}")
    try:
        os.makedirs(dpath, exist_ok=True)
        with open(fpath, "wb") as f:
            f.write(b"start")

        with open(fpath, "rb+") as f:
            os.unlink(fpath)
            try:
                os.rmdir(dpath)
            except OSError as e:
                if e.errno == errno.ENOTEMPTY:
                    message = (
                        "test_open_parent_unlink_read_write: "
                        "rmdir failed because the open file remains: "
                        f"{format_os_error(e)}"
                    )
                    if use_xfail:
                        expected_error(message)
                    else:
                        error(message)
                    return XFAIL if use_xfail else False
                raise
            if os.path.exists(dpath):
                error("parent directory still exists after removal")
                return False

            f.seek(0, os.SEEK_END)
            f.write(b"-end")
            f.flush()
            os.fsync(f.fileno())
            f.seek(0)
            data = f.read()
            if data != b"start-end":
                error(
                    "content mismatch after parent directory removal: "
                    f"expected={b'start-end'!r} got={data!r}"
                )
                return False
        return True
    except Exception as e:
        error(
            "test_open_parent_unlink_read_write exception: "
            f"{format_os_error(e)}"
        )
        return False
    finally:
        if os.path.exists(dpath):
            rmtree_with_retry(dpath)


def test_open_unlink_utime(base_dir):
    """Test utime behavior on a file that was unlinked while open."""
    fpath = os.path.join(base_dir, "open_unlink_utime_file")
    debug(f"test_open_unlink_utime: fpath={fpath}")
    try:
        if os.path.exists(fpath):
            os.remove(fpath)

        with open(fpath, 'wb') as f:
            f.write(b"start")

        old_atime = 1000000300
        old_mtime = 1000000400
        new_atime = old_atime + 321
        new_mtime = old_mtime + 654

        with open(fpath, 'rb+') as f:
            os.unlink(fpath)
            if os.path.exists(fpath):
                error("open_unlink_utime unlink did not remove the path")
                return False

            os.utime(f.fileno(), (old_atime, old_mtime))
            os.utime(f.fileno(), (new_atime, new_mtime))

            fst = os.fstat(f.fileno())
            if int(fst.st_mtime) != new_mtime:
                error(
                    "open_unlink_utime fstat mtime mismatch: "
                    f"atime={fst.st_atime} mtime={fst.st_mtime}"
                )
                return False

            try:
                os.stat(fpath)
                error("open_unlink_utime: stat unexpectedly succeeded "
                      "after unlink")
                return False
            except OSError as e:
                expected_error(
                    "open_unlink_utime stat failed as expected after unlink: "
                    f"{format_os_error(e)}"
                )

        if os.path.exists(fpath):
            error("open_unlink_utime path still exists after close")
            return False
        return True
    except Exception as e:
        error(f"test_open_unlink_utime exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_open_unlink_ftruncate(base_dir):
    """Test ftruncate behavior on a file that was unlinked while open."""
    fpath = os.path.join(base_dir, "open_unlink_ftruncate_file")
    debug(f"test_open_unlink_ftruncate: fpath={fpath}")
    try:
        if os.path.exists(fpath):
            os.remove(fpath)

        with open(fpath, 'wb') as f:
            f.write(b"start")

        with open(fpath, 'rb+') as f:
            os.unlink(fpath)
            if os.path.exists(fpath):
                error("open_unlink_ftruncate unlink did not remove the path")
                return False

            # NOTE: When hard_remove is used, fstat() after unlink() may fail.
            try:
                st = os.fstat(f.fileno())
                if st.st_size != len(b"start"):
                    error(
                        "open_unlink_ftruncate initial fstat mismatch: "
                        f"expected={len(b'start')} got={st.st_size}"
                    )
                    return False
            except OSError as e:
                error(
                    "open_unlink_ftruncate fstat failed after unlink: "
                    f"{format_os_error(e)}"
                )
                return False

            f.truncate(3)
            st = os.fstat(f.fileno())
            if st.st_size != 3:
                error(
                    "open_unlink_ftruncate size mismatch after truncate: "
                    f"expected=3 got={st.st_size}"
                )
                return False

            try:
                os.stat(fpath)
                error("open_unlink_ftruncate stat unexpectedly succeeded "
                      "after unlink")
                return False
            except OSError as e:
                expected_error(
                    "open_unlink_ftruncate stat failed "
                    "as expected after unlink: "
                    f"{format_os_error(e)}"
                )

        if os.path.exists(fpath):
            error("open_unlink_ftruncate path still exists after close")
            return False
        return True
    except Exception as e:
        error(f"test_open_unlink_ftruncate exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_open_rename_read_write(base_dir):
    """Test read and write operations after renaming an open file."""
    src = os.path.join(base_dir, "open_rename_src")
    dst = os.path.join(base_dir, "open_rename_dst")
    debug(f"test_open_rename_read_write: src={src}, dst={dst}")
    try:
        for path in (src, dst):
            if os.path.exists(path):
                os.remove(path)

        with open(src, 'wb') as f:
            f.write(b"start")

        with open(src, 'rb+') as f:
            os.rename(src, dst)
            if os.path.exists(src) or not os.path.exists(dst):
                error("open_rename_read_write rename did not move the file")
                return False

            f.seek(0, os.SEEK_END)
            f.write(b"-middle")
            f.flush()
            os.fsync(f.fileno())

            f.seek(0)
            if f.read() != b"start-middle":
                error("open_rename_read_write mid content mismatch")
                return False

            f.seek(0, os.SEEK_END)
            f.write(b"-end")
            f.flush()
            os.fsync(f.fileno())

            f.seek(0)
            if f.read() != b"start-middle-end":
                error("open_rename_read_write final content mismatch")
                return False

        with open(dst, 'rb') as f:
            data = f.read()
            if data != b"start-middle-end":
                error(
                    "open_rename_read_write path content mismatch: "
                    f"expected={b'start-middle-end'!r} got={data!r}"
                )
                return False
            return True
    except Exception as e:
        error(f"test_open_rename_read_write exception: {format_os_error(e)}")
        return False
    finally:
        for path in (src, dst):
            if os.path.exists(path):
                os.remove(path)


def test_open_rename_utime(base_dir):
    """Test utime behavior on a file that was renamed while open."""
    src = os.path.join(base_dir, "open_rename_utime_src")
    dst = os.path.join(base_dir, "open_rename_utime_dst")
    debug(f"test_open_rename_utime: src={src}, dst={dst}")
    try:
        for path in (src, dst):
            if os.path.exists(path):
                os.remove(path)

        with open(src, 'wb') as f:
            f.write(b"start")

        old_atime = 1000000100
        old_mtime = 1000000200
        new_atime = old_atime + 321
        new_mtime = old_mtime + 654

        with open(src, 'rb+') as f:
            f.seek(0, os.SEEK_END)
            f.write(b"-middle")
            f.flush()
            os.fsync(f.fileno())

            os.rename(src, dst)
            if os.path.exists(src) or not os.path.exists(dst):
                error("open_rename_utime rename did not move the file")
                return False

            os.utime(dst, (old_atime, old_mtime))
            st = os.stat(dst)
            if int(st.st_atime) != old_atime or int(st.st_mtime) != old_mtime:
                error(
                    "open_rename_utime initial utime mismatch: "
                    f"atime={st.st_atime} mtime={st.st_mtime}"
                )
                return False

            os.utime(dst, (new_atime, new_mtime))
            st = os.stat(dst)
            if int(st.st_atime) != new_atime or int(st.st_mtime) != new_mtime:
                error(
                    "open_rename_utime updated utime mismatch: "
                    f"atime={st.st_atime} mtime={st.st_mtime}"
                )
                return False

            f.seek(0)
            data = f.read()
            if data != b"start-middle":
                error(
                    "open_rename_utime content mismatch during open: "
                    f"expected={b'start-middle'!r} got={data!r}"
                )
                return False

            fst = os.fstat(f.fileno())
            if int(fst.st_mtime) != new_mtime:
                error(
                    "open_rename_utime fstat mtime mismatch: "
                    f"expect={new_mtime} mtime={fst.st_mtime}"
                )
                return False

        st = os.stat(dst)
        if int(st.st_mtime) != new_mtime:
            error(
                "open_rename_utime stat-before-read mtime mismatch: "
                f"atime={st.st_atime} mtime={st.st_mtime}"
            )
            return False

        with open(dst, 'rb') as f:
            data = f.read()
            if data != b"start-middle":
                error(run_gfstat(dst))
                error(
                    "open_rename_utime content mismatch: "
                    f"expected={b'start-middle'!r} got={data!r}, "
                    f"size={st.st_size}"
                )
                return False
        return True
    except Exception as e:
        error(f"test_open_rename_utime exception: {format_os_error(e)}")
        return False
    finally:
        for path in (src, dst):
            if os.path.exists(path):
                os.remove(path)


def test_append(base_dir):
    """Test append behavior on an open file."""
    fpath = os.path.join(base_dir, "append_file")
    debug(f"test_append: fpath={fpath}")
    try:
        with open(fpath, 'wb') as f:
            f.write(b"start")

        with open(fpath, 'ab') as f:
            f.write(b"-middle")
            f.flush()
            os.fsync(f.fileno())
            f.write(b"-end")
            f.flush()
            os.fsync(f.fileno())

        with open(fpath, 'rb') as f:
            data = f.read()
            if data != b"start-middle-end":
                error(
                    "append content mismatch: "
                    f"expected={b'start-middle-end'!r} got={data!r}"
                )
                return False
        return True
    except Exception as e:
        error(f"test_append exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_seek(base_dir):
    """Test large seek and partial read behavior on an open file."""
    fpath = os.path.join(base_dir, "seek_file")
    size = 10 * 1024 * 1024
    debug(f"test_seek: fpath={fpath}, size={size}")
    try:
        data = bytearray(os.urandom(size))
        positions = [
            9 * 1024 * 1024 + 29,
            8 * 1024 * 1024 + 7,
            7 * 1024 * 1024 + 13,
            6 * 1024 * 1024 + 1,
            5 * 1024 * 1024 + 17,
            4 * 1024 * 1024 + 3,
            3 * 1024 * 1024 + 11,
            2 * 1024 * 1024 + 5,
            1 * 1024 * 1024 + 19,
            23,
        ]

        with open(fpath, 'wb') as f:
            f.write(data)

        with open(fpath, 'rb+') as f:
            for pos in positions:
                f.seek(pos)
                expected = data[pos:pos + 1]
                got = f.read(1)
                if got != expected:
                    error(
                        "seek partial read mismatch: "
                        f"pos={pos} expected={expected!r} got={got!r}"
                    )
                    return False

                f.seek(pos)
                f.write(b"X")
                data[pos] = ord("X")
                f.flush()
                os.fsync(f.fileno())

        with open(fpath, 'rb') as f:
            read_back = f.read()
            if read_back != data:
                error("seek final content mismatch after scattered writes")
                return False
        return True
    except Exception as e:
        error(f"test_seek exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_symlink(base_dir):
    """Test symlink creation, removal, replacement, and readlink."""
    target1 = os.path.join(base_dir, "sym_target_1")
    target2 = os.path.join(base_dir, "sym_target_2")
    link = os.path.join(base_dir, "sym_link")
    rel_target = os.path.join(base_dir, "sym_target_rel")
    rel_link = os.path.join(base_dir, "sym_link_rel")
    debug(
        "test_symlink: "
        f"target1={target1}, target2={target2}, link={link}, "
        f"rel_target={rel_target}, rel_link={rel_link}"
    )

    def cleanup():
        for path in (link, target1, target2, rel_link, rel_target):
            if os.path.lexists(path):
                os.remove(path)

    try:
        with open(target1, 'w') as f:
            f.write("dummy-1")
        with open(target2, 'w') as f:
            f.write("dummy-2")
        info(f"Created dummy files: {target1}, {target2}")

        os.symlink(target1, link)
        info(f"Created symlink: {link} -> {target1}")
        if not os.path.lexists(link):
            error("symlink unexpectedly missing after creation")
            return False

        read_target = os.readlink(link)
        if read_target != target1:
            error(
                "symlink target mismatch: "
                f"expected={target1!r} got={read_target!r}"
            )
            return False

        os.remove(link)
        info(f"Removed symlink: {link}")
        if os.path.lexists(link):
            error("symlink still exists after removal")
            return False

        os.symlink(target2, link)
        info(f"Recreated symlink: {link} -> {target2}")
        read_target = os.readlink(link)
        if read_target != target2:
            error(
                "symlink target mismatch after recreate: "
                f"expected={target2!r} got={read_target!r}"
            )
            return False

        os.remove(link)
        info(f"Removed recreated symlink: {link}")

        with open(rel_target, 'w') as f:
            f.write("dummy-rel")
        info(f"Created relative dummy file: {rel_target}")

        base_dir_fd = os.open(base_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.symlink(
                "sym_target_rel", "sym_link_rel", dir_fd=base_dir_fd
            )
        finally:
            os.close(base_dir_fd)
        info(f"Created relative symlink: {rel_link} -> sym_target_rel")

        read_target = os.readlink(rel_link)
        if read_target != "sym_target_rel":
            error(
                "relative symlink target mismatch: "
                "expected='sym_target_rel' "
                f"got={read_target!r}"
            )
            return False

        if not os.path.exists(rel_link):
            error("relative symlink did not resolve to an existing target")
            return False

        os.remove(rel_link)
        info(f"Removed relative symlink: {rel_link}")
        return True
    except Exception as e:
        error(f"test_symlink exception: {format_os_error(e)}")
        error(traceback.format_exc().rstrip())
        cleanup()
        return False
    finally:
        cleanup()


def test_gfarm2fs_ungfarmize_path(base_dir):
    """Test conversion of a gfarm URL returned by readlink()."""
    gfmd_host = get_gfmd_from_xattr(base_dir)
    # Each entry is: (link name, gfarm URL to create, expected readlink path).
    links = (
        ("ungfarmize_path_link", "gfarm://ungfarmize-test-host/test/path",
         ".gfarm/ungfarmize-test-host/test/path"),
        ("ungfarmize_path_link_local", "gfarm:///test/path",
         f".gfarm/{gfmd_host}/test/path"),
    )
    mount_point = get_mount_point(base_dir)

    try:
        for name, gfarm_url, expected_path in links:
            link = os.path.join(base_dir, name)
            os.symlink(gfarm_url, link)
            expected = os.path.join(mount_point, expected_path)
            actual = os.readlink(link)
            if actual != expected:
                error(
                    "ungfarmize_path result mismatch: "
                    f"url={gfarm_url!r} expected={expected!r} "
                    f"got={actual!r}"
                )
                return False
        return True
    except Exception as e:
        error(
            "test_gfarm2fs_ungfarmize_path exception: "
            f"{format_os_error(e)}"
        )
        return False
    finally:
        for name, _, _ in links:
            link = os.path.join(base_dir, name)
            if os.path.lexists(link):
                os.remove(link)


def test_hardlink(base_dir):
    """Test hard link creation, content sharing, and removal."""
    src = os.path.join(base_dir, "hardlink_src")
    dst = os.path.join(base_dir, "hardlink_dst")
    debug(f"test_hardlink: src={src}, dst={dst}")
    try:
        for path in (src, dst):
            if os.path.exists(path):
                os.remove(path)

        with open(src, 'w') as f:
            f.write("hardlink content")
        try:
            os.link(src, dst)
        except OSError as e:
            error(f"hardlink creation failed: {format_os_error(e)}")
            return False
        if not os.path.exists(src) or not os.path.exists(dst):
            error("hardlink missing after creation")
            return False

        with open(dst, 'r') as f:
            if f.read() != "hardlink content":
                error("hardlink destination content mismatch")
                return False

        with open(src, 'w') as f:
            f.write("updated")
        with open(dst, 'r') as f:
            if f.read() != "updated":
                error("hardlink content not shared after source update")
                return False

        os.remove(dst)
        if not os.path.exists(src) or os.path.exists(dst):
            error("hardlink removal state mismatch")
            return False
        return True
    except Exception as e:
        error(f"test_hardlink exception: {format_os_error(e)}")
        return False
    finally:
        for path in (src, dst):
            if os.path.exists(path):
                os.remove(path)


def test_chmod(base_dir):
    """Test chmod operations on a file and a directory."""
    fpath = os.path.join(base_dir, "chmod_file")
    dpath = os.path.join(base_dir, "chmod_dir")
    debug(f"test_chmod: fpath={fpath}, dpath={dpath}")

    def cleanup():
        if os.path.exists(fpath):
            os.remove(fpath)
        if os.path.exists(dpath):
            os.chmod(dpath, 0o755)
            rmtree_with_retry(dpath)
    try:
        cleanup()

        with open(fpath, 'w') as f:
            f.write("content")
        info(f"Created file for chmod: {fpath}")

        os.mkdir(dpath)
        with open(os.path.join(dpath, "marker"), 'w') as f:
            f.write("content")
        info(f"Created directory for chmod: {dpath}")

        os.chmod(fpath, 0o000)
        debug(f"Set mode to 000 for {fpath}")
        try:
            with open(fpath, 'r') as f:
                _ = f.read()
        except OSError as e:
            debug(
                "chmod read-denied check passed: "
                f"{format_os_error(e)}"
            )
        else:
            error("chmod read-denied check unexpectedly succeeded")
            return False

        os.chmod(fpath, 0o644)
        info(f"Set mode to 644 for {fpath}")
        with open(fpath, 'r') as f:
            if f.read() != "content":
                error("chmod read-after-restore content mismatch")
                return False

        os.chmod(fpath, 0o444)
        info(f"Set mode to 444 for {fpath}")
        try:
            with open(fpath, 'w') as f:
                f.write("new")
        except OSError as e:
            debug(
                "chmod write-denied check passed: "
                f"{format_os_error(e)}"
            )
        else:
            error("chmod write-denied check unexpectedly succeeded")
            return False

        os.chmod(fpath, 0o644)
        info(f"Restored mode to 644 for {fpath}")

        os.chmod(dpath, 0o000)
        debug(f"Set mode to 000 for {dpath}")
        try:
            os.listdir(dpath)
        except OSError as e:
            debug(
                "chmod dir-read-denied check passed: "
                f"{format_os_error(e)}"
            )
        else:
            error("chmod dir-read-denied check unexpectedly succeeded")
            return False

        os.chmod(dpath, 0o755)
        info(f"Set mode to 755 for {dpath}")
        if "marker" not in os.listdir(dpath):
            error("chmod directory marker missing after restore")
            return False

        os.chmod(dpath, 0o555)
        info(f"Set mode to 555 for {dpath}")
        try:
            with open(os.path.join(dpath, "new_file"), 'w') as f:
                f.write("new")
        except OSError as e:
            debug(
                "chmod dir-write-denied check passed: "
                f"{format_os_error(e)}"
            )
        else:
            error("chmod dir-write-denied check unexpectedly succeeded")
            return False

        os.chmod(dpath, 0o755)
        info(f"Restored mode to 755 for {dpath}")
        cleanup()
        return True
    except Exception as e:
        error(f"test_chmod exception: {format_os_error(e)}")
        cleanup()
        return False


def test_truncate(base_dir):
    """Test path-based truncate behavior."""
    fpath = os.path.join(base_dir, "truncate_file")
    debug(f"test_truncate: fpath={fpath}")
    try:
        with open(fpath, 'w') as f:
            f.write("0123456789")

        os.truncate(fpath, 4)
        with open(fpath, 'r') as f:
            if f.read() != "0123":
                error("truncate content mismatch after os.truncate")
                return False

        st = os.stat(fpath)
        if st.st_size != 4:
            error(f"truncate size mismatch: expected=4 got={st.st_size}")
            return False
        return True
    except Exception as e:
        error(f"test_truncate exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_ftruncate(base_dir):
    """Test fd-based ftruncate behavior."""
    fpath = os.path.join(base_dir, "ftruncate_file")
    debug(f"test_ftruncate: fpath={fpath}")
    try:
        with open(fpath, 'w') as f:
            f.write("0123456789")

        with open(fpath, 'r+b') as f:
            f.truncate(2)
            st = os.fstat(f.fileno())
            if st.st_size != 2:
                error(
                    "ftruncate size mismatch after shrink: "
                    f"expected=2 got={st.st_size}"
                )
                return False

        with open(fpath, 'rb') as f:
            data = f.read()
            if data != b"01":
                error(
                    "ftruncate content mismatch after shrink reopen: "
                    f"got={data!r}"
                )
                return False

        with open(fpath, 'r+b') as f:
            f.truncate(8)
            st = os.fstat(f.fileno())
            if st.st_size != 8:
                error(
                    "ftruncate size mismatch after extend: "
                    f"expected=8 got={st.st_size}"
                )
                return False

        with open(fpath, 'rb') as f:
            data = f.read()
            if data[:2] != b"01" or data[2:] != b"\x00" * 6:
                error(
                    "ftruncate final content mismatch: "
                    f"got={data!r}"
                )
                return False
        return True
    except Exception as e:
        error(f"test_ftruncate exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_negative_lookup_recreate(base_dir):
    """Test recreate and reopen after a negative lookup."""
    fpath = os.path.join(base_dir, "negative_lookup_file")
    debug(f"test_negative_lookup_recreate: fpath={fpath}")
    try:
        if os.path.exists(fpath):
            os.remove(fpath)

        try:
            open(fpath, 'rb')
            error("negative lookup open unexpectedly succeeded")
            return False
        except OSError as e:
            debug(
                "negative lookup open failed as expected: "
                f"{format_os_error(e)}"
            )

        with open(fpath, 'wb') as f:
            f.write(b"first")

        with open(fpath, 'rb') as f:
            data = f.read()
            if data != b"first":
                error(
                    "negative lookup first reopen mismatch: "
                    f"expected={b'first'!r} got={data!r}"
                )
                return False

        os.remove(fpath)

        with open(fpath, 'wb') as f:
            f.write(b"second")

        with open(fpath, 'rb') as f:
            data = f.read()
            if data != b"second":
                error(
                    "negative lookup recreate mismatch: "
                    f"expected={b'second'!r} got={data!r}"
                )
                return False
        return True
    except Exception as e:
        error(
            "test_negative_lookup_recreate exception: "
            f"{format_os_error(e)}"
        )
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_readdir_inode_consistency(base_dir):
    """Test inode consistency for directory entries."""
    dpath = os.path.join(base_dir, "readdir_inode_dir")
    fpath = os.path.join(dpath, "inode_file")
    debug(f"test_readdir_inode_consistency: dpath={dpath}, fpath={fpath}")
    try:
        if os.path.exists(dpath):
            rmtree_with_retry(dpath)
        os.mkdir(dpath)

        with open(fpath, 'wb') as f:
            f.write(b"content")

        st_file = os.stat(fpath)
        st_dir = os.stat(dpath)

        # DirEntry.inode() is the inode returned by readdir(3), while
        # os.stat() obtains the inode through a separate lookup.
        dir_entries = {}
        with os.scandir(dpath) as entries:
            for entry in entries:
                dir_entries[entry.name] = entry.inode()

        if "inode_file" not in dir_entries:
            error("readdir inode test missing file entry")
            return False

        if dir_entries["inode_file"] != st_file.st_ino:
            error(
                "readdir inode mismatch: "
                f"expected={st_file.st_ino} got={dir_entries['inode_file']}"
            )
            return False

        if st_dir.st_ino == dir_entries["inode_file"]:
            error("readdir inode unexpectedly reused directory inode")
            return False

        return True
    except Exception as e:
        error(
            "test_readdir_inode_consistency exception: "
            f"{format_os_error(e)}"
        )
        return False
    finally:
        if os.path.exists(dpath):
            rmtree_with_retry(dpath)


def test_chown(base_dir):
    """Test chown (change owner to self)."""
    fpath = os.path.join(base_dir, "chown_file")
    debug(f"test_chown: fpath={fpath}")
    try:
        with open(fpath, 'w') as f:
            f.write("dummy")

        uid = os.getuid()
        os.chown(fpath, uid, -1)
        info(f"Changed owner of {fpath} to self (UID {uid})")
        return True
    except Exception as e:
        error(f"test_chown exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_statvfs(base_dir):
    """Test df-like operation (statvfs)."""
    debug(f"test_statvfs: base_dir={base_dir}")
    try:
        st = os.statvfs(base_dir)
        res = st.f_frsize > 0
        info(f"statvfs result: {res} (frsize={st.f_frsize})")
        return res
    except Exception as e:
        error(f"test_statvfs exception: {format_os_error(e)}")
        return False


def test_utime(base_dir):
    """Test atime and mtime updates."""
    fpath = os.path.join(base_dir, "time_file")
    debug(f"test_utime: fpath={fpath}")
    try:
        with open(fpath, 'w') as f:
            f.write("time")

        old_atime = 1000000000
        old_mtime = 1000000000
        os.utime(fpath, (old_atime, old_mtime))
        st = os.stat(fpath)
        if int(st.st_atime) != old_atime or int(st.st_mtime) != old_mtime:
            error(
                "utime initial timestamps mismatch: "
                f"atime={st.st_atime} mtime={st.st_mtime}"
            )
            return False

        new_atime = old_atime + 123
        new_mtime = old_mtime + 456
        os.utime(fpath, (new_atime, new_mtime))
        st = os.stat(fpath)
        if int(st.st_atime) != new_atime or int(st.st_mtime) != new_mtime:
            error(
                "utime updated timestamps mismatch: "
                f"atime={st.st_atime} mtime={st.st_mtime}"
            )
            return False
        return True
    except Exception as e:
        error(f"test_utime exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_utime_omit(base_dir):
    """Test that utimensat preserves either timestamp specified
       as UTIME_OMIT."""
    fpath = os.path.join(base_dir, "time_omit_file")
    debug(f"test_utime_omit: fpath={fpath}")
    try:
        with open(fpath, 'w') as f:
            f.write("time")

        old_atime_ns = 1000000000000000000
        old_mtime_ns = 1000000000000000000
        os.utime(fpath, ns=(old_atime_ns, old_mtime_ns))

        # Linux defines UTIME_OMIT as ((1 << 30) - 2).  Use utimensat
        # directly because Python's os.utime() does not expose this
        # timespec value on all supported versions.
        class Timespec(ctypes.Structure):
            _fields_ = [("tv_sec", ctypes.c_long),
                        ("tv_nsec", ctypes.c_long)]

        libc = ctypes.CDLL(None, use_errno=True)
        libc.utimensat.argtypes = [ctypes.c_int, ctypes.c_char_p,
                                   ctypes.POINTER(Timespec), ctypes.c_int]
        libc.utimensat.restype = ctypes.c_int
        UTIME_OMIT = (1 << 30) - 2
        AT_FDCWD = -100

        def call_utimensat(times):
            if libc.utimensat(AT_FDCWD, os.fsencode(fpath), times, 0) != 0:
                errno_value = ctypes.get_errno()
                raise OSError(errno_value, os.strerror(errno_value))

        def check_timestamps(case_name, expected_atime_ns,
                             expected_mtime_ns):
            st = os.stat(fpath)
            if (st.st_atime_ns != expected_atime_ns or
                    st.st_mtime_ns != expected_mtime_ns):
                error(
                    f"UTIME_OMIT {case_name} timestamps mismatch: "
                    f"atime_ns={st.st_atime_ns} "
                    f"mtime_ns={st.st_mtime_ns}"
                )
                return False
            return True

        new_mtime_ns = old_mtime_ns + 456000000000
        call_utimensat((Timespec * 2)(
            Timespec(0, UTIME_OMIT),
            Timespec(new_mtime_ns // 1000000000,
                     new_mtime_ns % 1000000000)))
        if not check_timestamps("atime", old_atime_ns, new_mtime_ns):
            return False

        # Reset both timestamps before testing the opposite side.
        os.utime(fpath, ns=(old_atime_ns, old_mtime_ns))
        new_atime_ns = old_atime_ns + 321000000000
        call_utimensat((Timespec * 2)(
            Timespec(new_atime_ns // 1000000000,
                     new_atime_ns % 1000000000),
            Timespec(0, UTIME_OMIT)))
        if not check_timestamps("mtime", new_atime_ns, old_mtime_ns):
            return False
        return True
    except Exception as e:
        error(f"test_utime_omit exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_utime_now(base_dir):
    """Test that utimensat updates a timestamp specified as UTIME_NOW."""
    fpath = os.path.join(base_dir, "time_now_file")
    debug(f"test_utime_now: fpath={fpath}")
    try:
        with open(fpath, 'w') as f:
            f.write("time")

        old_atime_ns = 1000000000000000000
        old_mtime_ns = 1000000000000000000
        os.utime(fpath, ns=(old_atime_ns, old_mtime_ns))

        class Timespec(ctypes.Structure):
            _fields_ = [("tv_sec", ctypes.c_long),
                        ("tv_nsec", ctypes.c_long)]

        libc = ctypes.CDLL(None, use_errno=True)
        libc.utimensat.argtypes = [ctypes.c_int, ctypes.c_char_p,
                                   ctypes.POINTER(Timespec), ctypes.c_int]
        libc.utimensat.restype = ctypes.c_int
        UTIME_NOW = (1 << 30) - 1
        AT_FDCWD = -100
        now_tolerance_ns = 5 * 1000000000

        def call_utimensat(times):
            before_ns = current_time_ns()
            if libc.utimensat(AT_FDCWD, os.fsencode(fpath), times, 0) != 0:
                errno_value = ctypes.get_errno()
                raise OSError(errno_value, os.strerror(errno_value))
            after_ns = current_time_ns()
            return before_ns, after_ns

        new_mtime_ns = old_mtime_ns + 456000000000
        before_ns, after_ns = call_utimensat((Timespec * 2)(
            Timespec(0, UTIME_NOW),
            Timespec(new_mtime_ns // 1000000000,
                     new_mtime_ns % 1000000000)))
        st = os.stat(fpath)
        if (st.st_mtime_ns != new_mtime_ns or
                not (before_ns - now_tolerance_ns <= st.st_atime_ns <=
                     after_ns + now_tolerance_ns)):
            error(
                "UTIME_NOW atime timestamps mismatch: "
                f"atime_ns={st.st_atime_ns} mtime_ns={st.st_mtime_ns} "
                f"expected_mtime_ns={new_mtime_ns} "
                f"now_range=[{before_ns}, {after_ns}]"
            )
            return False

        # Reset both timestamps before testing UTIME_NOW on mtime.
        os.utime(fpath, ns=(old_atime_ns, old_mtime_ns))
        new_atime_ns = old_atime_ns + 321000000000
        before_ns, after_ns = call_utimensat((Timespec * 2)(
            Timespec(new_atime_ns // 1000000000,
                     new_atime_ns % 1000000000),
            Timespec(0, UTIME_NOW)))
        st = os.stat(fpath)
        if (st.st_atime_ns != new_atime_ns or
                not (before_ns - now_tolerance_ns <= st.st_mtime_ns <=
                     after_ns + now_tolerance_ns)):
            error(
                "UTIME_NOW mtime timestamps mismatch: "
                f"atime_ns={st.st_atime_ns} mtime_ns={st.st_mtime_ns} "
                f"expected_atime_ns={new_atime_ns} "
                f"now_range=[{before_ns}, {after_ns}]"
            )
            return False
        return True
    except Exception as e:
        error(f"test_utime_now exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_open_utime_omit(base_dir):
    """Test UTIME_OMIT while a written file remains open until close."""
    fpath1 = os.path.join(base_dir, "open_time_omit_file1")
    fpath2 = os.path.join(base_dir, "open_time_omit_file2")
    fpath3 = os.path.join(base_dir, "open_time_omit_file3")
    fpath4 = os.path.join(base_dir, "open_time_omit_file4")
    fpaths = (fpath1, fpath2, fpath3, fpath4)
    debug(f"test_open_utime_omit: fpaths={fpaths}")
    try:
        old_atime_ns = 1000000000000000000
        old_mtime_ns = 1000000000000000000

        class Timespec(ctypes.Structure):
            _fields_ = [("tv_sec", ctypes.c_long),
                        ("tv_nsec", ctypes.c_long)]

        libc = ctypes.CDLL(None, use_errno=True)
        libc.utimensat.argtypes = [ctypes.c_int, ctypes.c_char_p,
                                   ctypes.POINTER(Timespec), ctypes.c_int]
        libc.utimensat.restype = ctypes.c_int
        UTIME_OMIT = (1 << 30) - 2
        AT_FDCWD = -100

        def call_utimensat(path, times):
            if libc.utimensat(AT_FDCWD, os.fsencode(path), times, 0) != 0:
                errno_value = ctypes.get_errno()
                raise OSError(errno_value, os.strerror(errno_value))

        def create_file(path):
            if os.path.exists(path):
                os.remove(path)
            with open(path, "wb") as f:
                f.write(b"start")
            os.utime(path, ns=(old_atime_ns, old_mtime_ns))

        # 1. A write followed by UTIME_OMIT(atime) preserves the old atime.
        create_file(fpath1)
        new_mtime_ns = old_mtime_ns + 456000000000
        preserved_atime_ns = os.stat(fpath1).st_atime_ns
        with open(fpath1, "rb+") as f:
            f.write(b"-atime")
            f.flush()
            call_utimensat(fpath1, (Timespec * 2)(
                Timespec(0, UTIME_OMIT),
                Timespec(new_mtime_ns // 1000000000,
                         new_mtime_ns % 1000000000)))

        st = os.stat(fpath1)
        debug(
            "open_utime_omit: "
            f"atime_ns={st.st_atime_ns} mtime_ns={st.st_mtime_ns} "
            f"expected_atime_ns={preserved_atime_ns} "
            f"new_mtime_ns={new_mtime_ns}"
        )
        if (st.st_atime_ns != preserved_atime_ns or
                st.st_mtime_ns != new_mtime_ns):
            error(
                "open_utime_omit atime mismatch: "
                f"atime_ns={st.st_atime_ns} != "
                f"expected_atime_ns={preserved_atime_ns}, "
                f"mtime_ns={st.st_mtime_ns} != new_mtime_ns={new_mtime_ns}"
            )
            return False

        # 2. A read followed by UTIME_OMIT(mtime) preserves the old mtime.
        create_file(fpath2)
        new_atime_ns = old_atime_ns + 321000000000
        preserved_mtime_ns = os.stat(fpath2).st_mtime_ns
        with open(fpath2, "rb+") as f:
            f.read()
            call_utimensat(fpath2, (Timespec * 2)(
                Timespec(new_atime_ns // 1000000000,
                         new_atime_ns % 1000000000),
                Timespec(0, UTIME_OMIT)))

        st = os.stat(fpath2)
        if (st.st_atime_ns != new_atime_ns or
                st.st_mtime_ns != preserved_mtime_ns):
            error(
                "open_utime_omit mtime mismatch: "
                f"atime_ns={st.st_atime_ns} != new_atime_ns={new_atime_ns}, "
                f"mtime_ns={st.st_mtime_ns} != "
                f"expected_mtime_ns={preserved_mtime_ns} "
            )
            return False

        # 3. A write updates mtime; UTIME_OMIT(mtime) preserves that mtime.
        create_file(fpath3)
        new_atime_ns = old_atime_ns + 321000000000
        with open(fpath3, "rb+") as f:
            f.seek(0, os.SEEK_END)
            f.write(b"-write")
            f.flush()
            os.fsync(f.fileno())
            write_mtime_ns = os.fstat(f.fileno()).st_mtime_ns
            if write_mtime_ns == old_mtime_ns:
                error(
                    "open_utime_omit write did not update mtime: "
                    f"mtime_ns={write_mtime_ns}"
                )
                return False

            call_utimensat(fpath3, (Timespec * 2)(
                Timespec(new_atime_ns // 1000000000,
                         new_atime_ns % 1000000000),
                Timespec(0, UTIME_OMIT)))

        st = os.stat(fpath3)
        if (st.st_atime_ns != new_atime_ns or
                st.st_mtime_ns != write_mtime_ns):
            error(
                "open_utime_omit write/omit-mtime timestamp mismatch: "
                f"atime_ns={st.st_atime_ns} != "
                f"new_atime_ns={new_atime_ns}, "
                f"mtime_ns={st.st_mtime_ns} != "
                f"write_mtime_ns={write_mtime_ns}"
            )
            return False

        # 4. A read updates atime; UTIME_OMIT(atime) preserves it after close.
        create_file(fpath4)
        requested_mtime_ns = old_mtime_ns + 654000000000
        with open(fpath4, "rb+") as f:
            f.seek(0)
            f.read()
            read_atime_ns = os.fstat(f.fileno()).st_atime_ns
            call_utimensat(fpath4, (Timespec * 2)(
                Timespec(0, UTIME_OMIT),
                Timespec(requested_mtime_ns // 1000000000,
                         requested_mtime_ns % 1000000000)))

        st = os.stat(fpath4)
        if (st.st_atime_ns != read_atime_ns or
                st.st_mtime_ns != requested_mtime_ns):
            error(
                "open_utime_omit read/omit-atime timestamp mismatch: "
                f"atime_ns={st.st_atime_ns} != "
                f"read_atime_ns={read_atime_ns}, "
                f"mtime_ns={st.st_mtime_ns} != "
                f"requested_mtime_ns={requested_mtime_ns}"
            )
            return False
        return True
    except Exception as e:
        error(f"test_open_utime_omit exception: {format_os_error(e)}")
        return False
    finally:
        for path in fpaths:
            if os.path.exists(path):
                os.remove(path)


def test_open_utime_cancel(base_dir):
    """Test that read/write preserve the other open-file utime update."""
    fpath_prefix = os.path.join(base_dir, "open_utime_cancel_file")
    fpath1 = fpath_prefix + "_mtime"
    fpath2 = fpath_prefix + "_atime"
    debug(f"test_open_utime_cancel: fpath_prefix={fpath_prefix}")
    try:
        old_atime_ns = 1000000000000000000
        old_mtime_ns = 1000000000000000000

        class Timespec(ctypes.Structure):
            _fields_ = [("tv_sec", ctypes.c_long),
                        ("tv_nsec", ctypes.c_long)]

        libc = ctypes.CDLL(None, use_errno=True)
        libc.utimensat.argtypes = [ctypes.c_int, ctypes.c_char_p,
                                   ctypes.POINTER(Timespec), ctypes.c_int]
        libc.utimensat.restype = ctypes.c_int
        AT_FDCWD = -100

        def call_utimensat(p, times):
            if libc.utimensat(AT_FDCWD, os.fsencode(p), times, 0) != 0:
                errno_value = ctypes.get_errno()
                raise OSError(errno_value, os.strerror(errno_value))

        def create_file(p):
            if os.path.exists(p):
                os.remove(p)
            with open(p, "wb") as f:
                f.write(b"start")
            os.utime(p, ns=(old_atime_ns, old_mtime_ns))

        # A write after utimensat updates mtime but preserves utime atime.
        create_file(fpath1)
        requested_mtime_ns = old_mtime_ns + 456000000000
        with open(fpath1, "rb+") as f:
            f.write(b"-before")
            f.flush()
            call_utimensat(fpath1, (Timespec * 2)(
                Timespec(old_atime_ns // 1000000000,
                         old_atime_ns % 1000000000),
                Timespec(requested_mtime_ns // 1000000000,
                         requested_mtime_ns % 1000000000)))
            f.write(b"-after")  # update mtime
            f.flush()

        st = os.stat(fpath1)
        if (st.st_atime_ns != old_atime_ns or
                st.st_mtime_ns == requested_mtime_ns):
            error(
                "open_utime_cancel write timestamp mismatch: "
                f"atime_ns={st.st_atime_ns} mtime_ns={st.st_mtime_ns}"
            )
            return False

        # A read after utimensat updates atime but preserves utime mtime.
        create_file(fpath2)
        requested_atime_ns = old_atime_ns + 321000000000
        with open(fpath2, "rb+") as f:
            f.write(b"-before")
            f.flush()
            call_utimensat(fpath2, (Timespec * 2)(
                Timespec(requested_atime_ns // 1000000000,
                         requested_atime_ns % 1000000000),
                Timespec(old_mtime_ns // 1000000000,
                         old_mtime_ns % 1000000000)))
            f.seek(0)
            f.read()  # update atime

        st = os.stat(fpath2)
        if (st.st_atime_ns == requested_atime_ns or
                st.st_mtime_ns != old_mtime_ns):
            error(
                "open_utime_cancel read timestamp mismatch: "
                f"atime_ns={st.st_atime_ns} mtime_ns={st.st_mtime_ns}"
            )
            return False

        return True
    except Exception as e:
        error(
            "test_open_utime_cancel exception: "
            f"{format_os_error(e)}"
        )
        return False
    finally:
        if os.path.exists(fpath1):
            os.remove(fpath1)
        if os.path.exists(fpath2):
            os.remove(fpath2)


def test_errors(base_dir):
    """Test expected error cases for missing paths and invalid opens."""
    missing_file = os.path.join(base_dir, "missing_file")
    missing_dir = os.path.join(base_dir, "missing_dir")
    readonly_dir = os.path.join(base_dir, "readonly_dir")
    debug(
        "test_errors: "
        f"missing_file={missing_file}, missing_dir={missing_dir}, "
        f"readonly_dir={readonly_dir}"
    )
    try:
        for path in (missing_file, missing_dir):
            if os.path.exists(path):
                if os.path.isdir(path):
                    rmtree_with_retry(path)
                else:
                    os.remove(path)

        try:
            open(missing_file, 'r')
        except OSError as e:
            msg = format_os_error(e)
            expected_error(f"missing file read failed as expected: {msg}")
        else:
            error("missing file read unexpectedly succeeded")
            return False

        try:
            os.listdir(missing_dir)
        except OSError as e:
            msg = format_os_error(e)
            expected_error(f"missing dir list failed as expected: {msg}")
        else:
            error("missing dir list unexpectedly succeeded")
            return False

        if os.path.exists(readonly_dir):
            rmtree_with_retry(readonly_dir)
        os.mkdir(readonly_dir)
        os.chmod(readonly_dir, 0o555)
        try:
            with open(os.path.join(readonly_dir, "new_file"), 'w') as _:
                _.write("new")
        except OSError as e:
            msg = format_os_error(e)
            expected_error(
                f"readonly dir file-create failed as expected: {msg}"
            )
        else:
            error("readonly dir file-create unexpectedly succeeded")
            return False

        try:
            os.mkdir(os.path.join(readonly_dir, "new_dir"))
        except OSError as e:
            msg = format_os_error(e)
            expected_error(f"readonly dir mkdir failed as expected: {msg}")
        else:
            error("readonly dir mkdir unexpectedly succeeded")
            return False
        return True
    except Exception as e:
        error(f"test_errors exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(readonly_dir):
            os.chmod(readonly_dir, 0o755)
            rmtree_with_retry(readonly_dir)


def test_seekdir(base_dir):
    """Test seekdir/telldir via libc (mirrors test_syscalls.c test_seekdir)."""
    dpath = os.path.join(base_dir, "seekdir_dir")
    debug(f"test_seekdir: dpath={dpath}")
    libc = getattr(thread_local, "_libc", None)
    if libc is None:
        try:
            libc = ctypes.CDLL(
                ctypes.util.find_library("c"), use_errno=True
            )

            class _DIR(ctypes.Structure):
                pass

            class _dirent(ctypes.Structure):
                _fields_ = [
                    ("d_ino", ctypes.c_uint64),
                    ("d_off", ctypes.c_int64),
                    ("d_reclen", ctypes.c_ushort),
                    ("d_type", ctypes.c_ubyte),
                    ("d_name", ctypes.c_char * 256),
                ]

            libc.opendir.restype = ctypes.POINTER(_DIR)
            libc.opendir.argtypes = [ctypes.c_char_p]
            libc.telldir.restype = ctypes.c_long
            libc.telldir.argtypes = [ctypes.POINTER(_DIR)]
            libc.seekdir.argtypes = [
                ctypes.POINTER(_DIR), ctypes.c_long
            ]
            libc.readdir.restype = ctypes.POINTER(_dirent)
            libc.readdir.argtypes = [ctypes.POINTER(_DIR)]
            libc.closedir.argtypes = [ctypes.POINTER(_DIR)]
            thread_local._libc = libc
        except (OSError, AttributeError) as e:
            debug(
                "test_seekdir: libc telldir/seekdir not available: "
                f"{format_os_error(e)}"
            )
            return False
    libc = thread_local._libc
    testfiles = ("f1", "f2", "f3")
    try:
        if os.path.exists(dpath):
            rmtree_with_retry(dpath)
        os.mkdir(dpath)
        # Create test files
        for name in testfiles:
            fpath = os.path.join(dpath, name)
            with open(fpath, "wb") as f:
                f.write(b"x")

        dp = libc.opendir(dpath.encode())
        if not dp:
            errno_val = ctypes.get_errno()
            error(
                "test_seekdir: opendir failed: "
                f"{os.strerror(errno_val)}"
            )
            return False
        try:
            # Remember directory offsets for testfiles
            offsets = []
            names = []
            for _ in range(len(testfiles)+1):
                off = libc.telldir(dp)
                de = libc.readdir(dp)
                if not de:
                    break
                name = de.contents.d_name.decode(errors="replace")
                if name in (".", ".."):
                    continue
                offsets.append(off)
                names.append(name)
            if not offsets:
                error("test_seekdir: no entries recorded")
                return False
            debug(
                "test_seekdir: recorded "
                f"{len(offsets)} offsets: {names}"
            )

            # Walk to the end of directory
            while True:
                de = libc.readdir(dp)
                if not de:
                    break

            # Seek backwards and verify the entries can still be read
            seen = []
            for off in reversed(offsets):
                libc.seekdir(dp, off)
                de = libc.readdir(dp)
                if not de:
                    error(
                        "test_seekdir: readdir returned NULL after seekdir"
                    )
                    fuse_version = get_fuse_version(base_dir)
                    # https://github.com/libfuse/libfuse/commit/06fc40705f23cb7e9af4df2febae8e6889b1a95d
                    if fuse_version is not None and fuse_version < (2, 9, 9):
                        warn(
                            "test_seekdir: expected failure with "
                            f"FUSE {'.'.join(map(str, fuse_version))} "
                            "(< 2.9.9)"
                        )
                        return XFAIL
                    return False
                seen.append(de.contents.d_name.decode(errors="replace"))
            debug(f"test_seekdir: re-read names: {seen}")

            if sorted(seen) != sorted(names):
                error(
                    "test_seekdir: re-read mismatch: "
                    f"expected={sorted(names)} got={sorted(seen)}"
                )
                return False
            info(f"test_seekdir: {len(seen)} entries re-read OK")
            return True
        finally:
            libc.closedir(dp)
    except Exception as e:
        error(f"test_seekdir exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(dpath):
            rmtree_with_retry(dpath)


def test_copy_file_range(base_dir):
    """Test copy_file_range (mirrors test_syscalls.c test_copy_file_range)."""
    if not hasattr(os, "copy_file_range"):
        warn(
            "test_copy_file_range: os.copy_file_range not available; "
            f"skipping (python={sys.version.split()[0]})"
        )
        return SKIP
    src_path = os.path.join(base_dir, "copy_file_range_src")
    dst_path = os.path.join(base_dir, "copy_file_range_dst")
    debug(
        "test_copy_file_range: "
        f"src={src_path}, dst={dst_path}"
    )
    data = b"abcdefghijklmnopqrstuvwxyz"
    expected = data
    try:
        for path in (src_path, dst_path):
            if os.path.exists(path):
                os.remove(path)
        # Create source with data
        with open(src_path, "wb") as f:
            f.write(data)
        # Create destination (truncate) using os.open
        fd_dst = os.open(
            dst_path,
            os.O_CREAT | os.O_WRONLY | os.O_TRUNC,
            0o644,
        )
        try:
            fd_src = os.open(src_path, os.O_RDONLY)
            try:
                # os.copy_file_range(src, dst, count,
                #                    offset_src=None,
                #                    offset_dst=None)
                copied = os.copy_file_range(
                    fd_src, fd_dst, len(data), 0, 0
                )
                if copied != len(data):
                    error(
                        "copy_file_range short copy: "
                        f"expected={len(data)} got={copied}"
                    )
                    return False
            finally:
                os.close(fd_src)
        finally:
            os.close(fd_dst)

        with open(dst_path, "rb") as f:
            got = f.read()
        if got != expected:
            error(
                "copy_file_range content mismatch: "
                f"expected={expected!r} got={got!r}"
            )
            return False
        info(
            f"test_copy_file_range: copied {len(data)} bytes OK"
        )
        return True
    except Exception as e:
        error(
            f"test_copy_file_range exception: "
            f"{format_os_error(e)}"
        )
        return False
    finally:
        for path in (src_path, dst_path):
            if os.path.exists(path):
                os.remove(path)


def test_creat_excl(base_dir):
    """Test O_CREAT|O_EXCL behavior (mirrors test_syscalls.c test_open)."""
    fpath = os.path.join(base_dir, "creat_excl_file")
    debug(f"test_creat_excl: fpath={fpath}")
    try:
        if os.path.exists(fpath):
            os.remove(fpath)
        # 1) Creating a new file with O_CREAT|O_EXCL should succeed
        fd = os.open(
            fpath,
            os.O_CREAT | os.O_EXCL | os.O_RDWR,
            0o644,
        )
        try:
            data = b"abcdefghijklmnopqrstuvwxyz"
            written = os.write(fd, data)
            if written != len(data):
                error(
                    "creat_excl: short write: "
                    f"expected={len(data)} got={written}"
                )
                return False
        finally:
            os.close(fd)
        if not os.path.isfile(fpath):
            error("creat_excl: file missing after initial create")
            return False
        st = os.stat(fpath)
        if st.st_size != len(data):
            error(
                "creat_excl: size mismatch after initial create: "
                f"expected={len(data)} got={st.st_size}"
            )
            return False
        with open(fpath, "rb") as f:
            got = f.read()
        if got != data:
            error(
                "creat_excl: content mismatch after initial create: "
                f"expected={data!r} got={got!r}"
            )
            return False
        # 2) Re-creating the same file with O_CREAT|O_EXCL must fail
        #    with EEXIST
        try:
            fd2 = os.open(
                fpath,
                os.O_CREAT | os.O_EXCL | os.O_RDWR,
                0o644,
            )
        except OSError as e:
            if e.errno != errno.EEXIST:
                error(
                    "creat_excl: expected EEXIST, got: "
                    f"{format_os_error(e)}"
                )
                return False
            expected_error(
                "creat_excl: re-open with O_EXCL failed as expected: "
                f"{format_os_error(e)}"
            )
        else:
            os.close(fd2)
            error(
                "creat_excl: re-open with O_EXCL unexpectedly succeeded"
            )
            return False
        # 3) The original content must still match after the failed
        #    re-open attempt
        with open(fpath, "rb") as f:
            got = f.read()
        if got != data:
            error(
                "creat_excl: content mismatch after failed re-open: "
                f"expected={data!r} got={got!r}"
            )
            return False
        # 4) O_CREAT (without O_EXCL) on an existing file must succeed
        fd3 = os.open(
            fpath, os.O_CREAT | os.O_RDWR, 0o644
        )
        try:
            pass
        finally:
            os.close(fd3)
        info("test_creat_excl: O_EXCL semantics verified")
        return True
    except Exception as e:
        error(f"test_creat_excl exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_xattr(base_dir, gfarm2fs=False):
    """Test xattr (extended attribute) operations."""
    fpath = os.path.join(base_dir, "xattr_file")
    debug(f"test_xattr: fpath={fpath}")
    try:
        with open(fpath, 'w') as f:
            f.write("xattr content")
        info(f"Created file for xattr: {fpath}")

        os_setxattr = getattr(os, 'setxattr', None)
        if os_setxattr is None:
            debug("os.setxattr not supported on this system")
            return False

        os_getxattr = getattr(os, 'getxattr', None)
        os_listxattr = getattr(os, 'listxattr', None)
        os_removexattr = getattr(os, 'removexattr', None)
        if (
            os_getxattr is None or
            os_listxattr is None or
            os_removexattr is None
        ):
            debug("xattr helpers not fully supported on this system")
            return False

        expected = {}
        for i in range(1, 11):
            key = f"user.test{i}"
            val = f"test_val{i}".encode()
            os_setxattr(fpath, key, val)
            expected[key] = val

        listed = os_listxattr(fpath)
        debug(f"listxattr({fpath}) => {listed}")
        for key in expected:
            if key not in listed:
                error(f"xattr key missing from listxattr result: {key}")
                return False

        for key, val in expected.items():
            got = getxattr_equals(
                os_getxattr,
                fpath,
                key,
                val,
                timeout_sec=5.0 if gfarm2fs else 0,
            )
            if got != val:
                error(
                    f"xattr mismatch for {key}: expected {val}, "
                    f"got {got}"
                )
                return False

        try:
            os_getxattr(fpath, "user.no_such_xattr")
            error("missing xattr get unexpectedly succeeded")
            return False
        except OSError as e:
            msg = format_os_error(e)
            expected_error(f"missing xattr get failed as expected: {msg}")

        try:
            os_setxattr(fpath, "user.test1", b"second", os.XATTR_CREATE)
            error("xattr create unexpectedly succeeded on existing key")
            return False
        except OSError as e:
            expected_error(
                f"xattr create failed as expected: {format_os_error(e)}"
            )
        except AttributeError:
            pass

        try:
            os_setxattr(
                fpath,
                "user.no_such_xattr",
                b"replace",
                os.XATTR_REPLACE,
            )
            error("xattr replace unexpectedly succeeded on missing key")
            return False
        except OSError as e:
            expected_error(
                f"xattr replace failed as expected: {format_os_error(e)}"
            )
        except AttributeError:
            pass

        for key in list(expected):
            os_removexattr(fpath, key)
            err = getxattr_missing(
                os_getxattr,
                fpath,
                key,
                timeout_sec=5.0 if gfarm2fs else 0,
            )
            if err is None:
                error("expected xattr missing check unexpectedly succeeded")
                return False
            if not gfarm2fs:
                expected_error("expected xattr missing: "
                               f"{format_os_error(err)}")

        os_setxattr(fpath, "user.test1", b"test_val1", 0)
        if getxattr_equals(
            os_getxattr,
            fpath,
            "user.test1",
            b"test_val1",
            timeout_sec=5.0 if gfarm2fs else 0,
        ) != b"test_val1":
            error("xattr rewrite value mismatch")
            return False

        try:
            os_setxattr(fpath, "user.test1", b"test_val1", os.XATTR_CREATE)
        except OSError as e:
            expected_error(
                f"expected xattr create failure: {format_os_error(e)}"
            )
        except AttributeError:
            pass
        else:
            error("xattr create unexpectedly succeeded")
            return False
        try:
            os_setxattr(fpath, "user.test1", b"replace", os.XATTR_REPLACE)
        except OSError as e:
            error(
                "xattr replace setxattr failed: "
                f"{format_os_error(e)}"
            )
            return False
        except AttributeError:
            pass
        else:
            if getxattr_equals(
                os_getxattr,
                fpath,
                "user.test1",
                b"replace",
                timeout_sec=5.0 if gfarm2fs else 0,
            ) != b"replace":
                error("xattr replace did not update value")
                return False

        info("xattr user.test1..user.test10 check passed")
        os.remove(fpath)
        return True
    except Exception as e:
        error(f"test_xattr exception: {format_os_error(e)}")
        error(traceback.format_exc().rstrip())
        if os.path.exists(fpath):
            os.remove(fpath)
        return False


def test_gfarm2fs_effective_perm(base_dir):
    """Test gfarm2fs effective_perm attribute."""
    fpath = os.path.join(base_dir, "gfarm_file")
    debug(f"test_gfarm2fs_effective_perm: fpath={fpath}")
    try:
        with open(fpath, 'w') as f:
            f.write("dummy")
        info(f"Created file for gfarm2fs check: {fpath}")

        key = "gfarm.effective_perm"
        os_getxattr = getattr(os, 'getxattr', None)
        if os_getxattr is None:
            debug("os.getxattr not supported on this system")
            return False

        for mode, expected in ((0o400, 4), (0o200, 2), (0o100, 1)):
            os.chmod(fpath, mode)
            val = os_getxattr(fpath, key)
            actual = val[0] if len(val) == 1 else None
            if actual != expected:
                error(
                    f"gfarm2fs {key} mismatch after chmod {mode:o}: "
                    f"expected={expected}, value={val}"
                )
                return False
            info(
                f"gfarm2fs {key} after chmod {mode:o}: "
                f"value={actual}"
            )
        return True
    except Exception as e:
        error(f"test_gfarm2fs_effective_perm exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def run_gfcksum_with_retry(fpath, retry_count=5, retry_interval=1.0):
    proc = None
    last_error = None
    for attempt in range(1, retry_count + 1):
        try:
            proc = subprocess.run(
                ["gfcksum", "-c", fpath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                check=True,
            )
            return proc
        except FileNotFoundError:
            raise
        except subprocess.CalledProcessError as e:
            last_error = e
            stderr = e.stderr.strip() if e.stderr else ""
            stdout = e.stdout.strip() if e.stdout else ""
            if stderr and stdout:
                msg = f"stdout={stdout} stderr={stderr}"
            elif stderr:
                msg = f"stderr={stderr}"
            elif stdout:
                msg = f"stdout={stdout}"
            else:
                msg = f"returncode={e.returncode}"
            if attempt < retry_count and "size differs" in msg:
                debug(
                    "gfcksum failed with size differs; "
                    f"retrying {attempt}/{retry_count}: {msg}"
                )
                time.sleep(retry_interval)
                continue
            raise subprocess.CalledProcessError(
                e.returncode, e.cmd, output=e.stdout, stderr=e.stderr
            ) from None

    if last_error is not None:
        raise subprocess.CalledProcessError(
            last_error.returncode,
            last_error.cmd,
            output=last_error.stdout,
            stderr=last_error.stderr,
        ) from None
    return proc


def test_gfarm2fs_cksum(base_dir):
    """Test gfarm2fs checksum xattr matches gfcksum output."""
    import errno
    fpath = os.path.join(base_dir, "gfarm_cksum_file")
    dpath = os.path.join(base_dir, "gfarm_cksum_dir")
    debug(f"test_gfarm2fs_cksum: fpath={fpath}, dpath={dpath}")
    try:
        with open(fpath, 'w') as f:
            f.write("checksum content\n")

        # close the previous write handle to encourage FUSE release
        with open(fpath, 'r') as f:
            f.read()

        os_getxattr = getattr(os, 'getxattr', None)
        if os_getxattr is None:
            debug("os.getxattr not supported on this system")
            return False

        if os.path.exists(dpath):
            rmtree_with_retry(dpath)
        os.mkdir(dpath)
        try:
            os_getxattr(dpath, "gfarm2fs.cksum")
            error(
                "getxattr for gfarm2fs.cksum on directory unexpectedly "
                "succeeded"
            )
            return False
        except OSError as e:
            if e.errno != errno.ENODATA:
                error(
                    "getxattr for gfarm2fs.cksum on directory failed with "
                    f"unexpected error: {format_os_error(e)} "
                    "(expected ENODATA)"
                )
                return False
            info(
                "getxattr for gfarm2fs.cksum on directory failed as expected: "
                f"{format_os_error(e)}"
            )
        finally:
            if os.path.exists(dpath):
                rmtree_with_retry(dpath)

        try:
            # fpath: the previous close may not have reached FUSE yet
            proc = run_gfcksum_with_retry(fpath)
        except FileNotFoundError:
            error("gfcksum not available")
            return False
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.strip() if e.stderr else ""
            stdout = e.stdout.strip() if e.stdout else ""
            if stderr and stdout:
                error(
                    "gfcksum failed: "
                    f"stdout={stdout} stderr={stderr}"
                )
            elif stderr:
                error(f"gfcksum failed: stderr={stderr}")
            elif stdout:
                error(f"gfcksum failed: stdout={stdout}")
            else:
                error(f"gfcksum failed: returncode={e.returncode}")
            return False

        cksum = os_getxattr(fpath, "gfarm2fs.cksum").decode()
        out = proc.stdout.strip()
        gfcksum_prefix = " ".join(out.split()[:3])
        info(f"gfarm2fs cksum={cksum}, gfcksum={gfcksum_prefix}")
        return cksum == gfcksum_prefix
    except Exception as e:
        error(f"test_gfarm2fs_cksum exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_gfarm2fs_local_xattr(base_dir):
    """Test gfarm2fs local read-only xattrs."""
    fpath = os.path.join(base_dir, "gfarm_local_xattr_file")
    debug(f"test_gfarm2fs_local_xattr: fpath={fpath}")
    try:
        with open(fpath, 'w') as f:
            f.write("dummy")

        os_getxattr = getattr(os, 'getxattr', None)
        os_setxattr = getattr(os, 'setxattr', None)
        os_removexattr = getattr(os, 'removexattr', None)
        os_listxattr = getattr(os, 'listxattr', None)
        if None in (os_getxattr, os_setxattr, os_removexattr):
            error("system xattr helpers not fully supported")
            return False
        if os_listxattr is None:
            error("os.listxattr not supported on this system")
            return False

        checks = {
            "gfarm2fs.path": lambda v: (
                v.endswith(os.path.basename(fpath).encode()) and
                b"regress_gfarm2fs_" in v
            ),
            "gfarm2fs.url": lambda v: v.startswith(b"gfarm://"),
            "gfarm2fs.metadb": lambda v: b":" in v,
            "gfarm2fs.version": lambda v: len(v) > 0,
            "gfarm2fs.gfarm_version": lambda v: len(v) > 0,
            "gfarm2fs.fuse_version": lambda v: len(v) > 0,
            "gfarm2fs.pid": lambda v: v.isdigit() and int(v) > 0,
            "gfarm2fs.exe": lambda v: v.startswith(b"/"),
            "gfarm2fs.gsipath": lambda v: len(v) > 0,
            "gfarm2fs.gsitimeleft": lambda v: len(v) > 0,
            "gfarm2fs.gsiproxyinfo": lambda v: len(v) > 0,
        }
        nodata_expected = (
            "gfarm2fs.gsipath",
            "gfarm2fs.gsitimeleft",
            "gfarm2fs.gsiproxyinfo",
        )

        nodata_errors = {errno.ENODATA}
        if hasattr(errno, "ENOATTR"):
            nodata_errors.add(errno.ENOATTR)

        for name, checker in checks.items():
            debug(f"xattr name={name}, " + str(name in nodata_expected))
            try:
                value = os_getxattr(fpath, name)
                if not checker(value):
                    error(f"unexpected value for {name}: {value!r}")
                    return False
            except OSError as e:
                if name in nodata_expected and e.errno in nodata_errors:
                    continue  # OK
                else:
                    raise

        # Expect no error
        os_setxattr(fpath, "gfarm2fs.path", b"overwrite")
        os_removexattr(fpath, "gfarm2fs.path")
        os_setxattr(fpath, "gfarm2fs.local_test", b"x")
        os_removexattr(fpath, "gfarm2fs.local_test")

        listed = os_listxattr(fpath)
        debug(f"listxattr({fpath}) => {listed}")
        for key in checks.keys():
            if key not in listed:
                error(f"missing xattr key: {key}")
                return False

        if "gfarm2fs.profile." in listed:
            error("profile prefix itself must not be listed")
            return False

        return True
    except Exception as e:
        error(f"test_gfarm2fs_local_xattr exception: {format_os_error(e)}")
        return False
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


def test_gfarm2fs_listxattr_profile(base_dir):
    """Test profile xattrs are listed at the mount root."""
    debug(f"test_gfarm2fs_listxattr_profile: base_dir={base_dir}")
    try:
        os_listxattr = getattr(os, 'listxattr', None)
        if os_listxattr is None:
            error("system xattr helpers not fully supported")
            return False

        mount_root = get_mount_point(base_dir)
        debug(f"resolved mount_root={mount_root}")
        listed = os_listxattr(mount_root)
        debug(f"listxattr({mount_root}) => {listed}")
        profile_keys = [
            name for name in listed
            if name.startswith("gfarm2fs.profile.")
        ]
        if len(profile_keys) < 2:
            error(f"too few profile xattrs: {profile_keys!r}")
            return False

        if "gfarm2fs.profile." in listed:
            error("profile prefix itself must not be listed")
            return False

        no_such_attribute = {errno.ENODATA}
        if hasattr(errno, "ENOATTR"):
            no_such_attribute.add(errno.ENOATTR)
        for name in profile_keys:
            try:
                value = os.getxattr(mount_root, name)
                debug(f"getxattr({mount_root}, {name}) => {value!r}")
            except OSError as e:
                if e.errno in no_such_attribute:
                    debug(f"getxattr({mount_root}, {name})"
                          " => No such attribute")
                    continue
                raise

        return True
    except Exception as e:
        error(
            f"test_gfarm2fs_listxattr_profile exception: {format_os_error(e)}"
        )
        return False


def run_single_run(run_id, base_dir, test_list,
                   stop_on_error=False, shuffle=False):
    """Run a single iteration of the test suite."""
    successes = 0
    failures = 0
    skips = 0
    interrupted = False
    stopped_on_error = False
    failed_test_names = []

    local_test_list = list(test_list)
    num_tests = len(test_list)

    if stop_event.is_set():
        interrupted = True
        skips = num_tests
        return successes, failures, skips, interrupted, failed_test_names

    thread_local.run_id = run_id

    unique_dir = tempfile.mkdtemp(prefix="regress_gfarm2fs_", dir=base_dir)
    register_active_dir(unique_dir)
    safe_print(f"Starting tests in: {unique_dir}")

    if shuffle:
        rng = random.Random()
        rng.shuffle(local_test_list)

    num_remain = num_tests
    try:
        for name, func in local_test_list:
            if stop_event.is_set():
                debug("Aborting tests due to stop_event being set.")
                break
            try:
                num_remain -= 1
                # return True/False/"SKIP"/"XFAIL"
                result = func(unique_dir)
                if result == SKIP:
                    safe_print(f"test {name} ... SKIP")
                    skips += 1
                elif result == XFAIL:
                    safe_print(f"test {name} ... XFAIL")
                    skips += 1
                elif result:
                    safe_print(f"test {name} ... PASS")
                    successes += 1
                else:
                    error(f"test_{name} returned False")
                    safe_print(f"test {name} ... FAIL")
                    failures += 1
                    failed_test_names.append(name)
                    register_failed_test(name)
                    if stop_on_error:
                        stopped_on_error = True
                        stop_event.set()
                        break
            except Exception as e:
                safe_print(f"test_{name} ... ERROR ({e})")
                failures += 1
                failed_test_names.append(name)
                register_failed_test(name)
                if stop_on_error:
                    stopped_on_error = True
                    stop_event.set()
                    break
    except KeyboardInterrupt:
        interrupted = True
        stop_event.set()
    finally:
        if stop_on_error and stopped_on_error and failures == 0:
            failures = 1
        skips += num_remain
        thread_id = get_thread_id()
        safe_print("")
        safe_print(
            f"Summary (ID{run_id}-T{thread_id}): "
            f"Total: {successes + failures}, "
            f"Success: {successes}, Failure: {failures}, "
            f"Skip: {skips}"
        )

        if os.path.exists(unique_dir):
            rmtree_with_retry(unique_dir)
        unregister_active_dir(unique_dir)

    return successes, failures, skips, interrupted, failed_test_names


def run_all_tests(base_dir, xattr=False, gfarm2fs=False, fuse=False,
                  stop_on_error=False,
                  loop=None, parallel=None, shuffle=False, tests=None,
                  gfarmized=False):
    """Run all defined tests.

    Supports parallel, loop, and shuffle options.
    """
    loop_val = loop if loop is not None else 1
    concurrency = parallel if parallel is not None else 1
    num_runs = loop_val * concurrency
    reset_failed_tests()

    total_successes = 0
    total_failures = 0
    total_skips = 0
    completed_runs = 0

    test_list = build_test_entries(
        xattr=xattr, gfarm2fs=gfarm2fs, fuse=fuse
    )
    if tests is not None:
        test_names = {name for name, _ in test_list}
        unknown = sorted(name for name in tests if name not in test_names)
        if unknown:
            raise ValueError(
                "Unknown test name(s): " + ", ".join(unknown)
            )
        test_list = [(name, func) for name, func in test_list
                     if name in tests]

    run_base_dir = base_dir
    if gfarmized and gfarm2fs:
        try:
            gfmd_host = get_gfmd_from_xattr(base_dir)
            debug(f"gfmd_host from gfarm2fs.metadb xattr: {gfmd_host}")
        except Exception as e:
            warn(f"gfarm2fs.metadb: {e}; trying gfmdhost -l")
            try:
                gfmd_host = get_gfmd_from_gfmdhost()
                debug(f"gfmd_host from gfmdhost -l: {gfmd_host}")
            except Exception as e:
                error(f"Could not determine gfmd host: {e}")
                sys.exit(1)

        mount_point = get_mount_point(base_dir)
        rel_path = os.path.relpath(base_dir, mount_point)
        run_base_dir = os.path.join(
            mount_point, ".gfarm", gfmd_host, rel_path
        )

    def print_summary(final=False):
        with print_lock:
            label = (
                "Final Aggregated Summary"
                if final
                else "Aggregated Summary"
            )
            sys.stdout.write(
                f"=== {label} "
                f"({completed_runs}/{num_runs} runs) ===\n"
            )
            sys.stdout.write(
                f"Total: {completed_runs}, "
                f"Success: {total_successes}, Failure: {total_failures}, "
                f"Skip: {total_skips}\n"
            )
            sys.stdout.flush()

    if concurrency > 1:
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=concurrency
        )
        try:
            futures = [
                executor.submit(
                    run_single_run,
                    run_id=i + 1,
                    base_dir=run_base_dir,
                    test_list=test_list,
                    stop_on_error=stop_on_error,
                    shuffle=shuffle,
                )
                for i in range(num_runs)
            ]
            processed_futures = set()
            try:
                for future in concurrent.futures.as_completed(futures):
                    try:
                        s, f, sk, run_interrupted, run_failed_tests = (
                            future.result()
                        )
                        total_successes += s
                        total_failures += f
                        total_skips += sk
                        completed_runs += 1
                        processed_futures.add(future)
                        print_summary()
                        if run_interrupted:
                            stop_event.set()
                    except Exception as e:
                        safe_print(f"[ERROR] Run failed with exception: {e}")
                        total_failures += 1
                        completed_runs += 1
                        processed_futures.add(future)
                        print_summary()
                        if stop_on_error:
                            stop_event.set()
            except KeyboardInterrupt:
                stop_event.set()
                executor.shutdown(wait=True)
                for future in futures:
                    if future in processed_futures:
                        continue
                    try:
                        s, f, sk, run_interrupted, run_failed_tests = (
                            future.result()
                        )
                        total_successes += s
                        total_failures += f
                        total_skips += sk
                        completed_runs += 1
                    except Exception as e:
                        safe_print(f"[ERROR] Run failed with exception: {e}")
                        total_failures += 1
                        completed_runs += 1
        finally:
            executor.shutdown(wait=True)
    else:
        try:
            for i in range(num_runs):
                s, f, sk, run_interrupted, run_failed_tests = run_single_run(
                    run_id=i + 1,
                    base_dir=run_base_dir,
                    test_list=test_list,
                    stop_on_error=stop_on_error,
                    shuffle=shuffle,
                )
                total_successes += s
                total_failures += f
                total_skips += sk
                completed_runs += 1
                print_summary()
                if run_interrupted or stop_event.is_set():
                    break
        except KeyboardInterrupt:
            stop_event.set()

    print_summary(final=True)
    failed_test_names = get_failed_tests()
    if failed_test_names:
        with print_lock:
            sys.stdout.write(
                "Failed tests: " + ", ".join(failed_test_names) + "\n"
            )
            sys.stdout.flush()
    if total_failures > 0:
        sys.exit(1)


class TerminalWidthFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        terminal_width = shutil.get_terminal_size(fallback=(80, 24)).columns
        max_width = max(40, terminal_width - 2)
        super().__init__(prog, width=max_width)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=TerminalWidthFormatter)
    parser.add_argument("target_dir", help="Target directory")
    parser.add_argument(
        "--xattr",
        action="store_true",
        help="Run xattr tests",
    )
    parser.add_argument(
        "--gfarm2fs",
        action="store_true",
        help="Run gfarm2fs tests",
    )
    parser.add_argument(
        "--fuse",
        action="store_true",
        help="Run tests for a FUSE implementation",
    )
    parser.add_argument("--gfarmized", action="store_true",
                        help="Run tests using the .gfarm/<gfmd_host> "
                        "mechanism relative to the mount point")
    parser.add_argument(
        "--loglevel",
        type=str,
        choices=["DEBUG", "INFO", "WARNING"],
        help="Set log level explicitly",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Set log level to DEBUG",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Set log level to INFO",
    )
    parser.add_argument(
        "--warning",
        action="store_true",
        help="Set log level to WARNING",
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop on the first test failure",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        help="Run tests in parallel with the specified number of threads",
    )
    parser.add_argument(
        "--loop",
        type=int,
        help="Number of times to loop the test suite",
    )
    parser.add_argument(
        "--shuffle",
        action="store_true",
        help="Shuffle the order of tests",
    )
    parser.add_argument(
        "--tests",
        nargs="?",
        const="",
        type=str,
        help=(
            "Comma-separated list of test names to run, "
            "e.g. symlink,hardlink"
        ),
    )
    args = parser.parse_args()

    if not os.path.isdir(args.target_dir):
        error(f"{args.target_dir} is not a directory.")
        sys.exit(1)

    selected_levels = [
        args.loglevel is not None,
        args.debug,
        args.info,
        args.warning,
    ]
    if sum(1 for selected in selected_levels if selected) > 1:
        error(
            "choose at most one of --loglevel, --debug, "
            "--info, or --warning."
        )
        sys.exit(1)

    if args.loglevel is not None:
        LOG_LEVEL = args.loglevel
    elif args.debug:
        LOG_LEVEL = "DEBUG"
    elif args.info:
        LOG_LEVEL = "INFO"
    elif args.warning:
        LOG_LEVEL = "WARNING"

    if args.parallel is not None and args.parallel <= 0:
        error("--parallel must be a positive integer.")
        sys.exit(1)

    if args.loop is not None and args.loop <= 0:
        error("--loop must be a positive integer.")
        sys.exit(1)

    tests = parse_test_filter(args.tests)
    if tests == set():
        parser.print_usage()
        error("--tests must contain at least one test name.")
        print("Available tests: " + ", ".join(list_test_names()))
        sys.exit(1)

    try:
        if args.gfarm2fs:
            print_gfarm2fs_versions(args.target_dir)
        run_all_tests(
            args.target_dir,
            xattr=args.xattr,
            gfarm2fs=args.gfarm2fs,
            fuse=args.fuse or args.gfarm2fs,
            stop_on_error=args.stop_on_error,
            loop=args.loop,
            parallel=args.parallel,
            shuffle=args.shuffle,
            tests=tests,
            gfarmized=args.gfarmized,
        )
    except KeyboardInterrupt:
        pass
    finally:
        cleanup_all_test_dirs()
        if INTERRUPTED_BY_SIGNAL:
            with print_lock:
                sys.stdout.write("Interrupted; temporary files cleaned up.\n")
                sys.stdout.flush()
