# gfarm2fs

gfarm2fs mounts a Gfarm file system through FUSE so that it can be accessed
as a local file system.

## Requirements

- Gfarm File System 2.4.2 or later
- FUSE version 3 (Filesystem in Userspace)
- libacl to enable extended ACL support

### Packages

On RPM-based systems, install:

- `gfarm-devel` or `gfarm-gsi-devel`
- `fuse3`
- `fuse3-devel`
- `libacl-devel`    # required for extended ACL support

On Debian-based systems, install:

- `libgfarm-dev`
- `fuse3`
- `libfuse3-dev`
- `libacl1-dev`    # required for extended ACL support

## Build and install

```sh
./configure [options]
make
sudo make install
```

The default Gfarm installation directory is `/usr`. The default installation
prefix for gfarm2fs is `/usr/local`.

To specify these directories explicitly:

```sh
./configure --with-gfarm=/path/to/gfarm --prefix=/path/to/install
```

`--with-gfarm` specifies the installation directory of Gfarm. `--prefix`
specifies where gfarm2fs is installed.

If a specific C compiler is required, set `CC` when running `configure`:

```sh
env CC=gcc ./configure [options]
```

Run `./configure --help` to see all available configuration options.

## Mounting a Gfarm file system

Before mounting, prepare valid Gfarm authentication credentials according to
your environment. Depending on the configured authentication method, this
may include initializing a session with `gfkey`, `jwt-agent`, or
`grid-proxy-init` (these commands are examples and are not all required).

For example, create a mount point and pass it to `gfarm2fs`:

```sh
sudo mkdir -p /mnt/gfarm/user1
sudo chown user1:user1 /mnt/gfarm/user1
gfarm2fs /mnt/gfarm/user1
```

The Gfarm configuration used by the client can be selected with the
`GFARM_CONFIG_FILE` environment variable:

```sh
env GFARM_CONFIG_FILE=/path/to/gfarm2.conf gfarm2fs /mnt/gfarm/user1
```

Use `gfarm2fs -h` for command-line and FUSE options, and `gfarm2fs -V` to
display the version.

Unmount the file system with the FUSE unmount command provided by the host,
for example:

```sh
fusermount3 -u /mnt/gfarm/user1
```

or

```sh
fusermount -u /mnt/gfarm/user1
```

## Limitations

- Deleting a directory and all of its contents while any file in it is
  open is not supported.
- The `access(2)` system call is not supported.
- The `mknod(2)` system call is supported only for regular files; FIFO and
  device files are not supported.

## Extended attributes and ACLs

Extended ACL support is enabled when the required ACL development library is
available at build time. Gfarm extended attributes can be accessed through
the Gfarm tools and, when supported by the build and mounted file system,
through standard file-system extended-attribute interfaces.

To display all extended attributes attached to a file or mount point,
use `getfattr` with `-m .`:

```sh
getfattr -d -m . /mnt/gfarm/user1/path/to/file_or_dir
```

## Security considerations

When untrusted users are registered in the `gfarmroot` group or
`gfarm_root.{user,group}` extended attributes of any files or
directories, a Security Hole exists on the mount point of gfarm2fs with
`-o suid,allow_other` option executed by root (even if either `-o ro`
option or `-o default_permissions` option is also specified).
Therefore both `-o suid,allow_other` option and `gfarm_root.{user,group}`
extended attributes should not be used.

## Related documentation

- `gfarm2fs(1)` — command reference
- `gfarm2.conf(5)` — Gfarm client configuration
- `gfarm_attr(5)` — Gfarm extended attributes
