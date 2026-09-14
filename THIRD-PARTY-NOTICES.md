# Third-Party Notices

This file lists third-party software and generated files distributed with
gfarm2fs.  The copyright and license notices included in each file are the
authoritative license notices.

## GNU Autotools and Libtool files

The following build-system files are generated or distributed by GNU
Autoconf, Automake, and Libtool, and contain their corresponding copyright
and license notices:

```text
aclocal.m4
config.h.in
compile
config.guess
config.sub
depcomp
install-sh
ltmain.sh
missing
m4/ax_pthread.m4
m4/libtool.m4
m4/ltoptions.m4
m4/ltsugar.m4
m4/ltversion.m4
m4/lt~obsolete.m4
Makefile.in
contrib/Makefile.in
contrib/gfarm2fs-exec/Makefile.in
contrib/gfarm2fs-proxy-info/Makefile.in
contrib/mount.gfarm2fs/Makefile.in
systest/Makefile.in
systest/common_scripts/Makefile.in
systest/plugins/Makefile.in
systest/scenarios/Makefile.in
systest/testcases/Makefile.in
```

These files are build tools or generated build-system support files; they are
not part of the gfarm2fs runtime implementation.  Refer to the notices in
the individual files for the applicable GPL terms and any exceptions.

## libfuse example used by regression tests

`regress/test-fuse-passthrough_fh.sh` downloads the following libfuse example
from the libfuse repository when the regression test is run:

```text
regress/passthrough_fh.c
regress/passthrough_helpers.h
```

These files are not part of the gfarm2fs source distribution and are ignored
by Git.  If they are included in a delivery, their copyright and GPL notices
from libfuse must be included and the applicable libfuse license terms must be
observed.
