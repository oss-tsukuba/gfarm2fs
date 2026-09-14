#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([gfarm2fs],[3.0.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([gfarm2fs.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile contrib/Makefile contrib/mount.gfarm2fs/Makefile contrib/mount.gfarm2fs/mount.gfarm2fs contrib/gfarm2fs-exec/Makefile contrib/gfarm2fs-proxy-info/Makefile systest/Makefile systest/testcases/Makefile systest/scenarios/Makefile systest/common_scripts/Makefile systest/plugins/Makefile])
AC_CONFIG_MACRO_DIR([m4])
AC_SYS_LARGEFILE

# Checks for programs.
AC_PROG_CC
LT_INIT
AX_PTHREAD

### --with-gfarm=GFARM_ROOT
AC_ARG_WITH([gfarm],
  AS_HELP_STRING([--with-gfarm=GFARM_ROOT],[Gfarm root directory [[/usr]]]))
case x$with_gfarm in
  x|xyes|xno) ;;
  *) PKG_CONFIG_PATH="$PKG_CONFIG_PATH:$with_gfarm/lib/pkgconfig"
     export PKG_CONFIG_PATH ;;
esac
PKG_CHECK_MODULES([gfarm], [gfarm])

### --with-private-srcdir
### This is provided to replace some functionalities with your private code.
AC_MSG_CHECKING([for private source directory])
AC_ARG_WITH([private_srcdir],
  AS_HELP_STRING([--with-private-srcdir=DIR],[private source directory]))
case x$with_private_srcdir in
x|xno)
  top_private_dir=""
  private_srcs=""
  AC_MSG_RESULT([no]) ;;
*)
  if test -d "${with_private_srcdir}"; then
    top_private_dir="`(cd ${with_private_srcdir}; /bin/pwd)`"
    private_srcs="replicate_private.c private_gfarm2fs_msg_enums.h"
    AC_MSG_RESULT([${top_private_dir}])
    AC_DEFINE(HAVE_PRIVATE_SRCS, [1], [Define to 1 if you have private sources])
  else
    AC_MSG_ERROR([${with_private_srcdir} is not a directory.])
  fi
esac
AC_SUBST(top_private_dir)
AC_SUBST(private_srcs)

### --disable-xattr
AC_ARG_ENABLE(xattr,
  AS_HELP_STRING([--disable-xattr], [disable extended attribute]), [], [enable_xattr=yes])
if test "x$enable_xattr" != xno; then
  AC_DEFINE(ENABLE_XATTR, [1], [support extended attribute])
fi

### --disable-acl
AC_ARG_ENABLE(acl,
  AS_HELP_STRING([--disable-acl], [disable extended ACL]), [], [enable_acl=yes])
if test "x$enable_acl" != xno; then
  if test "x$enable_xattr" = xno; then
    AC_MSG_ERROR([extended ACL requires extended attribute.  specify --disable-acl])
  fi
  AC_DEFINE(ENABLE_ACL, [1], [support extended ACL])
fi

# Checks for header files.
#AC_CHECK_HEADERS([gfarm/gfarm.h],, [AC_MSG_ERROR([gfarm/gfarm.h not found])])
# fuse.h requres _FILE_OFFSET_BITS is defined in any case, but
# AC_SYS_LARGEFILE does not define it on a 64bit platform like x86_64
# since it is not necessary.  To avoid this problem we just skip the check.
#AC_CHECK_HEADERS([fuse.h],, [AC_MSG_ERROR([fuse.h not found])])
AC_CHECK_HEADERS(sys/xattr.h,,
if test "x$enable_xattr" != xno; then
  AC_MSG_ERROR([sys/xattr.h not found.  specify --disable-xattr])
fi)
AC_CHECK_HEADERS(sys/acl.h,,
if test "x$enable_acl" != xno; then
  AC_MSG_ERROR([sys/acl.h not found.  specify --disable-acl])
fi)

# Checks for libraries.
AC_ARG_WITH([fuse2],
  [AS_HELP_STRING([--with-fuse2], [use FUSE 2.x @<:@default=check@:>@])],
  [with_fuse2=$withval],
  [with_fuse2=check])

AC_ARG_WITH([fuse3],
  [AS_HELP_STRING([--with-fuse3], [use FUSE 3.x @<:@default=check@:>@])],
  [with_fuse3=$withval],
  [with_fuse3=check])

if test "x$with_fuse2" = "xyes" && test "x$with_fuse3" = "xyes"; then
  AC_MSG_ERROR([cannot specify both --with-fuse2 and --with-fuse3])
fi
if test "x$with_fuse2" = "xno" && test "x$with_fuse3" = "xno"; then
  AC_MSG_ERROR([cannot disable both FUSE2 and FUSE3])
fi

use_fuse3=no
use_fuse2=no

if test "x$with_fuse3" != "xno" && test "x$with_fuse2" != "xyes"; then
  PKG_CHECK_MODULES([FUSE3], [fuse3], [
    use_fuse3=yes
  ], [
    if test "x$with_fuse3" = "xyes"; then
      AC_MSG_ERROR([FUSE3 not found])
    fi
  ])
fi

if test "x$use_fuse3" = "xyes"; then
  AC_DEFINE([HAVE_FUSE3], [1], [Define to 1 if you have FUSE3])
  CFLAGS="$CFLAGS $FUSE3_CFLAGS"
  LIBS="$LIBS $FUSE3_LIBS"
else
  if test "x$with_fuse2" = "xno"; then
    AC_MSG_ERROR([FUSE3 not found and FUSE2 is disabled])
  fi
  AC_MSG_NOTICE([checking for library containing fuse_opt_parse (FUSE2)])
  AC_SEARCH_LIBS([fuse_opt_parse], [fuse refuse], [
    use_fuse2=yes
  ], [
    if test "x$with_fuse2" = "xyes" || test "x$with_fuse3" = "xno"; then
      AC_MSG_ERROR([FUSE2 not found])
    else
      AC_MSG_ERROR([neither FUSE3 nor FUSE2 found; FUSE3 is preferred. Install FUSE3 development files, or specify --with-fuse2 to use FUSE2])
    fi
  ])
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_MEMBERS([struct stat.st_mtim.tv_nsec])

# Checks for library functions.
save_libs=$LIBS
LIBS=$gfarm_LIBS
AC_CHECK_FUNCS(gfs_replicate_file_to gfarm_schedule_cache_dump gfs_getxattr_cached gfarm_xattr_caching gfarm_xattr_caching_pattern_add gfs_lchown gfs_lutimes gfarm_version gfs_stat_cksum gfarm_config_profile_value gfs_profile_lock)
LIBS=$save_libs

AC_RUN_IFELSE([AC_LANG_SOURCE([[
#  define _FILE_OFFSET_BITS 64
#  include <fuse.h>

  void *data_save;

  int opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
  {
	  data_save = data;
  }

  int
  main(int argc, char **argv)
  {
	  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	  int data;
	  fuse_opt_parse(&args, &data, NULL, opt_proc);
	  if (data_save == &data)
		  return 1;
	  return 0; /* have a bug on NetBSD */
  }
  ]])],[AC_DEFINE(HAVE_BUG_OF_FUSE_OPT_PARSE_ON_NETBSD)],[
],[])

AH_BOTTOM([
/* fuse_opt_parse() doesn't correctly pass 2nd arg on NetBSD-5.1 and before */
#undef HAVE_BUG_OF_FUSE_OPT_PARSE_ON_NETBSD
])

AC_OUTPUT
