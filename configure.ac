#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([gfarm2fs],[1.2.21])
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
AC_SEARCH_LIBS([fuse_opt_parse], [fuse refuse],, [AC_MSG_ERROR([libfuse not found])])

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
