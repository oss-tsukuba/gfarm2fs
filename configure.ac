#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([gfarm2fs], [0.9])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_MAINTAINER_MODE
AC_CONFIG_SRCDIR([gfarm2fs.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])
AC_SYS_LARGEFILE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([gfarm], [gfarm_initialize],, [AC_MSG_ERROR([libgfarm not found])])
AC_CHECK_LIB([fuse], [fuse_main],, [AC_MSG_ERROR([libfuse not found])])

# Checks for header files.
AC_CHECK_HEADERS([gfarm/gfarm.h],, [AC_MSG_ERROR([gfarm/gfarm.h not found])])
AC_CHECK_HEADERS([fuse.h],, [AC_MSG_ERROR([fuse.h not found])])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT
