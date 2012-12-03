bin_PROGRAMS = gfarm2fs gfarm2fs_fix_acl
gfarm2fs_SOURCES = gfarm2fs.c acl.c id.c replicate.c open_file.c xattr.c \
	gfarm_config.c \
	gfarm2fs.h acl.h id.h replicate.h open_file.h gfarm2fs_msg_enums.h \
	hash.h xattr.h gfarm_config.h
gfarm2fs_fix_acl_SOURCES = gfarm2fs_fix_acl.c \
	acl.c id.c xattr.c gfarm_config.c \
	acl.h id.h xattr.h gfarm_config.h gfarm2fs.h
dist_bin_SCRIPTS = gfarm2fs_fix_acl.sh
man_MANS = gfarm2fs.1
EXTRA_DIST = RELNOTES LICENSE gfarm2fs.spec $(man_MANS) $(private_srcs)
SUBDIRS = contrib
AM_CFLAGS = -Wall
ACLOCAL_AMFLAGS = -I m4

#
# gflog message number assignment
#
msgno: assign_msgno

ASSIGNMSGNO=$(top_srcdir)/msgno/assign_msgno.pl

assign_msgno:
	GFARM_TOPDIR=$(top_srcdir) $(ASSIGNMSGNO) $(gfarm2fs_SOURCES)

#
# private sources
#
private-src-link:
	@if test "x$(top_private_dir)" != "x"; then \
		for i in $(private_srcs); do \
			if test ! -r ./$${i} -a \
			-r $(top_private_dir)/$${i}; then \
				ln -s $(top_private_dir)/$${i} . ; \
			fi ; \
		done ; \
	fi

private-src-unlink:
	@if test "x$(top_private_dir)" != "x"; then \
		for i in $(private_srcs); do \
			if test -L ./$${i}; then \
				$(RM) ./$${i} ; \
			fi ; \
		done ; \
	fi

install-private: $(bin_PROGRAMS)
	if test "x$(top_private_dir)" != "x"; then \
		for i in $(bin_PROGRAMS); do \
			$(binPROGRAMS_INSTALL) $$i \
			$(DESTDIR)$(bindir)/$${i}_private ; \
		done ; \
	fi

gfarm2fs.c: private-src-link
distclean-local: private-src-unlink
