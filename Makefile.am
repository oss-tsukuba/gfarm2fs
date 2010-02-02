bin_PROGRAMS = gfarm2fs
gfarm2fs_SOURCES = gfarm2fs.c replicate.c

AM_CFLAGS = -Wall

EXTRA_DIST = RELNOTES LICENSE gfarm2fs.spec

#
# gflog message number assignment
#

msgno: assign_msgno

ASSIGNMSGNO=$(top_srcdir)/msgno/assign_msgno.pl

assign_msgno:
	GFARM_TOPDIR=$(top_srcdir) $(ASSIGNMSGNO) $(gfarm2fs_SOURCES)
