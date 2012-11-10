#!/bin/sh
#
# $Id$

USAGE() {
cat <<EOF
wrapper script to execute a program in Gfarm file system using GfarmFS-FUSE

Usage:
    gfarm2fs-exec.sh [OPTIONS] prog arg ...
    or
    GFS_PROG=prog GFS_ARGS="arg ..." gfarm2fs-exec.sh

Environment variable:

    GFS_USERNAME  global user name in Gfarm
    GFS_MOUNTDIR  mount point            (defaut: /tmp/\$GFS_USERNAME/\$\$)
    GFS_WDIR      working directory relative to the home directory
                  in Gfarm file system                      (default: .)
    GFS_STDOUT    Filename for the standard output  (default: STDOUT.\$\$)
    GFS_STDERR    Filename for the standard error   (default: STDERR.\$\$)

Options:
    -u username
    -m mountdir
    -wdir working_directory_from_home
    -stdout filename
    -stderr filename
EOF
	exit 1
}

ABORT() {
	[ $# -gt 0 ] && echo 1>&2 $*
	exit 1
}

PARSE_ARG() {
	while [ $# -gt 0 ]; do
		case $1 in
		-u)    shift; GFS_USERNAME=$1 ;;
		-m)    shift; GFS_MOUNTDIR=$1 ;;
		-wdir) shift; GFS_WDIR=$1 ;;
		-stdout) shift; GFS_STDOUT=$1 ;;
		-stderr) shift; GFS_STDERR=$1 ;;
		-*) USAGE ;;
		*) break ;;
		esac
		shift
	done
	[ $# -lt 1 ] && USAGE
	GFS_PROG=$1
	shift
	GFS_ARGS=$*
}

UMOUNT_FUSE()
{
	MNTDIR=$1
	retry=10
	i=0
	while true; do
		fusermount -u $MNTDIR > /dev/null 2>&1
		if [ $? -eq 0 ]; then
			return 0
		fi
		ls -l $MNTDIR > /dev/null 2>&1
		if [ $i -ge $retry ]; then
			return 1
		fi
		i=`expr $i + 1`
	done
}

if [ X"$GFS_PROG" = X ]; then
	PARSE_ARG $*
fi
: ${GFS_USERNAME:=`gfwhoami 2> /dev/null`}
: ${GFS_USERNAME:=$USER}
: ${GFS_USERNAME:=$LOGNAME}
: ${GFS_USERNAME:=`logname 2> /dev/null`}
: ${GFS_MOUNTDIR:=/tmp/$GFS_USERNAME/$$}
: ${GFARMFS_ROOT:=`gfuser -l $GFS_USERNAME 2> /dev/null | awk -F: '{ print $3 }'`}
: ${GFARMFS_ROOT:=/}
: ${GFARMFS_OPTIONS:=}
: ${FUSE_OPTIONS:=}
: ${GFS_WDIR:=.}
: ${GFS_STDOUT:=STDOUT.$$}
: ${GFS_STDERR:=STDERR.$$}

DELETE_MOUNTDIR=0
if [ ! -d $GFS_MOUNTDIR ]; then
	mkdir -p $GFS_MOUNTDIR ||
		ABORT "cannot create a mount point: " $GFS_MOUNTDIR
	DELETE_MOUNTDIR=1
fi
[ -O $GFS_MOUNTDIR ] || ABORT "$GFS_MOUNTDIR: not owned by " $LOGNAME

cd /
# mount Gfarm file system
if ! grep $GFS_MOUNTDIR /etc/mtab > /dev/null; then
	gfarm2fs -o modules=subdir,subdir=$GFARMFS_ROOT $GFARMFS_OPTIONS $GFS_MOUNTDIR $FUSE_OPTIONS || :
fi
# change directory and execute $GFS_PROG with $GFS_ARGS
cd $GFS_MOUNTDIR && cd $GFS_WDIR &&
	$GFS_PROG $GFS_ARGS > $GFS_STDOUT 2> $GFS_STDERR
STATUS=$?
cd /
sleep 1
# unmount Gfarm file system
if grep $GFS_MOUNTDIR /etc/mtab > /dev/null; then
	UMOUNT_FUSE $GFS_MOUNTDIR
fi
[ $DELETE_MOUNTDIR = 1 ] && rmdir $GFS_MOUNTDIR

exit $STATUS
