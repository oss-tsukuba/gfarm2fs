Summary: GfarmFS-FUSE for Gfarm File System 2
Name: gfarm2fs
Version: 1.2.15
Release: 1%{?dist}
License: BSD
Group: Applications/Internet
URL: http://sourceforge.net/projects/gfarm/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: fuse-devel, gfarm-devel >= 2.4.1
Requires: fuse, gfarm-libs >= 2.4.1

%description
GfarmFS-FUSE (gfarm2fs) enables to mount a Gfarm file system by using
FUSE (http://fuse.sourceforge.net/).

%prep
%setup -q

%build
%configure ${GFARM2FS_CONFIGURE_OPTION}
make

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_bindir}/gfarm2fs
%{_bindir}/gfarm2fs_fix_acl
%{_bindir}/gfarm2fs_fix_acl.sh
%{_bindir}/gfarm2fs-exec.sh
%{_bindir}/gfarm2fs-proxy-info
%{_bindir}/mount.gfarm2fs
%{_bindir}/mount.hpci
%{_bindir}/umount.gfarm2fs
%{_bindir}/umount.hpci
%doc RELNOTES
%doc LICENSE
%doc %{_mandir}
%{_datadir}/gfarm/gfservice
%{_datadir}/gfarm/systest

%changelog
* Mon Apr 22 2013 Osamu Tatebe <tatebe@cs.tsukuba.ac.jp> 1.2.9-1
- atomic append (O_APPEND) support
- automount(8) support

* Tue Jan 15 2013 Osamu Tatebe <tatebe@cs.tsukuba.ac.jp> 1.2.8.1-1
- %{_datadir}/gfarm/{gfservice,systest} are included
- update mount.hpci to mount /gfarm/GROUP/localaccount

* Mon Sep  3 2012 Osamu Tatebe <tatebe@cs.tsukuba.ac.jp> 1.2.7-1
- support file overwrite under no file replica
- support ubuntu 11.10 or later

* Mon Dec 19 2011 Osamu Tatebe <tatebe@cs.tsukuba.ac.jp> 1.2.5-1
- fix symlink problem

* Sat Apr 23 2011 Osamu Tatebe <tatebe@cs.tsukuba.ac.jp> 1.2.3-1
- extended ACL support

* Fri Mar  4 2011 Osamu Tatebe <tatebe@cs.tsukuba.ac.jp> 1.2.2-2
- configure option can be specified by GFARM2FS_CONFIGURE_OPTION
- install manual page

* Wed Nov 28 2007 Osamu Tatebe <tatebe@cs.tsukuba.ac.jp> 1.0.0-1
- Initial build.
