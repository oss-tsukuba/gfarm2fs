Summary: GfarmFS-FUSE for Gfarm File System 2
Name: gfarm2fs
Version: 1.2.1
Release: 1%{?dist}
License: BSD
Group: Applications/Internet
URL: http://sourceforge.net/projects/gfarm/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: fuse-devel, gfarm-devel >= 2.3.2
Requires: fuse, gfarm-libs >= 2.3.2

%description
GfarmFS-FUSE (gfarm2fs) enables to mount a Gfarm file system by using
FUSE (http://fuse.sourceforge.net/).

%prep
%setup -q

%build
%configure
make

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_bindir}
%doc RELNOTES
%doc LICENSE


%changelog
* Wed Nov 28 2007 Osamu Tatebe <tatebe@cs.tsukuba.ac.jp> 1.0.0-1
- Initial build.
