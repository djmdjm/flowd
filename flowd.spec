%define ver 0.4
%define rel 1fc2

# Python < 2.3 (e.g. Redhat 9) doesn't have everything we need, so it may be
# necessary to turn off the python package on older systems
%define python_pkg 1

Summary: The flowd NetFlow collector daemon
Name: flowd
Version: %{ver}
Release: %{rel}
URL: http://www.mindrot.org/flowd.html
Source0: http://www.mindrot.org/files/flowd/flowd-%{ver}.tar.gz
License: BSD
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot
PreReq: initscripts
BuildPreReq: byacc
BuildPreReq: glibc-devel
BuildRequires: %{__python}

%package perl
Summary: Perl API to access flowd logfiles
Group: Applications/Internet
Requires: perl

%if %{python_pkg}
%package python
Summary: Python API to access flowd logfiles
Group: Applications/Internet
Requires: python
%endif

%description
This is flowd, a NetFlow collector daemon intended to be small, fast and secure.

It features some basic filtering to limit or tag the flows that are recorded
and is privilege separated, to limit security exposure from bugs in flowd 
itself.

%description perl
This is a Perl API to the binary flowd network flow log format and an example
reader application

%if %{python_pkg}
%description python
This is a Python API to the binary flowd network flow log format and an 
example reader application
%endif

%prep

%setup

%build
%configure --enable-gcc-warnings

make
./setup.py build

%install
rm -rf $RPM_BUILD_ROOT

%makeinstall

# Misc stuff
install -d $RPM_BUILD_ROOT/var/empty
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 flowd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/flowd

# Perl module
install -d $RPM_BUILD_ROOT/%{perl_sitearch}/
install -m755 Flowd.pm $RPM_BUILD_ROOT/%{perl_sitearch}/

# Python module
%if %{python_pkg}
./setup.py install --optimize 1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
sed -e 's|/[^/]*$||' INSTALLED_FILES | grep "site-packages/" | \
    sort -u | awk '{ print "%attr(755,root,root) %dir " $1}' > INSTALLED_DIRS
cat INSTALLED_FILES INSTALLED_DIRS > INSTALLED_OBJECTS
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%pre
%{_sbindir}/groupadd -r _flowd 2>/dev/null || :
%{_sbindir}/useradd -d /var/empty -s /bin/false -g _flowd -M -r _flowd \
	2>/dev/null || :

%post
/sbin/chkconfig --add flowd

%postun
/sbin/service flowd condrestart > /dev/null 2>&1 || :

%preun
if [ "$1" = 0 ]
then
	/sbin/service flowd stop > /dev/null 2>&1 || :
	/sbin/chkconfig --del flowd
fi

%files
%defattr(-,root,root)
%doc ChangeLog LICENSE README TODO
%dir %attr(0111,root,root) %{_var}/empty
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/flowd.conf
%attr(0644,root,root) %{_mandir}/man5/flowd.conf.5*
%attr(0644,root,root) %{_mandir}/man8/flowd.8*
%attr(0644,root,root) %{_mandir}/man8/flowd-reader.8*
%attr(0755,root,root) %{_bindir}/flowd-reader
%attr(0755,root,root) %config /etc/rc.d/init.d/flowd
%attr(0755,root,root) %{_sbindir}/flowd

%files perl
%defattr(-,root,root)
%doc reader.pl
%attr(0644,root,root) %{perl_sitearch}/Flowd.pm

%if %{python_pkg}
%files python -f INSTALLED_OBJECTS
%defattr(-,root,root)
%doc reader.py
%endif

%changelog
* Mon Aug 16 2004 Damien Miller <djm@mindrot.org>
- Make Python package optional, Redhat 9 doesn't have support for
  socket.inet_ntop, which flowd.py needs

* Fri Aug 13 2004 Damien Miller <djm@mindrot.org>
- Subpackages for perl and python modules

* Tue Aug 03 2004 Damien Miller <djm@mindrot.org>
- Initial RPM spec

