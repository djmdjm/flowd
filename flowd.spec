%define ver 0.2
%define rel 1fc2

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

%description
This is flowd, a NetFlow collector daemon intended to be small, fast and secure.

It features some basic filtering to limit or tag the flows that are recorded
and is privilege separated, to limit security exposure from bugs in flowd 
itself.

%prep

%setup

%build

%configure --enable-gcc-warnings

make

%install
rm -rf $RPM_BUILD_ROOT

%makeinstall

install -d $RPM_BUILD_ROOT/var/empty
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 flowd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/flowd

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

%changelog
* Tue Aug 03 2004 Damien Miller <djm@mindrot.org>
- Initial RPM spec

