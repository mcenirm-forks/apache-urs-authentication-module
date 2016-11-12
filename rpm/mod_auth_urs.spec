Name:           mod_auth_urs
Version:        0.1
Release:        20150427git1505c09.1%{?dist}
Summary:        EOSDIS User Registration System module for Apache httpd

Group:          System Environment/Daemons
License:        Apache
URL:            https://git.earthdata.nasa.gov/projects/AAM/repos/apache-urs-authentication-module/browse
Source0:        LICENSE
Source1:        mod_auth_urs.h
Source2:        mod_auth_urs.c
Source3:        mod_auth_urs_cfg.c
Source4:        mod_auth_urs_session.c
Source5:        mod_auth_urs_ssl.c
Source6:        mod_auth_urs_http.c
Source7:        mod_auth_urs_json.c
Source8:        README

BuildRequires:  httpd-devel openssl-devel
Requires:       httpd-mmn = %(cat %{_includedir}/httpd/.mmn || echo missing)

%description
The Apache User Registration Service authentication module is
a drop-in module for Apache httpd version 2.2. It can be used
to provide URS authentication control for one or more
independent resources being served by an Apache httpd server.
Driven entirely by configuration under your control, it can
be used to protect files, directories, or even entire
applications, without requiring any change to the underlying
resource.


%prep
cp -p %{SOURCE0} %{SOURCE1} %{SOURCE2} %{SOURCE3} \
  %{SOURCE4} %{SOURCE5} %{SOURCE6} %{SOURCE7} %{SOURCE8} \
  .


%build
apxs -c -n %{name} mod_auth_urs.c mod_auth_urs_cfg.c \
  mod_auth_urs_session.c mod_auth_urs_ssl.c \
  mod_auth_urs_http.c mod_auth_urs_json.c


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{_libdir}/httpd/modules
install -m 755 .libs/%{name}.so \
  $RPM_BUILD_ROOT%{_libdir}/httpd/modules/%{name}.so


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc README LICENSE
%{_libdir}/httpd/modules/%{name}.so


%changelog