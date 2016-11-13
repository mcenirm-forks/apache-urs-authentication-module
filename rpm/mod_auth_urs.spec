Name:           mod_auth_urs
Version:        1.1
Release:        1%{?dist}
Summary:        EOSDIS User Registration System module for Apache httpd

Group:          System Environment/Daemons
License:        Apache
URL:            https://git.earthdata.nasa.gov/projects/AAM/repos/apache-urs-authentication-module/browse
Source0:        %{name}-%{version}.tar.xz

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
%setup -q


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
