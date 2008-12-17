%define shortname dmidecode
%define name python-dmidecode
%define version 0.1
%define unmangled_version 0.1
%define release 1

Summary: Python wrapper around dmidecode
Name: %{name}
Version: %{version}
Release: %{release}.%{dist}
Requires: redhat-lsb
Source: %{shortname}-%{unmangled_version}.tar.gz
License: GNU GPL v3
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{shortname}-buildroot
Prefix: %{_prefix}
Vendor: Autonomy <dmidecode-devel@autonojects.net.au>
BuildRequires: python-devel
Url: http://projects.autonomy.net.au/dmidecode/

%description
The python module for dmidecode, written in C.

%prep
%setup -n %{shortname}-%{unmangled_version}
python setup.py clean

%build
python setup.py build

%install
python setup.py install --root=$RPM_BUILD_ROOT --record=INSTALLED_OBJECTS

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_OBJECTS
