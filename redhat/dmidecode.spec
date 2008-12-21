%define is_not_debian %(test -e /etc/debian_version && echo 1 || echo 0)

Summary: Python extension module for dmidecode.
Name: python-dmidecode
Version: 2.10
Release: 0%?{dist}
Requires: redhat-lsb
Source: %{name}-%{version}.tar.gz
License: GNU GPL v3
Group: System Environment/Libraries
BuildRoot: %{_tmppath}/%{name}-buildroot
Prefix: %{_prefix}
Vendor: Autonomy <dmidecode-devel@autonojects.net.au>
%{?!is_not_debian:BuildRequires: python-devel}
Url: http://projects.autonomy.net.au/dmidecode/

%description
 The Desktop Management Interface provides a standardized description of
 a computer's hardware, including characteristics such as BIOS serial
 number and hardware connectors.

 python-dmidecode provides an interface to the DMI data available from
 the BIOS.  It is intended to be used as a back-end tool by other
 hardware detection programs implemented in python.

%prep
%setup -q -n %{name}-%{version}
python src/setup.py clean

%build
python src/setup.py build

%install
python src/setup.py install --root=%{buildroot} --record=INSTALLED_OBJECTS

%clean
rm -rf %{buildroot}

%files -f INSTALLED_OBJECTS

%changelog
* Fri Dec 19 2008 Nima Talebi <nima@it.net.au> - 2.10-0
- Initial release

