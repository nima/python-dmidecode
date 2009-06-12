%{!?python_sitearch: %define python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(1)")}
%{!?python_ver: %define python_ver %(%{__python} -c "import sys ; print sys.version[:3]")}
%(!?dmidec_ver: %define dmidec_ver %(cd src ; %{__python} -c "from setup_common import *; print get_version();"))

Summary: python extension module to access DMI data
Name: python-dmidecode
Version: %{dmidec_ver}
Release: 1
License: GPLv2
Group: System Environment/Libraries
URL: http://projects.autonomy.net.au/dmidecode/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: libxml2
Requires: libxml2-python

%description
python-dmidecode is a python extension module that uses the
code-base of the 'dmidecode' utility, and presents the data
as python data structures

%prep
%setup -q

%build
make

%install
rm -rf $RPM_BUILD_ROOT
python src/setup.py install --root $RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc
%{python_sitearch}/dmidecodemod.so
%{python_sitearch}/dmidecode.py
%{python_sitearch}/dmidecode.py[co]
#%if "%{python_ver}" >= "2.5"
#%{python_sitearch}/*.egg-info
#%endif
/usr/share/python-dmidecode/pymap.xml

%changelog
* Fri Jun 12 2009 David Sommerseth <davids@redhat.com> - 3.10.6-1
- Use python setup_common::get_version() function to get the version number

* Wed Jun 10 2009 David Sommerseth <davids@redhat.com> - 3.10.6-1
- Updated to work with the new XML based python-dmidecode

* Sat Mar  7 2009 Clark Williams <williams@redhat.com> - 2.10.3-1
- Initial build.

