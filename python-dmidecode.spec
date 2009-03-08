%{!?python_sitearch: %define python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib(1)")}
%{!?python_ver: %define python_ver %(%{__python} -c "import sys ; print sys.version[:3]")}

Summary: python extension module to access DMI data
Name: python-dmidecode
Version: 2.10
Release: 1
License: GPLv3
Group: System Environment/Libraries
URL: http://projects.autonomy.net.au/dmidecode/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

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
%{python_sitearch}/dmidecode.so
%if "%{python_ver}" >= "2.5"
%{python_sitearch}/*.egg-info
%endif

%changelog
* Sat Mar  7 2009 Clark Williams <williams@redhat.com> - 2.10.3-1
- Initial build.

