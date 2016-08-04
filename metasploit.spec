#
# spec file for package metasploit
#
# Please submit bugfixes or comments via https://github.com/pureooze/metasploit-framework-rpm/issues
#

Name:           metasploit
Version:        20160424
Release:        0
Summary:        Provides useful information and tools for testers,researchers,and developers
License:        BSD-3
Group:          Applications/Security
Url:            https://www.metasploit.com/
Source:         https://github.com/rapid7/metasploit-framework/%{name}-%{version}.tar.gz
BuildRequires:	unzip
BuildRequires:	update-alternatives
BuildRequires:	ant
BuildRequires:  fdupes
BuildRequires:  ruby-devel
BuildRequires:  postgresql-devel
BuildRequires:  libpcap-devel
BuildRequires:  ruby2.2-rubygem-bundler

%define rb_build_versions ruby22
%define rb_build_abi ruby:2.2.0
BuildRequires:	%{rubygem simplecov}
Requires:       rubygem(%{rb_build_abi}:simplecov)

BuildRequires:	%{rubygem yard}
Requires:       rubygem(%{rb_build_abi}:yard)

BuildRequires:	%{rubygem pry}
Requires:       rubygem(%{rb_build_abi}:pry)

#BuildRequires:	%{rubygem octokit}
#Requires:       rubygem(%{rb_build_abi}:octokit)

BuildRequires:	%{rubygem factory_girl_rails}
Requires:       rubygem(%{rb_build_abi}:factory_girl_rails)

BuildRequires:	%{rubygem fivemat}
Requires:       rubygem(%{rb_build_abi}:fivemat)

BuildRequires:	%{rubygem rake}
Requires:       rubygem(%{rb_build_abi}:rake)

BuildRequires:	%{rubygem rspec-rails}
Requires:       rubygem(%{rb_build_abi}:rspec-rails)

BuildRequires:	%{rubygem aruba}
Requires:       rubygem(%{rb_build_abi}:aruba)

Requires:       ruby
Requires:       rubygems
BuildRoot:      %{_tmppath}/%{name}-%{version}-build


%description
Knowing the adversary's moves helps you better prepare your defenses.
Metasploit,backed by a community of 200,000 users and contributors,gives you that insight.
It's the most impactful penetration testing solution on the planet.
With it,uncover weaknesses in your defenses,focus on the highest risks,and improve your security outcomes.

%prep
%setup -q
find -type f -name .gitkeep -print -delete
mv Gemfile.lock{,.upstream}
bundle exec rails --version
diff -urN Gemfile.lock{.upstream,} ||:

%build

%install
install -Dd %{buildroot}%{_bindir}/
install -Dd %{buildroot}%{_datadir}/%{name}
install -Dd %{buildroot}%{_libdir}/%{name}/data/templates
install -Dd %{buildroot}%{_libdir}/%{name}/data/exploits
rm -rf external/source
rm -rf data/templates/src
rm -f external/serialport/README.orig
rm -f tools/context/cpuid-key.c
rm -f tools/context/time-key.c
rm -f external/serialport/serialport.c
rm -f data/templates/cpuinfo.c
rm -f tools/memdump/memdump.c
rm -f tools/context/stat-key.c

mv data/templates/* %{buildroot}%{_libdir}/%{name}/data/templates
mv data/cpuinfo/* %{buildroot}%{_libdir}/%{name}/data/templates
mv data/exploits/CVE-2014-3153.elf %{buildroot}%{_libdir}/%{name}/data/exploits
mv data/exploits/CVE-2013-2171.bin %{buildroot}%{_libdir}/%{name}/data/exploits

cp -a  * %{buildroot}%{_datadir}/%{name}
%fdupes %{buildroot}%{_datadir}/%{name}/*/*
ln -s %{_datadir}/%{name}/msfbinscan %{buildroot}%{_bindir}/msfbinscan
ln -s %{_datadir}/%{name}/msfconsole %{buildroot}%{_bindir}/msfconsole
ln -s %{_datadir}/%{name}/msfd %{buildroot}%{_bindir}/msfd
ln -s %{_datadir}/%{name}/msfelfscan %{buildroot}%{_bindir}/msfelfscan
ln -s %{_datadir}/%{name}/msfmachscan %{buildroot}%{_bindir}/msfmachscan
ln -s %{_datadir}/%{name}/msfpescan %{buildroot}%{_bindir}/msfpescan
ln -s %{_datadir}/%{name}/msfrop %{buildroot}%{_bindir}/msfrop
ln -s %{_datadir}/%{name}/msfrpc %{buildroot}%{_bindir}/msfrpc
ln -s %{_datadir}/%{name}/msfrpcd %{buildroot}%{_bindir}/msfrpcd
ln -s %{_datadir}/%{name}/msfupdate %{buildroot}%{_bindir}/msfupdate
ln -s %{_datadir}/%{name}/msfvenom %{buildroot}%{_bindir}/msfvenom

%files
%defattr(-,root,wheel)
%{_bindir}/msf*

%dir %{_datadir}/%{name}
%dir %{_datadir}/%{name}/*
%{_datadir}/%{name}/*
%{_datadir}/metasploit/*/*

%dir %{_libdir}/%{name}
%dir %{_libdir}/%{name}/*
%{_libdir}/%{name}/*
%{_libdir}/%{name}/*/*

%attr(750,root,wheel) %{_datadir}/%{name}/msf*
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/module_license.rb
%attr(750,root,wheel) %{_datadir}/%{name}/script/cucumber
%attr(750,root,wheel) %{_datadir}/%{name}/test/tests/testbase.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/module_commits.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/password/winscp_decrypt.rb
%attr(750,root,wheel) %{_datadir}/%{name}/lib/rex/post/meterpreter/extensions/android/android.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/dev/msftidy.rb
%attr(750,root,wheel) %{_datadir}/%{name}/plugins/msgrpc.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/dev/add_pr_fetch.rb
%attr(750,root,wheel) %{_datadir}/%{name}/features/support/bin/stty
%attr(750,root,wheel) %{_datadir}/%{name}/tools/password/lm2ntcrack.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/psexec.rb
%attr(750,root,wheel) %{_datadir}/%{name}/plugins/msfd.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/metasm_shell.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/java_deserializer.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/profile.sh
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/update_payload_cached_sizes.rb
%attr(750,root,wheel) %{_datadir}/%{name}/lib/rex/google/geolocation.rb
%attr(750,root,wheel) %{_datadir}/%{name}/lib/nessus/nessus-cli.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/exe2vbs.rb
%attr(750,root,wheel) %{_datadir}/%{name}/lib/rex/post/gen.pl
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/module_reference.rb
%attr(750,root,wheel) %{_datadir}/%{name}/data/sounds/aiff2wav.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/msu_finder.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/module_payloads.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/pattern_offset.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/recon/google_geolocate_bssid.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/find_badchars.rb
%attr(750,root,wheel) %{_datadir}/%{name}/data/exploits/capture/http/forms/grabforms.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/password/vxdigger.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/missing_payload_tests.rb
%attr(750,root,wheel) %{_datadir}/%{name}/lib/rex/post/meterpreter/extensions/android/tlv.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/module_rank.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/pdf2xdp.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/password/hmac_sha1_crack.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/dev/find_release_notes.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/password/cpassword_decrypt.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/module_disclodate.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/virustotal.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/module_mixins.rb
%attr(750,root,wheel) %{_datadir}/%{name}/lib/msf/core/module/platform_list.rb
%attr(750,root,wheel) %{_datadir}/%{name}/plugins/openvas.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/msf_irb_shell.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/committer_count.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/dev/set_binary_encoding.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/password/vxmaster.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/password/md5_lookup.rb
%attr(750,root,wheel) %{_datadir}/%{name}/external/serialport/debian/rules
%attr(750,root,wheel) %{_datadir}/%{name}/tools/password/halflm_second.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/module_count.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/dev/import-dev-keys.sh
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/module_author.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/module_ports.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/file_pull_requests.rb
%attr(750,root,wheel) %{_datadir}/%{name}/plugins/nexpose.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/exe2vba.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/nasm_shell.rb
%attr(750,root,wheel) %{_datadir}/%{name}/Rakefile
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/module_targets.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/recon/makeiplist.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/recon/list_interfaces.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/egghunter.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/pattern_create.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/install_msf_apk.sh
%attr(750,root,wheel) %{_datadir}/%{name}/tools/dev/pre-commit-hook.rb
%attr(750,root,wheel) %{_datadir}/%{name}/data/exploits/capture/http/forms/extractforms.rb
%attr(750,root,wheel) %{_datadir}/%{name}/lib/openvas/openvas-omp.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/payload_lengths.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/reg.rb
%attr(750,root,wheel) %{_datadir}/%{name}/tools/exploit/jsobfu.rb
%attr(750,root,wheel) %{_datadir}/%{name}/script/rails
%attr(750,root,wheel) %{_datadir}/%{name}/tools/modules/verify_datastore.rb
%attr(750,root,wheel) %{_libdir}/%{name}/data/templates/build.sh

%changelog

