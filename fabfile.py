from fabric.api import run, env, put, local, settings
from datetime import datetime
from socket import gethostname
from os import getcwd
import subprocess



email = 'dvanliere@wikimedia.org'

def prod():
	host = gethostname()
	if host == 'drdee':
		env.hosts = ['192.168.2.24']
	else:
		env.port = 222
		env.hosts = ['wikilytics.org']
	
def collect_params():
	params ={}
	p = subprocess.Popen(['./udp-filter', '-V'], shell=False, stdout=subprocess.PIPE)
	stdout, stderr = p.communicate()
	version = stdout.split("\n")[0]
	version = version.split(" ")[1]
	print "Version: %s was detected." % version
	return version

def build_remote(target_dir, target_gz, target_tar, version, year, month, day):
	local_dir = getcwd()
	run('rm -rf %s' % target_dir)
	with settings(warn_only=True):
		run('rm udp-filter_%s+git%s%s%s.orig.tar.gz' % (version, year, month, day))
	with settings(warn_only=True):
		run('rm udp-filter_%s*' % version)
	run('mkdir ~/%s' % target_dir)
	run('gunzip --force %s' % target_gz)
	run('tar -xvf %s -C ~/%s/' % (target_tar, target_dir))
	run('gzip --force %s' % target_tar)
	run('cd %s && aclocal' % (target_dir))
	run('cd %s && autoreconf --install' % (target_dir))
	run('cd %s && autoconf' % (target_dir))
	run('cd %s && dh_make --single -c gpl2 -e %s -f ../%s' %  (target_dir, email, target_gz))
	run('cd %s && cp control-sample ~/%s/debian/control' % (target_dir, target_dir))
	run('cd %s && cp copyright-sample ~/%s/debian/copyright' % (target_dir, target_dir))
	run('cd %s && cp ChangeLog ~/%s/debian/changelog' % (target_dir, target_dir))
	run('cd %s && cp udp-filter.manpages ~/%s/debian/udp-filter.manpages' % (target_dir, target_dir))
	run('cd %s/debian/ && touch file' % target_dir)
	run('cd %s/debian/ && rm *.ex && rm udp-filter.doc-base.EX' % (target_dir))
	#there is a bug with dh_make < 0.56 that will not create a debian package when the format is specified as 3.0 (quilt)
	run('cd %s/debian/source && rm format' % (target_dir))
	run('cd %s/debian/source && echo "1.0" >> format' % (target_dir))
	run('cd %s/debian/ && touch files' % (target_dir))
	run('cd %s/debian/ && rm README.Debian' % (target_dir))
	run('cd %s/debian/ && rm README.source' % (target_dir))
	run('cd %s && dpkg-buildpackage -rfakeroot' % (target_dir))
	run('cd %s && lintian -Ivi ../udp-filter_%s_amd64.changes' % (target_dir, version))
	
	local('cd package && scp -P %s %s:~/udp-filter_%s* .' % (env.port, env.hosts[0], version))
	local('cd package && scp udp-filter_%s* emery.wikimedia.org:~/' % version)

def write_control_file(version):
	fh = open('control-sample', 'w')
	fh.write('Source: udp-filter\n')
	fh.write('Section: utils\n')
	fh.write('Priority: extra\n')
	fh.write('Maintainer: Diederik van Liere (Wikimedia Foundation) <dvanliere@wikimedia.org>\n')
	fh.write('Build-Depends: debhelper (>= 7.0.50~), autotools-dev, mime-support, mawk, libgeoip-dev\n')
	fh.write('Standards-Version: 3.9.1\n')
	fh.write('Vcs-Git: git://gerrit.wikimedia.org:29416/analytics/udp-filters.git\n')
	fh.write('Vcs-Browser: https://gerrit.wikimedia.org/r/gitweb?p=analytics/udp-filters.git\n')
	fh.write('Homepage: http://www.mediawiki.org/wiki/Analytics/UDP-filters\n')
	fh.write('\n')
	fh.write('Package: udp-filter\n')
	fh.write('Architecture: any\n')
	#fh.write('Version: %s\n' % version)	
	fh.write('Depends: libgeoip1 (>= 1.4.6), libc6 (>= 2.4)\n')
	#fh.write('Depends: ${shlibs:Depends}, ${misc:Depends}, libgeoip1 (>= 1.4.6)\n')
	fh.write("Description: <Wikimedia's udp-filter system.>\n")
	fh.write(" WMF logs pageviews by listing to the udp2log daemon. udp-filter allows\n") 
	fh.write(" you to configure a filter and write particular pageviews, based on a\n")
	fh.write(" combination of domain and url matching, to a logfile. It also offers\n")
	fh.write(" geocoding, anonymization and ip-range filtering of ip addresses.\n")
	fh.close()

def main():
	version = collect_params()
	today = datetime.today()
	
	day = today.day if len(str(today.day))==2 else '%s%s' % (0, today.day)
	month = today.month if len(str(today.month))==2 else '%s%s' % (0, today.month)
	year = today.year
	
	target_tar = 'udp-filter-%s+git%s%s%s.tar' % (version, today.year, month, day)
	target_gz = 'udp-filter-%s+git%s%s%s.tar.gz' % (version, today.year, month, day)
	target_dir = 'udp-filter-%s+git%s%s%s' % (version, today.year, month, day)
	
	local('git pull')
	write_control_file(version)
	local('help2man --section=1 --no-info --include=help2man.include --output=docs/udp-filter.1 --version-string=V ./udp-filter')
	#local('rm ChangeLog')	
	#local('git2cl >> ChangeLog')
	#local('git log --pretty=%s >> ChangeLog')
	local('tar -cvf %s -X exclude.txt .' % target_tar)
	local('gzip --force %s' % target_tar)
	put('%s' % target_gz, '~/%s' % target_gz)

	build_remote(target_dir, target_gz, target_tar, version, year, month, day)

if __name__ == '__main__':
	main()
