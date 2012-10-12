#/bin/bash

if [ -z "$DEBFULLNAME" ]
	then export DEBFULLNAME="Diederik van Liere"
fi

if [ -z "$DEBEMAIL" ]
	then export DEBEMAIL="dvanliere@wikimedia.org"
fi


if [ `whoami` != 'root' ]; then
  echo "Executing debianize.sh script"
else
  echo "Error: Executing debianize.sh as root not recommended"
  exit 1
fi



# TODO: check if the project uses automake/autoconf and if so then run the following commnds
# in order to clean stuff up

make clean;
rm -f Makefile configure;
aclocal;
autoreconf;
autoconf;
automake;

LICENSE=gpl2
FIRST_COMMIT_DATE=`git log --pretty=format:"%H %ad" | perl -ne '/(\d+) ([+-]?\d+)$/ && print "$1\n"' | sort | uniq | tail -1`
FINAL_COMMIT_DATE=`git log --pretty=format:"%H %ad" | perl -ne '/(\d+) ([+-]?\d+)$/ && print "$1\n"' | sort | uniq | head -1`
REMOTE_URL=`git config --get remote.origin.url  | perl -ne '@url=split /\@/,$_; print $url[1];'`

VERSION=`git describe | awk -F'-g[0-9a-fA-F]+' '{print $1}' | sed -e 's/\-/./g' `
MAIN_VERSION=`git describe --abbrev=0`

PACKAGE=${PWD##*/}
echo 'Building package for ' $PACKAGE

tar -cvf $PACKAGE.tar --exclude-from=exclude .
mv $PACKAGE.tar ../
cd ..
rm -rf $PACKAGE-${VERSION}
mkdir  $PACKAGE-${VERSION}
tar -C $PACKAGE-${VERSION} -xvf $PACKAGE.tar

rm ${PACKAGE}\_${VERSION}.orig.tar.gz

cd $PACKAGE-${VERSION}

VERSION=$VERSION perl -pi -e 's/VERSION=".*";/VERSION="$ENV{VERSION}";/' src/udp-filter.c
VERSION=$VERSION perl -pi -e 's/VERSION=".*";/VERSION="$ENV{VERSION}";/' configure.ac

mkdir m4
DH_MAKE_PKG_NAME=$PACKAGE\_${VERSION}



#if [ ! -e "$DH_MAKE_PKG_NAME" ]; then
  #echo "Error: archive $DH_MAKE_PKG_NAME doesn't exist"
  #exit 2
#else
echo "dh_make -c ${LICENSE} -e ${DEBEMAIL} -s --createorig -p $DH_MAKE_PKG_NAME"
#fi


dh_make -c ${LICENSE} -e ${DEBEMAIL} -s --createorig -p ${DH_MAKE_PKG_NAME}

cd debian
rm *ex *EX
rm README.Debian dirs
#cp ../$PACKAGE/debian/control debian/.
#cp ../$PACKAGE/debian/rules debian/.
#cp ../$PACKAGE/debian/copyright debian/.
#cp ../$PACKAGE/debian/changelog debian/.
#cp ../$PACKAGE/Makefile debian/.
#cd ../$PACKAGE_${VERSION} &&
cd ..
dpkg-buildpackage -b #-v${VERSION}
cd ..


ARCHITECTURE=`uname -m`
ARCH_i686="i386"
ARCH_x86_64="amd64"
ARCH_SYS=""

if [ $ARCHITECTURE == "i686" ]; then
  ARCH_SYS=$ARCH_i686
elif [ $ARCHITECTURE == "x86_64" ]; then
  ARCH_SYS="amd64"
else
  echo -e  "Sorry, only i686 and x86_64 architectures are supported.\n"
  exit 1
fi


PACKAGE_NAME_VERSION=$PACKAGE\_${VERSION}\_$ARCH_SYS.deb
PACKAGE_NAME_MAIN_VERSION=$PACKAGE\_${MAIN_VERSION}\_${ARCH_SYS}.deb


dpkg-deb --contents ${PACKAGE_NAME_VERSION}
echo "Currently in =>"`pwd`
echo -e "Linting package ${PACKAGE_NAME_VERSION} ...\n"
lintian -Ivi${PACKAGE_NAME_VERSION}
#mv ${PACKAGE_NAME_MAIN_VERSION} ${PACKAGE_NAME_VERSION}




