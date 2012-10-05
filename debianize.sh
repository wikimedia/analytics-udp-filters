#/bin/bash

export DEBFULLNAME="Diederik van Liere"

VERSION=`git describe | awk -F'-g[0-9a-fA-F]+' '{print $1}' | sed -e 's/\-/./g' `
MAIN_VERSION=`git describe --abbrev=0`

PACKAGE=${PWD##*/}
echo 'Building package for $PACKAGE'

tar -cvf $PACKAGE.tar --exclude-from=exclude .
mv $PACKAGE.tar ../
cd ..
rm -rf $PACKAGE-${MAIN_VERSION}
mkdir $PACKAGE-${MAIN_VERSION}
tar -C $PACKAGE-${MAIN_VERSION} -xvf $PACKAGE.tar


rm $PACKAGE-${MAIN_VERSION}.orig.tar.gz

cd $PACKAGE-${MAIN_VERSION}

VERSION=$VERSION perl -pi -e 's/VERSION=".*";/VERSION="$ENV{VERSION}";/' src/udp-filter.c

mkdir m4
dh_make -c gpl2 -e dvanliere@wikimedia.org -s --createorig -p $PACKAGE_${VERSION}
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
dpkg-buildpackage -v${VERSION}
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


PACKAGE_NAME_VERSION=$PACKAGE_${VERSION}_$ARCH_SYS.deb
PACKAGE_NAME_MAIN_VERSION=$PACKAGE_${MAIN_VERSION}_${ARCH_SYS}.deb


dpkg-deb --contents ${PACKAGE_NAME_MAIN_VERSION}

echo -e "Linting package ${PACKAGE_NAME_MAIN_VERSION} ...\n"
lintian ${PACKAGE_NAME_MAIN_VERSION}
mv ${PACKAGE_NAME_MAIN_VERSION} ${PACKAGE_NAME_VERSION}




