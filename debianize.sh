#/bin/bash

if [ -z "$DEBFULLNAME" ]
	then export DEBFULLNAME="Diederik van Liere"
fi

if [ -z "$DEBEMAIL" ]
	then export DEBEMAILADDRESS="dvanliere@wikimedia.org"
fi
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
mkdir $PACKAGE-${VERSION}
tar -C $PACKAGE-${VERSION} -xvf $PACKAGE.tar

rm ${PACKAGE}_${VERSION}.orig.tar.gz

cd $PACKAGE-${VERSION}

VERSION=$VERSION perl -pi -e 's/VERSION=".*";/VERSION="$ENV{VERSION}";/' src/udp-filter.c
VERSION=$VERSION perl -pi -e 's/VERSION=".*";/VERSION="$ENV{VERSION}";/' configure.ac

mkdir m4
dh_make -c $LICENSE -e $DEBEMAILS -s --createorig -p $PACKAGE\_${VERSION}
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


PACKAGE_NAME_VERSION=$PACKAGE\_${VERSION}\_$ARCH_SYS.deb
PACKAGE_NAME_MAIN_VERSION=$PACKAGE\_${MAIN_VERSION}\_${ARCH_SYS}.deb


dpkg-deb --contents ${PACKAGE_NAME_VERSION}
echo "Currently in =>"`pwd`
echo -e "Linting package ${PACKAGE_NAME_VERSION} ...\n"
lintian -Ivi${PACKAGE_NAME_VERSION}
#mv ${PACKAGE_NAME_MAIN_VERSION} ${PACKAGE_NAME_VERSION}



