make clean
aclocal
autoconf
autoreconf

./configure CPPFLAGS=-DDEBUG CFLAGS="-g3 -O0 -Wall -pedantic"  $@

