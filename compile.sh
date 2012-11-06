#!/bin/bash
autoreconf
aclocal
autoconf
automake

./configure  $@

