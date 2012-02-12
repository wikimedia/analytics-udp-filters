make clean
make
cat example.log | ./udp-filter -u wiki,waka  -g -d GeoIP.dat -v -c BA,IN
