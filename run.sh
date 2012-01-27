make clean
make
cat example.log | ./udp_filter -u wiki,waka  -g -d GeoIP.dat -v -c BA,IN
