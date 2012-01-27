make clean
make
cat example.log | ./udp_filter -p wiki,waka  -g -d GeoIP.dat -v -c BA,IN
