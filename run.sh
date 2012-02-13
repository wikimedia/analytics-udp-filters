make clean
make
cat example.log | ./udp-filter -u "(wiki)" -i 192.168.0.0 -r -g -d GeoIP.dat -v -c BA,IN
