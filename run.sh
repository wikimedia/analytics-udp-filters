#!/bin/bash
#./configure CPPFLAGS=-DDEBUG CFLAGS="-g3 -O0 -Wall -pendantic"
make clean
make DEBUG=1
ip_filter1=$(cat example.log | ./udp-filter -i 216.38.130.161 | wc -l)
ip_filter2=$(cat example.log | ./udp-filter -i 0.0.0.0/0 | wc -l)
ip_filter3=$(cat example.log | ./udp-filter -i 216.38.130.161,0.0.0.0 | wc -l)
ip_filter4=$(cat example.log | ./udp-filter -i 127.0.0.1/14,216.0.0.0/4 | wc -l)
ip_filter5=$(cat example.collector.log | ./udp-filter -o -B | diff example.collector.expected_result -)


domain_filter1=$(cat example.log | ./udp-filter -d waka | wc -l)
domain_filter2=$(cat example.log | ./udp-filter -d wiki -g -c US -b country | wc -l)
domain_filter3=$(cat example.log | ./udp-filter -d "([wiki])" -r | wc -l)

anonymize_filter1=$(cat example.log | ./udp-filter -a | wc -l)

geo_filter1=$(cat example.log | ./udp-filter -g -b country | wc -l)
geo_filter2=$(cat example.log | ./udp-filter -d wiki -g -c US,FR -b country | wc -l)

path_filter1=$(cat example.log | ./udp-filter -p Manual | wc -l)

status_filter1=$(cat example.log | ./udp-filter -s 504 | wc -l)
status_filter2=$(cat example.log | ./udp-filter -s 50 | wc -l)
status_filter3=$(cat example.log | ./udp-filter -s 400,200 | wc -l)

referer_filter1=$(cat example.log| ./udp-filter -f www.mediawiki.org | wc -l)

red="\033[31m"
green="\033[32m"
black="\033[30m"


alias Reset="tput sgr0"      #  Reset text attributes to normal
 
 
cecho ()                     # Color-echo.
                             # Argument $1 = message
                             # Argument $2 = color
  {
  local default_msg="No message passed."
                               # Doesn't really need to be a local variable.

   message=${1:-$default_msg}   # Defaults to default message.
   color=${2:-$black}           # Defaults to black, if not specified.

   echo -e "$color"
   echo "$message"
   #Reset                      # Reset to normal.

 return
}



if [ $ip_filter1 -eq 1 ]; then
	cecho "Pass" $green
else
	cecho "Fail" $red
fi

if [ $ip_filter2 -eq 4 ]; then
	cecho "Pass" $green
else
	cecho "Fail" $red
fi

if [ $ip_filter3 -eq 1 ]; then
	cecho "Pass" $green
else
	cecho "Fail" $red
fi

if [ $ip_filter4 -eq 4 ]; then
	cecho "Pass" $green
else
	cecho "Fail" $red
fi

if [ $domain_filter1 -eq 0 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $domain_filter2 -eq 2 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $domain_filter3 -eq 3 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $anonymize_filter1 -eq 6 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $geo_filter1 -eq 6 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $geo_filter2 -eq 2 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi


if [ $path_filter1 -eq 1 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $status_filter1 -eq 1 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $status_filter2 -eq 2 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $status_filter3 -eq 4 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi


if [ -z "$ip_filter5" ]; then
  cecho "Pass" $green
else
	cecho "Fail" $red
fi


if [ $referer_filter1 -eq 1 ]; then
	cecho "Pass" $green
else
	cecho "Fail" $red
fi
exit 0

