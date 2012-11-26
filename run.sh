#!/bin/bash
#./configure CPPFLAGS=-DDEBUG CFLAGS="-g3 -O0 -Wall -pendantic"
make clean
make DEBUG=1

UDP_FILTER="./udp-filter -t"
ip_filter1=$(cat example.log | $UDP_FILTER -i 216.38.130.161 | wc -l)
ip_filter2=$(cat example.log | $UDP_FILTER -i 0.0.0.0/0 | wc -l)
ip_filter3=$(cat example.log | $UDP_FILTER -i 216.38.130.161,0.0.0.0 | wc -l)
ip_filter4=$(cat example.log | $UDP_FILTER -i 127.0.0.1/14,216.0.0.0/4 | wc -l)


domain_filter1=$(cat example.log | $UDP_FILTER -d waka | wc -l)
domain_filter2=$(cat example.log | $UDP_FILTER -d wiki -g -c US -b country | wc -l)
domain_filter3=$(cat example.log | $UDP_FILTER -d "(wiki)" -r | wc -l)

anonymize_filter1=$(cat example.log | $UDP_FILTER -arandom | wc -l)




# Do anonymization on a small data set, make sure the ips are different
# from the original ones (the actual definition of anonymization)
anonymize_filter2_id=`date +%s`
anonymize2_input=/tmp/anonymize_input_$anonymize_filter2_id
anonymize2_output=/tmp/anonymize_output_$anonymize_filter2_id
cat example.log |                         cut -d' ' -f5 >  $anonymize2_input
cat example.log | ./udp-filter -arandom | cut -d' ' -f5 > $anonymize2_output
# get difference between ip field before and after anonymization and because
# diff it outputting the number of lines doubled, we just divide it by two
# and get the number of differences
anonymize_filter2=$(diff -U 0 $anonymize2_input $anonymize2_output | \
                     grep -v "^\(---\|\+++\)" | \
                     grep "^[-+]" | \
                     wc -l | perl -ne '$_ >>= 1; print $_')
# cleanup
rm -f $anonymize2_input $anonymize2_output







geo_filter1=$(cat example.log | $UDP_FILTER -g -b country | wc -l)
geo_filter2=$(cat example.log | $UDP_FILTER -d wiki -g -c US,FR -b country | wc -l)

# there's one single log line in example.xforwardfor.log and the ip is resolved to U.S. but the
# X-Forwarded-For header says it's from Japan and we check to see if that is correctly resolved
geo_filter3=$(cat example.xforwardfor.log | $UDP_FILTER -g -b country | grep " JP$\| US$" | wc -l)

path_filter1=$(cat example.log | $UDP_FILTER -p Manual | wc -l)

status_filter1=$(cat example.log | $UDP_FILTER -s 504 | wc -l)
status_filter2=$(cat example.log | $UDP_FILTER -s 50 | wc -l)
status_filter3=$(cat example.log | $UDP_FILTER -s 400,200 | wc -l)

referer_filter1=$(cat example.log| $UDP_FILTER -f www.mediawiki.org | wc -l)

collector_output1=$(cat example.collector.log  | $UDP_FILTER -o -B | diff example.collector.expected_result -)
collector_output2=$(cat example.collector2.log | ./udp-filter -o | grep "null" | wc -l )
collector_output3_wv=$(cat example.wikivoyage.wikidata.log | ./udp-filter -o | grep "\.wv" | wc -l )
collector_output3_wd=$(cat example.wikivoyage.wikidata.log | ./udp-filter -o | grep "\.wd" | wc -l )

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



if [ $ip_filter1 -eq 5 ]; then
	cecho "Pass" $green
else
	cecho "Fail" $red
fi

if [ $ip_filter2 -eq 6 ]; then
	cecho "Pass" $green
else
	cecho "Fail" $red
fi

if [ $ip_filter3 -eq 5 ]; then
	cecho "Pass" $green
else
	cecho "Fail" $red
fi

if [ $ip_filter4 -eq 6 ]; then
	cecho "Pass" $green
else
	cecho "Fail" $red
fi

if [ $domain_filter1 -eq 0 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $domain_filter2 -eq 5 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $domain_filter3 -eq 6 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $anonymize_filter1 -eq 6 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi


if [ $anonymize_filter2 -eq 10 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi


if [ $geo_filter1 -eq 6 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $geo_filter2 -eq 5 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $geo_filter3 -eq 2 ]; then
        cecho "Pass" $green
else
        cecho "Fail" $red
fi

if [ $path_filter1 -eq 0 ]; then
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


if [ -z "$collector_output1" ]; then
        cecho "Pass" $green
else
	  cecho "Fail" $red
fi

# collector output should not have any (null)
if [ $collector_output2 -eq 0 ]; then
        cecho "Pass" $green
else
	  cecho "Fail" $red
fi

if [ $referer_filter1 -eq 1 ]; then
	cecho "Pass" $green
else
	cecho "Fail" $red
fi

if [ $collector_output3_wv -eq 2 -a $collector_output3_wd -eq 2 ]; then
	cecho "Pass" $green
else
	cecho "Fail" $red
fi


exit 0

