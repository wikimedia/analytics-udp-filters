#
# Regular cron jobs for the udp-filters package
#
0 4	* * *	root	[ -x /usr/bin/udp-filters_maintenance ] && /usr/bin/udp-filters_maintenance
