/*
    Copyright (C) 2012  <Diederik van Liere / Wikimedia Foundation>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <arpa/inet.h>
#include "udp-filter.h"
#include "anonymize.h"

anon_ipv4_t *anon_ipv4 = NULL;   // The libanon anon_ipv4 object for ipv4 anonymization.
anon_ipv6_t *anon_ipv6 = NULL;   // The libanon anon_ipv6 object for ipv6 anonymization.

/**
 * Initializes global anon_ipv4 and anon_ipv6 objects.
 * If anon_key_salt is NULL, a random key salt will
 * be used.
 */
char anonymous_ip[] = "0.0.0.0";
void init_anon_ip(uint8_t *anon_key_salt) {
	anon_key_t *anon_key = anon_key_new();

	// if anon_key_salt is set, then
	// use it as the salt to IP address anonymization hashing.
	if (anon_key_salt) {
		anon_key_set_key(anon_key, anon_key_salt, strlen((char *)anon_key_salt));
	}
	// else choose a random key.
	else {
		anon_key_set_random(anon_key);
	}

	// initialize the ipv4 and ipv6 objects
	anon_ipv4 = anon_ipv4_new();
	anon_ipv6 = anon_ipv6_new();

	if (!anon_ipv4 || !anon_ipv6) {
		fprintf(stderr, "Failed to initialize anonymization IP mapping.\n");
		anon_key_delete(anon_key);
		exit(EXIT_FAILURE);
    }

    anon_ipv4_set_key(anon_ipv4, anon_key);
    anon_ipv6_set_key(anon_ipv6, anon_key);
}



/**
 * Anonymizes an IPv4 or IPv6 string.
 *
 * If the globals anon_ipv4 or anon_ipv6 are not set
 * then the global anonymous_ip string will be used
 * to anonymize the IP.
 *
 * @param  string ip  string IP address.
 * @return string anonymized IP address.
 */
char *anonymize_ip_address(char *ip) {
	in_addr_t  raw4_address, raw4_anon_address;
	in6_addr_t raw6_address, raw6_anon_address;
	// AF_INET or AF_INET6
	int   ai_family;
	// pointer to the binary form of ip.
	void *raw_address;
	// string form of anonymized ip.
	char *anonymized_ip;

	// Big enough to hold 128 IPv6 addresses.
	// This is just a byte array meant hold raw
	// IPv4 or IPv6 addresses.  determine_ai_family
	// will set it to the raw address returned by
	// getaddrinfo().
	// NOTE:  This is to avoid an extra call to
	// inet_pton, since getaddrinfo() converts
	// a string IP address to its raw binary form.
	raw_address = malloc(sizeof(in6_addr_t));
	ai_family   = determine_ai_family(ip, raw_address); // AF_INET or AF_INET6

	// if raw_address is NULL, then getaddrinfo() either
	// couldn't get ai_family or it failed converting
	// ip into a binary raw IP address.  Return the
	// default anonymous_ip string.
	if (raw_address == NULL) {
		fprintf(stderr, "determine_ai_family did not return raw_address for %s.", ip);
		return anonymous_ip;
	}

	switch (ai_family) {
		// NOTE.  anon_ipv4_map_pref() and anon_ipv6_map_pref
		// take a ip*_addr_t struct as the raw address second
		// argument, NOT a pointer to one.  You'd think this
		// distinction wouldn't be important, but it is.
		// I haven't figured out why, but simply dereferencing
		// and casting the void *raw_address to the proper type
		// doesn't work.  You *can* get this to compile (if you
		// use a char * instead of void *), but unless you
		// memcpy into a ip*_addr_t struct, the anon_ function
		// will return unreliable results.  I was getting the same
		// anonymized IPs for different but similiar IPs.

		// anonymize IPv4 address
		case AF_INET:
			if (anon_ipv4 == NULL) {
				anonymized_ip = anonymous_ip;
			}
			else {
				// Anonymize the IPv4 address, saved in raw4_anon_address.
				memcpy(&raw4_address, raw_address, sizeof(in_addr_t));
				anon_ipv4_map_pref(anon_ipv4, raw4_address, &raw4_anon_address);
				// printf("anon_ipv4_map_pref %u -> %u\n", (unsigned int)(raw_address[0]), (unsigned int)raw4_anon_address);

				// Convert the raw anonymized address back to a string
				anonymized_ip = malloc(INET_ADDRSTRLEN);
				// If failed, use anonymous_ip "0.0.0.0".  This should never happen.
				if (!inet_ntop(AF_INET, &raw4_anon_address, anonymized_ip, INET_ADDRSTRLEN)) {
					perror("anonymize_ip_address: inet_ntop could not convert raw anonymized IPv4 address to a string");
					anonymized_ip = anonymous_ip;
				}
			}
			break;

		// anonymize IPv6 address
		case AF_INET6:
			if (anon_ipv6 == NULL) {
				anonymized_ip = anonymous_ip;
			}
			else {
				// Anonymize the IPv6 address, saved in raw6_anon_address.
				memcpy(&raw6_address, raw_address, sizeof(in6_addr_t));
				anon_ipv6_map_pref(anon_ipv6, raw6_address, &raw6_anon_address);
				// Convert the raw anonymized address back to a string
				anonymized_ip = malloc(INET6_ADDRSTRLEN);

				// If failed, use anonymous_ip "0.0.0.0".  This should never happen.
				if (!inet_ntop(AF_INET6, &raw6_anon_address, anonymized_ip, INET6_ADDRSTRLEN)) {
					perror("anonymize_ip_address: inet_ntop could not convert raw anonymized IPv6 address to a string");
					anonymized_ip = anonymous_ip;
				}
			}
			break;

		// Default use anonymous_ip "0.0.0.0"
		// This will only happen if ai_family couldn't
		// be determined.
		default:
			anonymized_ip = anonymous_ip;
			break;
	}
	// don't need this anymore.
	free(raw_address);

	// printf("Anonymized %s -> %s\n", ip, anonymized_ip);
	return anonymized_ip;
}
