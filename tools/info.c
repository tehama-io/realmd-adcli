/*
 * adcli
 *
 * Copyright (C) 2013 Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 *
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "adcli.h"
#include "tools.h"

#include <assert.h>
#include <err.h>
#include <stdio.h>

typedef enum {
	/* Have short equivalents */
	opt_domain = 'D',
	opt_domain_controller = 'S',
	opt_verbose = 'v',
} Option;

static adcli_tool_desc common_usages[] = {
	{ opt_domain, "active directory domain name" },
	{ opt_domain_controller, "domain controller to connect to" },
	{ opt_verbose, "show verbose progress and failure messages", },
	{ 0 },
};

static void
print_info (adcli_disco *disco,
            int for_host)
{
	adcli_disco *other;

	printf ("[domain]\n");
	if (disco->domain)
		printf ("domain-name = %s\n", disco->domain);
	if (disco->domain_short)
		printf ("domain-short = %s\n", disco->domain_short);
	if (disco->forest)
		printf ("domain-forest = %s\n", disco->forest);
	if (disco->host_name)
		printf ("domain-controller = %s\n", disco->host_name);
	if (disco->server_site)
		printf ("domain-controller-site = %s\n", disco->server_site);
	if (disco->flags) {
		printf ("domain-controller-flags =");
		if (disco->flags & ADCLI_DISCO_PDC) printf (" pdc");
		if (disco->flags & ADCLI_DISCO_GC) printf (" gc");
		if (disco->flags & ADCLI_DISCO_LDAP) printf (" ldap");
		if (disco->flags & ADCLI_DISCO_DS) printf (" ds");
		if (disco->flags & ADCLI_DISCO_KDC) printf (" kdc");
		if (disco->flags & ADCLI_DISCO_TIMESERV) printf (" timeserv");
		if (disco->flags & ADCLI_DISCO_CLOSEST) printf (" closest");
		if (disco->flags & ADCLI_DISCO_WRITABLE) printf (" writable");
		if (disco->flags & ADCLI_DISCO_GOOD_TIMESERV) printf (" good-timeserv");
		if (disco->flags & ADCLI_DISCO_NDNC) printf (" ndnc");
		if (disco->flags & ADCLI_DISCO_SELECT_SECRET_DOMAIN_6) printf (" select-secret");
		if (disco->flags & ADCLI_DISCO_FULL_SECRET_DOMAIN_6) printf (" full-secret");
		if (disco->flags & ADCLI_DISCO_ADS_WEB_SERVICE) printf (" ads-web");
		if (disco->flags & ADCLI_DISCO_HAS_DNS_NAME) printf (" dns-name");
		if (disco->flags & ADCLI_DISCO_IS_DEFAULT_NC) printf (" default-nc");
		if (disco->flags & ADCLI_DISCO_FOREST_ROOT) printf (" forest-root");
		printf ("\n");
	}

	switch (adcli_disco_usable (disco)) {
	case ADCLI_DISCO_UNUSABLE:
		printf ("domain-controller-usable = no\n");
		break;
	case ADCLI_DISCO_MAYBE:
		printf ("domain-controller-usable = maybe\n");
		break;
	case ADCLI_DISCO_USABLE:
		printf ("domain-controller-usable = yes\n");
		break;
	default:
		break;
	}

	if (!for_host && disco->host_name) {
		printf ("domain-controllers =");
		for (other = disco; other != NULL; other = other->next) {
			if (other->host_name)
				printf (" %s", other->host_name);
		}
		printf ("\n");
	}

	printf ("[computer]\n");
	if (disco->client_site)
		printf ("computer-site = %s\n", disco->client_site);

}

int
adcli_tool_info (adcli_conn *unused,
                 int argc,
                 char *argv[])
{
	const char *domain = NULL;
	const char *server = NULL;
	adcli_disco *disco = NULL;
	int for_host;
	int opt;

	struct option options[] = {
		{ "domain", required_argument, NULL, opt_domain },
		{ "domain-controller", required_argument, NULL, opt_domain_controller },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	static adcli_tool_desc usages[] = {
		{ 0, "usage: adcli info <domain>" },
		{ 0 },
	};

	while ((opt = adcli_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_domain:
			domain = optarg;
			break;
		case opt_domain_controller:
			server = optarg;
			break;
		case opt_verbose:
			break;
		case 'h':
		case '?':
		case ':':
			adcli_tool_usage (options, usages);
			adcli_tool_usage (options, common_usages);
			return opt == 'h' ? 0 : 2;
		default:
			assert (0 && "not reached");
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1)
		domain = argv[0];
	else if (argc != 0)
		errx (2, "specify one user name to create");

	if (server) {
		adcli_disco_host (server, &disco);
		if (disco == NULL)
			errx (1, "couldn't discover domain controller: %s", server);
		for_host = 1;
	} else if (domain) {
		adcli_disco_domain (domain, &disco);
		if (disco == NULL)
			errx (1, "couldn't discover domain: %s", domain);
		for_host = 0;
	} else {
		errx (2, "specify a domain to discover");
	}

	print_info (disco, for_host);
	adcli_disco_free (disco);

	return 0;
}
