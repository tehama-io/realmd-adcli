/*
 * adcli
 *
 * Copyright (C) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#ifndef ADDISCO_H_
#define ADDISCO_H_

enum {
	ADCLI_DISCO_PDC                     = 0x00000001,
	ADCLI_DISCO_GC                      = 0x00000004,
	ADCLI_DISCO_LDAP                    = 0x00000008,
	ADCLI_DISCO_DS                      = 0x00000010,
	ADCLI_DISCO_KDC                     = 0x00000020,
	ADCLI_DISCO_TIMESERV                = 0x00000040,
	ADCLI_DISCO_CLOSEST                 = 0x00000080,
	ADCLI_DISCO_WRITABLE                = 0x00000100,
	ADCLI_DISCO_GOOD_TIMESERV           = 0x00000200,
	ADCLI_DISCO_NDNC                    = 0x00000400,
	ADCLI_DISCO_SELECT_SECRET_DOMAIN_6  = 0x00000800,
	ADCLI_DISCO_FULL_SECRET_DOMAIN_6    = 0x00001000,
	ADCLI_DISCO_ADS_WEB_SERVICE         = 0x00002000,
	ADCLI_DISCO_HAS_DNS_NAME            = 0x20000000,
	ADCLI_DISCO_IS_DEFAULT_NC           = 0x40000000,
	ADCLI_DISCO_FOREST_ROOT             = 0x80000000
};

typedef struct _adcli_disco {
	unsigned int flags;
	char *forest;
	char *domain;
	char *domain_short;
	char *host_name;
	char *host_addr;
	char *host_short;
	char *client_site;
	char *server_site;
	struct _adcli_disco *next;
} adcli_disco;

int           adcli_disco_domain            (const char *domain,
                                             adcli_disco **disco);

int           adcli_disco_host              (const char *host,
                                             adcli_disco **disco);

void          adcli_disco_free              (adcli_disco *disco);

enum {
	ADCLI_DISCO_UNUSABLE = 0,
	ADCLI_DISCO_MAYBE = 1,
	ADCLI_DISCO_USABLE = 2
};

int           adcli_disco_usable            (adcli_disco *disco);

#endif /* ADDISCO_H_ */
