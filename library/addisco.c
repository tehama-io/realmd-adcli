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

#include "config.h"

#include "adcli.h"
#include "adprivate.h"
#include "addisco.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <assert.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Number of servers to do discovery against */
#define DISCO_COUNT 5

/* The time period in which to do rapid requests */
#define DISCO_FEVER  1

/* Discovery timeout in seconds */
#define DISCO_TIME  15

/* Type of LDAP to use for discovery */
#define DISCO_SCHEME "cldap"

typedef struct _srvinfo {
	unsigned short priority;
	unsigned short weight;
	unsigned short port;
	char *hostname;
	struct _srvinfo *next;
} srvinfo;

static void
freesrvinfo (srvinfo *res)
{
	srvinfo *next;

	while (res != NULL) {
		next = res->next;
		free (res->hostname);
		free (res);
		res = next;
	}
}

static int
perform_query (const char *rrname,
               unsigned char **answer,
               int *length)
{
	unsigned char *ans = NULL;
	unsigned char *mem;
	int len = 512;
	int herr;
	int ret;

	for (;;) {
		len *= 2;
		mem = realloc (ans, len);
		if (mem == NULL) {
			free (ans);
			return EAI_MEMORY;
		}

		ans = mem;
		ret = res_query (rrname, C_IN, T_SRV, ans, len);

		/* If answer fit in the buffer then we're done */
		if (ret < 0 || ret < len) {
			len = ret;
			break;
		}

		/*
		 * On overflow some res_query's return the length needed, others
		 * return the full length entered. This code works in either case.
		 */
	}

	herr = h_errno;
	if (len <= 0) {
		free (ans);
		if (len == 0 || herr == HOST_NOT_FOUND || herr == NO_DATA)
			return EAI_NONAME;
		else if (herr == TRY_AGAIN)
			return EAI_AGAIN;
		else
			return EAI_FAIL;
	} else {
		*answer = ans;
		*length = len;
		return 0;
	}
}

static unsigned short
get_16 (unsigned char **p,
        unsigned char *end)
{
	unsigned short val;
	if (end - (*p) < 2)
		return 0;
	val = ns_get16 (*p);
	(*p) += 2;
	return val;
}

static unsigned long
get_32 (unsigned char **p,
        unsigned char *end)
{
	unsigned long val;
	if (end - (*p) < 4)
		return 0;
	val = ns_get32 (*p);
	(*p) += 4;
	return val;
}

static char *
get_string (unsigned char *beg,
            unsigned char *end,
            unsigned char **at)
{
	char buffer[HOST_NAME_MAX];
	int n;

	n = dn_expand (beg, end, *at, buffer, sizeof (buffer));
	if (n < 0)
		return NULL;

	(*at) += n;
	return strdup (buffer);
}

static int
parse_record (unsigned char *answer,
              unsigned char *p,
              unsigned char *end,
              srvinfo **res)
{
	srvinfo *srv;

	/* Check that the below calls are sane */
	if (end - p < 8)
		return 0;

	srv = calloc (1, sizeof (srvinfo));
	if (srv == NULL)
		return EAI_MEMORY;

	srv->priority = get_16 (&p, end);
	srv->weight = get_16 (&p, end);
	srv->port = get_16 (&p, end);
	srv->hostname = get_string (answer, end, &p);

	if (!srv->hostname) {
		free (srv);
		return EAI_FAIL;
	}

	/* This is not perfect RFC 2782 sorting */

	while (*res != NULL) {
		if (srv->priority == (*res)->priority) {
			/* Just sort zero weights first */
			if (!!srv->weight > !!((*res)->weight))
				break;
		} else if (srv->priority > (*res)->priority) {
			break;
		}
		res = &((*res)->next);
	}

	srv->next = *res;
	*res = srv;

	return 0;
}

static int
parse_answer (unsigned char *answer,
              int length,
              srvinfo **res)
{
	srvinfo *results = NULL;
	unsigned char *p, *end;
	unsigned short type, qclass, rdlength;
	HEADER *header;
	int count;
	int ret;
	int n;

	header = (HEADER *)answer;
	p = answer + sizeof (HEADER);
	end = answer + length;

	if (p > end)
		return EAI_FAIL;

	/* Skip query */
	count = ntohs (header->qdcount);
	while (count-- && p < end) {
		n = dn_skipname (p, end);
		if (n < 0)
			return EAI_FAIL;
		p += (n + 4);
	}

	if (count >= 0)
		return EAI_FAIL;

	/* Read answers */
	count = ntohs (header->ancount);
	while (count-- && p < end) {
		n = dn_skipname (p, end);
		if (n < 0 || (end - p) < (n + 10)) {
			freesrvinfo (results);
			return EAI_FAIL;
		}
		p += n;
		type = get_16 (&p, end);
		qclass = get_16 (&p, end);
		get_32 (&p, end); /* skip the ttl */
		rdlength = get_16 (&p, end);

		if (type == T_SRV && qclass == C_IN && (end - p) >=  rdlength) {
			ret = parse_record (answer, p, end, &results);
			if (ret != 0) {
				freesrvinfo (results);
				return ret;
			}
		}

		p += rdlength;
	}

	/* Note that we allow truncated results by not checking count */

	/* 'A Target of "." means that the service is decidedly not
	 * available at this domain.'
	 */
	if (results == NULL ||
	    (results->next == NULL &&
	     strcmp (results->hostname, ".") == 0)) {
		freesrvinfo (results);
		return EAI_NONAME;
	}

	*res = results;
	return 0;
}

static int
getsrvinfo (const char *rrname,
            srvinfo **res)
{
	unsigned char *answer;
	int length;
	int ret;

	ret = perform_query (rrname, &answer, &length);
	if (ret != 0)
		return ret;

	ret = parse_answer (answer, length, res);
	free (answer);

	return ret;
}

static int
parse_disco_string (unsigned char *beg,
                    unsigned char *end,
                    unsigned char **at,
                    char **result)
{
	char *string;

	assert (result);

	string = get_string (beg, end, at);
	if (string == NULL)
		return 0;

	free (*result);
	*result = string;

	return 1;
}

static int
get_32_le (unsigned char **at,
           unsigned char *end,
           unsigned int *val)
{
	unsigned char *p = *at;
	if (end - p < 4)
		return 0;
	*val = p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
	(*at) += 4;
	return 1;
}

static int
skip_n (unsigned char **at,
        unsigned char *end,
        int n)
{
	if (end - (*at) < n)
		return 0;
	(*at) += n;
	return 1;
}

static adcli_disco *
parse_disco_data (struct berval *bv)
{
	unsigned char *at, *end, *beg;
	unsigned int type;
	adcli_disco *disco;
	char *user = NULL;

	beg = (unsigned char *)bv->bv_val;
	end = beg + bv->bv_len;
	at = beg;

	disco = calloc (1, sizeof (adcli_disco));
	return_val_if_fail (disco != NULL, NULL);

	/* domain forest */
	if (!get_32_le (&at, end, &type) || type != 23 ||
	    !get_32_le (&at, end, &disco->flags) ||
	    !skip_n (&at, end, 16) || /* guid */
	    !parse_disco_string (beg, end, &at, &disco->forest) ||
	    !parse_disco_string (beg, end, &at, &disco->domain) ||
	    !parse_disco_string (beg, end, &at, &disco->host_name) ||
	    !parse_disco_string (beg, end, &at, &disco->domain_short) ||
	    !parse_disco_string (beg, end, &at, &disco->host_short) ||
	    !parse_disco_string (beg, end, &at, &user) ||
	    !parse_disco_string (beg, end, &at, &disco->server_site) ||
	    !parse_disco_string (beg, end, &at, &disco->client_site)) {
		_adcli_warn ("Could not parse NetLogon discovery data");
		adcli_disco_free (disco);
		disco = NULL;
	} else {
		_adcli_info ("Received NetLogon info from: %s", disco->host_name);
	}

	/* We don't care about these */
	free (user);
	return disco;
}

static int
insert_disco_sorted (adcli_disco **res,
                     adcli_disco *disco,
                     int usability,
                     int unique)
{
	adcli_disco **at = NULL;

	/* Sort in order of usability of this disco record */
	while (*res != NULL) {
		if (unique && strcasecmp (disco->host_name, (*res)->host_name) == 0)
			return 0;
		if (!at && usability > adcli_disco_usable (*res))
			at = res;
		if (at && !unique)
			break;
		res = &((*res)->next);
	}

	if (at == NULL)
		at = res;

	disco->next = *at;
	*at = disco;
	return 1;
}

static int
parse_disco (LDAP *ldap,
             const char *host_addr,
             LDAPMessage *message,
             adcli_disco **res)
{
	adcli_disco *disco = NULL;
	LDAPMessage *entry;
	struct berval **bvs;
	int usability;

	entry = ldap_first_entry (ldap, message);
	if (entry != NULL) {
		bvs = ldap_get_values_len (ldap, entry, "NetLogon");
		if (bvs != NULL) {
			if (!bvs[0])
				disco = NULL;
			else
				disco = parse_disco_data (bvs[0]);
			ldap_value_free_len (bvs);
		}
	}

	if (!disco)
		return ADCLI_DISCO_UNUSABLE;

	disco->host_addr = strdup (host_addr);
	return_val_if_fail (disco, ADCLI_DISCO_UNUSABLE);

	usability = adcli_disco_usable (disco);
	if (!insert_disco_sorted (res, disco, usability, 0))
		assert (0 && "not reached");
	return usability;
}

static int
ldap_disco (const char *domain,
            srvinfo *srv,
            adcli_disco **results)
{
	char *attrs[] = { "NetLogon", NULL };
	LDAP *ldap[DISCO_COUNT];
	const char *addrs[DISCO_COUNT];
	int found = ADCLI_DISCO_UNUSABLE;
	LDAPMessage *message;
	char buffer[1024];
	struct addrinfo hints;
	struct addrinfo *res, *ai;
	const char *scheme;
	int msgidp;
	int version;
	time_t started;
	time_t now;
	char *url;
	char *filter;
	char *value;
	int num, i;
	int ret;
	int have_any = 0;

	if (domain) {
		value = _adcli_ldap_escape_filter (domain);
		return_val_if_fail (value != NULL, 0);
		if (asprintf (&filter, "(&(DnsDomain=%s)(NtVer=\\06\\00\\00\\00))", value) < 0)
			return_val_if_reached (0);
		free (value);
	} else {
		if (asprintf (&filter, "(&(NtVer=\\06\\00\\00\\00)(AAC=\\00\\00\\00\\00))") < 0)
			return_val_if_reached (0);
	}

	memset (addrs, 0, sizeof (addrs));
	memset (ldap, 0, sizeof (ldap));

	/* Make sure cldap is supported, it's not always built into openldap */
	if (ldap_is_ldap_url (DISCO_SCHEME "://hostname"))
		scheme = DISCO_SCHEME;
	else
		scheme = "ldap";

	/*
	 * The ai_socktype and ai_protocol hint fields are unused below,
	 * but are set in order to prevent duplicate returns from
	 * getaddrinfo().
	 */
	memset (&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags |= AI_NUMERICSERV;
#ifdef AI_ADDRCONFIG
	hints.ai_flags |= AI_ADDRCONFIG;
#endif

	for (num = 0; srv != NULL; srv = srv->next) {
		ret = getaddrinfo (srv->hostname, "389", &hints, &res);
		if (ret != 0) {
			_adcli_warn ("Couldn't resolve server host: %s: %s",
			             srv->hostname, gai_strerror (ret));
			continue;
		}

		for (ai = res; num < DISCO_COUNT && ai != NULL; ai  = ai->ai_next) {
			if (getnameinfo (ai->ai_addr, ai->ai_addrlen, buffer, sizeof (buffer),
			                 NULL, 0, NI_NUMERICHOST) != 0)
				return_val_if_reached (0);
			if (ai->ai_family == AF_INET6) {
				/*
				 * Currently openldap has cldap bugs when used with IPv6:
				 * http://www.openldap.org/its/index.cgi/Incoming?id=7694
				 */
				if (asprintf (&url, "%s://[%s]", "ldap", buffer) < 0)
					return_val_if_reached (0);
			} else {
				if (asprintf (&url, "%s://%s", scheme, buffer) < 0)
					return_val_if_reached (0);
			}

			ret = ldap_initialize (&ldap[num], url);
			if (ret == LDAP_SUCCESS) {
				version = LDAP_VERSION3;
				ldap_set_option (ldap[num], LDAP_OPT_PROTOCOL_VERSION, &version);
				ldap_set_option (ldap[num], LDAP_OPT_REFERRALS , 0);
				_adcli_info ("Sending netlogon pings to domain controller: %s", url);
				addrs[num] = srv->hostname;
				have_any = 1;
				num++;

			} else {
				_adcli_err ("Couldn't perform discovery on server: %s: %s", url, ldap_err2string (ret));
			}

			free (url);
		}

		freeaddrinfo (res);
	}

	/* Wait for the first response. Poor mans fd watch */
	for (started = now = time (NULL);
	     have_any && found != ADCLI_DISCO_USABLE && now < started + DISCO_TIME;
	     now = time (NULL)) {

		struct timeval tvpoll = { 0, 0 };
		struct timeval interval;

		/* If in the initial period, send feverishly */
		if (now < started + DISCO_FEVER) {
			interval.tv_sec = 0;
			interval.tv_usec = 100 * 1000;
		} else {
			interval.tv_sec = 1;
			interval.tv_usec = 0;
		}

		select (0, NULL, NULL, NULL, &interval);

		have_any = 0;
		for (i = 0; found != ADCLI_DISCO_USABLE && i < num; i++) {
			int close_ldap;
			int parsed;

			if (ldap[i] == NULL)
				continue;

			ret = 0;
			have_any = 1;
			switch (ldap_result (ldap[i], LDAP_RES_ANY, 1, &tvpoll, &message)) {
			case LDAP_RES_SEARCH_ENTRY:
			case LDAP_RES_SEARCH_RESULT:
				parsed = parse_disco (ldap[i], addrs[i], message, results);
				if (parsed > found)
					found = parsed;
				ldap_msgfree (message);
				close_ldap = 1;
				break;
			case 0:
				ret = ldap_search_ext (ldap[i], "", LDAP_SCOPE_BASE,
				                       filter, attrs, 0, NULL, NULL, NULL,
				                       -1, &msgidp);
				close_ldap = (ret != 0);
				break;
			case -1:
				ldap_get_option (ldap[i], LDAP_OPT_RESULT_CODE, &ret);
				close_ldap = 1;
				break;
			default:
				ldap_msgfree (message);
				close_ldap = 0;
				break;
			}

			if (ret != LDAP_SUCCESS) {
				_adcli_ldap_handle_failure (ldap[i], ADCLI_ERR_CONFIG,
				                            "Couldn't perform discovery search");
			}

			/* Done with this connection */
			if (close_ldap) {
				ldap_unbind_ext_s (ldap[i], NULL, NULL);
				ldap[i] = NULL;
			}
		}
	}

	for (i = 0; i < num; i++) {
		if (ldap[i] != NULL)
			ldap_unbind_ext_s (ldap[i], NULL, NULL);
	}

	free (filter);
	return found;
}

static void
fill_disco (adcli_disco **results,
            int usability,
            const char *domain,
            const char *site,
            srvinfo *srv)
{
	adcli_disco *disco;

	while (srv != NULL) {
		disco = calloc (1, sizeof (adcli_disco));
		return_if_fail (disco != NULL);
		disco->client_site = site ? strdup (site) : NULL;
		disco->server_site = site ? strdup (site) : NULL;
		disco->domain = strdup (domain);
		disco->host_name = strdup (srv->hostname);
		disco->host_addr = strdup (srv->hostname);
		if (!insert_disco_sorted (results, disco, usability, 1))
			adcli_disco_free (disco);
		srv = srv->next;
	}
}

static int
site_disco (adcli_disco *disco,
            adcli_disco **results)
{
	srvinfo *srv;
	char *rrname;
	int found;
	int ret;

	if (!disco->client_site || !disco->domain)
		return ADCLI_DISCO_MAYBE;

	if (asprintf (&rrname, "_ldap._tcp.%s._sites.dc._msdcs.%s",
	              disco->client_site, disco->domain) < 0)
		return_val_if_reached (ADCLI_DISCO_UNUSABLE);

	_adcli_info ("Discovering site domain controllers: %s", rrname);

	ret = getsrvinfo (rrname, &srv);
	switch (ret) {
	case 0:
		break;

	case EAI_NONAME:
	case EAI_AGAIN:
		_adcli_err ("No LDAP SRV site records: %s: %s",
		            rrname, gai_strerror (ret));
		break;

	default:
		_adcli_err ("Couldn't resolve SRV site records: %s: %s",
		            rrname, gai_strerror (ret));
		break;
	}

	free (rrname);

	if (ret != 0)
		return ADCLI_DISCO_MAYBE;

	/*
	 * Now that we have discovered the site domain controllers do a
	 * second round of cldap discovery.
	 */
	found = ldap_disco (disco->domain, srv, results);

	fill_disco (results, ADCLI_DISCO_MAYBE,
	            disco->domain, disco->client_site, srv);

	freesrvinfo (srv);

	return found;
}

int
adcli_disco_domain (const char *domain,
                    adcli_disco **results)
{
	char *rrname;
	srvinfo *srv;
	int found;
	int ret;

	return_unexpected_if_fail (domain != NULL);
	return_unexpected_if_fail (results != NULL);

	*results = NULL;

	if (asprintf (&rrname, "_ldap._tcp.%s", domain) < 0)
		return_unexpected_if_reached ();

	_adcli_info ("Discovering domain controllers: %s", rrname);

	ret = getsrvinfo (rrname, &srv);
	switch (ret) {
	case 0:
		break;

	case EAI_NONAME:
	case EAI_AGAIN:
		_adcli_err ("No LDAP SRV records for domain: %s: %s",
		            rrname, gai_strerror (ret));
		break;

	default:
		_adcli_err ("Couldn't resolve SRV record: %s: %s",
		            rrname, gai_strerror (ret));
		break;
	}

	free (rrname);
	if (ret != 0)
		return 0;

	found = ldap_disco (domain, srv, results);
	if (found == ADCLI_DISCO_MAYBE) {
		assert (*results);
		found = site_disco (*results, results);
	}

	fill_disco (results, ADCLI_DISCO_MAYBE, domain, NULL, srv);
	freesrvinfo (srv);

	return found;
}

int
adcli_disco_host (const char *host,
                  adcli_disco **results)
{
	srvinfo srv;

	return_val_if_fail (host != NULL, 0);
	return_val_if_fail (results != NULL, 0);

	*results = NULL;

	memset (&srv, 0, sizeof (srv));
	srv.hostname = (char *)host;

	return ldap_disco (NULL, &srv, results);
}

void
adcli_disco_free (adcli_disco *disco)
{
	adcli_disco *next;

	for (; disco != NULL; disco = next) {
		next = disco->next;
		free (disco->host_addr);
		free (disco->host_name);
		free (disco->host_short);
		free (disco->forest);
		free (disco->domain);
		free (disco->domain_short);
		free (disco->client_site);
		free (disco->server_site);
		free (disco);
	}
}

int
adcli_disco_usable (adcli_disco *disco)
{
	return_val_if_fail (disco != NULL, ADCLI_DISCO_UNUSABLE);

	if (disco->flags != 0) {
		if ((disco->flags & (ADCLI_DISCO_KDC | ADCLI_DISCO_LDAP | ADCLI_DISCO_WRITABLE)) == 0)
			return ADCLI_DISCO_UNUSABLE;
	}

	if (disco->client_site && disco->server_site &&
	    strcasecmp (disco->client_site, disco->server_site) == 0)
		return ADCLI_DISCO_USABLE;

	return ADCLI_DISCO_MAYBE;
}
