
#include "config.h"

#include "adcli.h"
#include "adprivate.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
	if ((*p) + 2 > end)
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
	if ((*p) + 4 > end)
		return 0;
	val = ns_get32 (*p);
	(*p) += 4;
	return val;
}

static int
parse_record (unsigned char *answer,
              unsigned char *p,
              unsigned char *end,
              adcli_srvinfo **res)
{
	adcli_srvinfo *srv;
	int n;

	/* Check that the below calls are sane */
	if (p + 8 > end)
		return 0;

	srv = calloc (1, sizeof (adcli_srvinfo));
	if (srv == NULL)
		return EAI_MEMORY;

	srv->priority = get_16 (&p, end);
	srv->weight = get_16 (&p, end);
	srv->port = get_16 (&p, end);
	n = dn_expand (answer, end, p, srv->hostname, sizeof (srv->hostname));

	if (n < 0) {
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
              adcli_srvinfo **res)
{
	adcli_srvinfo *results = NULL;
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
		if (n < 0 || p + n + 10 > end) {
			_adcli_freesrvinfo (results);
			return EAI_FAIL;
		}
		p += n;
		type = get_16 (&p, end);
		qclass = get_16 (&p, end);
		get_32 (&p, end); /* skip the ttl */
		rdlength = get_16 (&p, end);

		if (type == T_SRV && qclass == C_IN && p + rdlength <= end) {
			ret = parse_record (answer, p, end, &results);
			if (ret != 0) {
				_adcli_freesrvinfo (results);
				return ret;
			}
		}

		p += rdlength;
	}

	/* Note that we allow truncated results by not checking count */

	/* 'A Target of "." means that the service is decidedly not
	 * available at this domain.'
	 */
	if (results != NULL && results->next == NULL &&
	    strcmp (results->hostname, ".") == 0) {
		_adcli_freesrvinfo (results);
		return EAI_NONAME;
	}

	*res = results;
	return 0;
}

int
_adcli_getsrvinfo (const char *rrname,
                   adcli_srvinfo **res)
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

void
_adcli_freesrvinfo (adcli_srvinfo *res)
{
	adcli_srvinfo *next;

	while (res != NULL) {
		next = res->next;
		free (res);
		res = next;
	}
}
