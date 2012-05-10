
#include "config.h"

#include "adenroll.h"
#include "adprivate.h"

#include <ldap.h>

#include <krb5/krb5.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

struct _adcli_enroll_ctx {

	/* Input/output params */
#if 0
	char *login_user;
	char *login_password;
	krb5_ccache login_ccache;
#endif
	char *domain_name;
	char *domain_realm;
	char **ldap_urls;
#if 0
	char *domain_netbios;
	char *naming_context;
#endif
	char *host_fqdn;
	char *host_netbios;
#if 0
	char *computer_ou;
	char *host_password;
	krb5_keytab host_keytab;
#endif

	adcli_message_func message_func;

	/* Enroll state */
	LDAP *ldap;
};

static void
enroll_err (adcli_enroll_ctx *enroll,
            const char *format,
            ...) GNUC_PRINTF(2, 3);

static void
enroll_err (adcli_enroll_ctx *enroll,
            const char *format,
            ...)
{
	va_list va;
	va_start (va, format);
	_adcli_messagev (enroll->message_func, ADCLI_MESSAGE_ERROR, format, va);
	va_end (va);
}

static void
enroll_warn (adcli_enroll_ctx *enroll,
             const char *format,
             ...) GNUC_PRINTF(2, 3);

static void
enroll_warn (adcli_enroll_ctx *enroll,
             const char *format,
             ...)
{
	va_list va;
	va_start (va, format);
	_adcli_messagev (enroll->message_func, ADCLI_MESSAGE_ERROR, format, va);
	va_end (va);
}

static void
enroll_info (adcli_enroll_ctx *enroll,
             const char *format,
             ...) GNUC_PRINTF(2, 3);

static void
enroll_info (adcli_enroll_ctx *enroll,
             const char *format,
             ...)
{
	va_list va;
	va_start (va, format);
	_adcli_messagev (enroll->message_func, ADCLI_MESSAGE_INFO, format, va);
	va_end (va);
}

static void
to_upper_case (char *str)
{
	while (*str != '\0') {
		*str = toupper (*str);
		str++;
	}
}

static adcli_result
enroll_ensure_host_fqdn (adcli_result res,
                         adcli_enroll_ctx *enroll)
{
	char hostname[HOST_NAME_MAX + 1];
	struct addrinfo hints;
	struct addrinfo *ai;
	int ret;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->host_fqdn) {
		enroll_info (enroll, "Using fully qualified name: %s", enroll->host_fqdn);
		return ADCLI_SUCCESS;
	}

	ret = gethostname (hostname, sizeof (hostname));
	if (ret < 0) {
		enroll_err (enroll, "Couldn't get local hostname: %s", strerror (errno));
		return ADCLI_ERR_SYSTEM;
	}

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME;
	ret = getaddrinfo (hostname, NULL, &hints, &ai);

	switch (ret) {
	case 0:
		if (ai->ai_canonname) {
			enroll_info (enroll, "Resolved local host name %s into "
			             "fully qualified name: %s", ai->ai_canonname,
			             hostname);
			enroll->host_fqdn = strdup (ai->ai_canonname);
			freeaddrinfo (ai);
			return enroll->host_fqdn ? ADCLI_SUCCESS : ADCLI_ERR_MEMORY;
		}
		freeaddrinfo (ai);
		/* fall through */

	case EAI_AGAIN:
	case EAI_FAIL:
	case EAI_NODATA:
	case EAI_NONAME:
		enroll_warn (enroll, "Couldn't find qualified domain name, "
		             "proceeding with local host name instead: %s%s%s",
		             hostname,
		             ret == 0 ? "" : ": ",
		             ret == 0 ? "" : gai_strerror (ret));
		enroll->host_fqdn = strdup (hostname);
		return enroll->host_fqdn ? ADCLI_SUCCESS : ADCLI_ERR_MEMORY;

	case EAI_MEMORY:
		return ADCLI_ERR_MEMORY;

	default:
		enroll_err (enroll, "Couldn't resolve host name: %s: %s",
		            hostname, gai_strerror (ret));
		return ADCLI_ERR_DNS;
	}

	assert (0 && "not reached");
}

static adcli_result
enroll_ensure_domain_and_host_netbios (adcli_result res,
                                       adcli_enroll_ctx *enroll)
{
	const char *dom;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->domain_name)
		enroll_info (enroll, "Using domain name: %s", enroll->domain_name);
	if (enroll->host_netbios)
		enroll_info (enroll, "Using host netbios name: %s", enroll->host_netbios);
	if (enroll->domain_name && enroll->host_netbios)
		return ADCLI_SUCCESS;

	assert (enroll->host_fqdn != NULL);

	/* Use the FQDN minus the last part */
	dom = strchr (enroll->host_fqdn, '.');

	/* If no dot, or dot is first or last, then fail */
	if (dom == NULL || dom == enroll->host_fqdn || dom[1] == '\0') {
		enroll_err (enroll, "Couldn't determine the domain name and "
		            "netbios name from host name: %s", enroll->host_fqdn);
		return ADCLI_ERR_DNS;
	}

	if (!enroll->domain_name) {
		enroll->domain_name = strdup (dom + 1);
		if (enroll->domain_name) {
			enroll_info (enroll, "Calculated domain name from host fqdn: %s",
			             enroll->domain_name);
		}
	}

	if (!enroll->host_netbios) {
		enroll->host_netbios = strndup (enroll->host_fqdn,
		                                dom - enroll->host_fqdn);
		if (enroll->host_netbios) {
			to_upper_case (enroll->host_netbios);
			enroll_info (enroll, "Calculated host netbios name from fqdn: %s",
			             enroll->host_netbios);
		}
	}

	return enroll->domain_name && enroll->host_netbios ?
			ADCLI_SUCCESS : ADCLI_ERR_MEMORY;
}

static adcli_result
enroll_ensure_domain_realm (adcli_result res,
                            adcli_enroll_ctx *enroll)
{
	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->domain_realm) {
		enroll_info (enroll, "Using domain realm: %s", enroll->domain_name);
		return ADCLI_SUCCESS;
	}

	enroll->domain_realm = strdup (enroll->domain_name);
	if (!enroll->domain_realm)
		return ADCLI_ERR_MEMORY;

	to_upper_case (enroll->domain_realm);
	enroll_info (enroll, "Calculated domain realm from name: %s",
	             enroll->domain_realm);
	return ADCLI_SUCCESS;
}

static adcli_result
srvinfo_to_ldap_urls (adcli_srvinfo *res,
                      char ***urls_out)
{
	adcli_srvinfo *srv;
	char **urls = NULL;
	int length = 0;
	char *url;

	for (srv = res; srv != NULL; srv = srv->next) {
		if (asprintf (&url, "ldap://%s:%u", srv->hostname,
		              (unsigned int)srv->port) < 0)
			break;
		urls = _adcli_strv_add (urls, url, &length);
		if (urls == NULL)
			break;
	}

	/* Early break? */
	if (srv != NULL) {
		_adcli_strv_free (urls);
		return ADCLI_ERR_MEMORY;
	}

	*urls_out = urls;
	return ADCLI_SUCCESS;
}

static adcli_result
enroll_ensure_ldap_urls (adcli_result res,
                         adcli_enroll_ctx *enroll)
{
	adcli_srvinfo *srv;
	char *rrname;
	char *string;
	int ret;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->ldap_urls) {
		if (enroll->message_func) {
			string = _adcli_strv_join (enroll->ldap_urls, " ");
			enroll_info (enroll, "Using LDAP urls: %s", string);
			free (string);
		}
		return ADCLI_SUCCESS;
	}

	if (asprintf (&rrname, "_ldap._tcp.%s", enroll->domain_name) < 0)
		return ADCLI_ERR_MEMORY;

	ret = _adcli_getsrvinfo (rrname, &srv);

	if (ret != 0) {
		enroll_err (enroll, "Couldn't resolve SRV record: %s: %s",
		            rrname, gai_strerror (ret));
		free (rrname);
		return ADCLI_ERR_DNS;
	}

	ret = srvinfo_to_ldap_urls (srv, &enroll->ldap_urls);
	_adcli_freesrvinfo (srv);

	if (ret == 0 && enroll->message_func) {
		string = _adcli_strv_join (enroll->ldap_urls, " ");
		enroll_info (enroll, "Resolved LDAP urls from SRV record: %s: %s",
		             rrname, string);
		free (string);
	}

	free (rrname);
	return ret;
}

static adcli_result
enroll_with_context (adcli_enroll_ctx *enroll)
{
	adcli_result result = ADCLI_SUCCESS;

	result = enroll_ensure_host_fqdn (result, enroll);
	result = enroll_ensure_domain_and_host_netbios (result, enroll);
	result = enroll_ensure_domain_realm (result, enroll);
	result = enroll_ensure_ldap_urls (result, enroll);

	/* - Create a valid password */

	/* - Login with creds, setup login ccache */

	/* - Connect to LDAP server */

	/* - Figure out the naming context */

	/* - Figure out the domain short name */

	/* - Search for computer account */

	/* - Update computer account or create */

	/* - Write out password to host keytab */

	return result;
}

static void
enroll_clear_state (adcli_enroll_ctx *enroll)
{
	if (enroll->ldap)
		ldap_unbind_ext_s (enroll->ldap, NULL, NULL);
	enroll->ldap = NULL;
}

adcli_result
adcli_enroll (const char *domain,
              adcli_enroll_ctx *enroll)
{
	adcli_enroll_ctx *allocated = NULL;
	adcli_result result = 0;

	if (enroll == NULL)
		enroll = allocated = adcli_enroll_ctx_new ();

	free (enroll->domain_name);
	enroll->domain_name = strdup (domain);
	if (enroll->domain_name == NULL)
		result = ADCLI_ERR_MEMORY;

	if (result == 0)
		result = enroll_with_context (enroll);

	enroll_clear_state (enroll);
	adcli_enroll_ctx_free (allocated);
	return result;
}

adcli_enroll_ctx *
adcli_enroll_ctx_new (void)
{
	return calloc (1, sizeof (adcli_enroll_ctx));
}

void
adcli_enroll_ctx_free (adcli_enroll_ctx *enroll)
{
	if (enroll == NULL)
		return;

	enroll_clear_state (enroll);

	free (enroll->domain_name);
	free (enroll->domain_realm);

	free (enroll->host_fqdn);
	free (enroll->host_netbios);

	_adcli_strv_free (enroll->ldap_urls);

	free (enroll);
}

adcli_result
adcli_enroll_set_message_func (adcli_enroll_ctx *enroll,
                               adcli_message_func message_func)
{
	enroll->message_func = message_func;
	return ADCLI_SUCCESS;
}

const char *
adcli_enroll_get_host_fqdn (adcli_enroll_ctx *enroll)
{
	return enroll->host_fqdn;
}

static adcli_result
set_enroll_string_value (char **field,
                         const char *value)
{
	char *newval = NULL;

	if (*field == value)
		return ADCLI_SUCCESS;

	if (value) {
		newval = strdup (value);
		if (newval == NULL)
			return ADCLI_ERR_MEMORY;
	}

	free (*field);
	*field = newval;

	return ADCLI_SUCCESS;
}

adcli_result
adcli_enroll_set_host_fqdn (adcli_enroll_ctx *enroll,
                            const char *value)
{
	return set_enroll_string_value (&enroll->host_fqdn, value);
}

const char *
adcli_enroll_get_domain_name (adcli_enroll_ctx *enroll)
{
	return enroll->domain_name;
}

const char *
adcli_enroll_get_domain_realm (adcli_enroll_ctx *enroll)
{
	return enroll->domain_realm;
}

adcli_result
adcli_enroll_set_domain_realm (adcli_enroll_ctx *enroll,
                               const char *value)
{
	return set_enroll_string_value (&enroll->domain_realm, value);
}

const char *
adcli_enroll_get_host_netbios (adcli_enroll_ctx *enroll)
{
	return enroll->host_netbios;
}

adcli_result
adcli_enroll_set_host_netbios (adcli_enroll_ctx *enroll,
                               const char *value)
{
	return set_enroll_string_value (&enroll->host_netbios, value);
}

const char **
adcli_enroll_get_ldap_urls (adcli_enroll_ctx *enroll)
{
	return (const char **)enroll->ldap_urls;
}

adcli_result
adcli_enroll_set_ldap_urls (adcli_enroll_ctx *enroll,
                            const char **value)
{
	char **newval = NULL;

	if (enroll->ldap_urls == (char **)value)
		return ADCLI_SUCCESS;

	if (value) {
		newval = _adcli_strv_dup ((char **)value);
		if (newval == NULL)
			return ADCLI_ERR_MEMORY;
	}

	_adcli_strv_free (enroll->ldap_urls);
	enroll->ldap_urls = newval;

	return ADCLI_SUCCESS;
}

adcli_result
adcli_enroll_add_ldap_url (adcli_enroll_ctx *enroll,
                           const char *value)
{
	char *newval;

	newval = strdup (value);
	if (newval == NULL)
		return ADCLI_ERR_MEMORY;

	enroll->ldap_urls = _adcli_strv_add (enroll->ldap_urls, newval, NULL);
	if (enroll->ldap_urls == NULL)
		return ADCLI_ERR_MEMORY;

	return ADCLI_SUCCESS;
}
