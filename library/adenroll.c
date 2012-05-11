
#include "config.h"

#include "adenroll.h"
#include "adprivate.h"

#include <gssapi/gssapi_krb5.h>
#include <krb5/krb5.h>
#include <ldap.h>
#include <sasl/sasl.h>

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
	char *admin_name;
	char *admin_password;
	char *admin_ccache_name;
	int admin_ccache_name_is_krb5;

	adcli_password_func password_func;
	adcli_destroy_func password_destroy;
	void *password_data;

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
	adcli_destroy_func message_destroy;
	void *message_data;

	/* Enroll state */
	LDAP *ldap;
	krb5_context k5;
	krb5_ccache ccache;
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
	_adcli_messagev (enroll->message_func, enroll->message_data,
	                 ADCLI_MESSAGE_ERROR, format, va);
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
	_adcli_messagev (enroll->message_func, enroll->message_data,
	                 ADCLI_MESSAGE_ERROR, format, va);
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
	_adcli_messagev (enroll->message_func, enroll->message_data,
	                 ADCLI_MESSAGE_INFO, format, va);
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

static krb5_error_code
kinit_with_password_and_ccache (krb5_context k5,
                                const char *name,
                                const char *password,
                                krb5_ccache ccache)
{
	krb5_get_init_creds_opt *opt;
	krb5_principal principal;
	krb5_error_code code;
	krb5_creds creds;

	/* Parse that admin principal name */
	code = krb5_parse_name (k5, name, &principal);
	if (code != 0)
		return code;

	code = krb5_get_init_creds_opt_alloc (k5, &opt);
	if (code != 0) {
		krb5_free_principal (k5, principal);
		return code;
	}

	code = krb5_get_init_creds_opt_set_out_ccache (k5, opt, ccache);
	if (code != 0) {
		krb5_free_principal (k5, principal);
		krb5_get_init_creds_opt_free (k5, opt);
		return code;
	}

	code = krb5_get_init_creds_password (k5, &creds, principal,
	                                     (char *)password, NULL, 0,
	                                     0, NULL, opt);

	krb5_get_init_creds_opt_free (k5, opt);
	krb5_free_principal (k5, principal);

	if (code == 0)
		krb5_free_cred_contents (k5, &creds);

	return code;
}

static adcli_result
enroll_ensure_k5_ctx (adcli_enroll_ctx *enroll)
{
	krb5_error_code code;

	if (enroll->k5)
		return ADCLI_SUCCESS;

	code = krb5_init_context (&enroll->k5);
	if (code == ENOMEM) {
		return ADCLI_ERR_MEMORY;
	} else if (code != 0) {
		enroll_err (enroll, "Failed to create kerberos context: %s",
		            krb5_get_error_message (enroll->k5, code));
		return ADCLI_ERR_SYSTEM;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
enroll_ensure_admin_password (adcli_enroll_ctx *enroll)
{
	char *prompt;

	if (enroll->admin_ccache_name != NULL ||
	    enroll->admin_password != NULL)
		return ADCLI_SUCCESS;

	if (enroll->password_func) {
		if (asprintf (&prompt, "Password for %s: ",
		              adcli_enroll_get_admin_name (enroll)) < 0)
			return ADCLI_ERR_MEMORY;
		enroll->admin_password = (enroll->password_func) (prompt, enroll->password_data);
		free (prompt);
	}

	if (enroll->admin_password == NULL) {
		enroll_err (enroll, "No admin password or credential cache specified");
		return ADCLI_ERR_CREDENTIALS;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
enroll_prep_kerberos_and_kinit (adcli_enroll_ctx *enroll)
{
	krb5_error_code code;
	krb5_ccache ccache;
	adcli_result res;
	char *name;

	res = enroll_ensure_k5_ctx (enroll);
	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->admin_ccache_name != NULL)
		return ADCLI_SUCCESS;

	/* Build out the admin principal name */
	if (!enroll->admin_name) {
		if (asprintf (&enroll->admin_name, "Administrator@%s", enroll->domain_realm) < 0)
			return ADCLI_ERR_MEMORY;
	} else if (strchr (enroll->admin_name, '@') == NULL) {
		if (asprintf (&name, "%s@%s", enroll->admin_name, enroll->domain_realm) < 0)
			return ADCLI_ERR_MEMORY;
		free (enroll->admin_name);
		enroll->admin_name = name;
	}

	res = enroll_ensure_admin_password (enroll);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Initialize the credential cache */
	code = krb5_cc_new_unique (enroll->k5, "MEMORY", NULL, &ccache);
	if (code == ENOMEM) {
		return ADCLI_ERR_MEMORY;
	} else if (code != 0) {
		enroll_err (enroll, "Failed to create credential cache: %s",
		            krb5_get_error_message (enroll->k5, code));
		return ADCLI_ERR_SYSTEM;
	}

	code = kinit_with_password_and_ccache (enroll->k5, enroll->admin_name,
	                                       enroll->admin_password, ccache);

	if (code == 0) {
		code = krb5_cc_get_full_name (enroll->k5, ccache,
		                              &enroll->admin_ccache_name);
		if (code == 0) {
			enroll->ccache = ccache;
			enroll->admin_ccache_name_is_krb5 = 1;
			ccache = NULL;
			res = ADCLI_SUCCESS;
		} else if (code == ENOMEM) {
			res = ADCLI_ERR_MEMORY;
		} else {
			enroll_err (enroll, "Couldn't get credential cache name");
			res = ADCLI_ERR_SYSTEM;
		}
	} else if (code == ENOMEM) {
		res = ADCLI_ERR_MEMORY;
	} else {
		enroll_err (enroll, "Couldn't authenticate as admin: %s",
		            enroll->admin_name);
		res = ADCLI_ERR_CREDENTIALS;
	}

	if (ccache != NULL)
		krb5_cc_close (enroll->k5, ccache);
	return res;

}

static int
sasl_interact (LDAP *ld,
               unsigned flags,
               void *defaults,
               void *interact)
{
	sasl_interact_t *in = (sasl_interact_t *)interact;

	if (!ld) return LDAP_PARAM_ERROR;

	while (in->id != SASL_CB_LIST_END) {
		switch (in->id) {
		case SASL_CB_GETREALM:
		case SASL_CB_USER:
		case SASL_CB_PASS:
			if (in->defresult)
				in->result = in->defresult;
			else
				in->result = "";
			in->len = strlen (in->result);
			break;
		case SASL_CB_AUTHNAME:
			if (in->defresult)
				in->result = in->defresult;
			else
				in->result = "";
			in->len = strlen (in->result);
			break;
		case SASL_CB_NOECHOPROMPT:
		case SASL_CB_ECHOPROMPT:
			goto fail;
		}
		in++;
	}

	return LDAP_SUCCESS;

fail:
	return LDAP_UNAVAILABLE;
}

static adcli_result
enroll_connect_to_ldap (adcli_enroll_ctx *enroll)
{
	int res = -1;
	OM_uint32 status;
	OM_uint32 minor;
	char *info;
	LDAP *ldap;
	int ret;
	int ver;
	int i;

	if (enroll->ldap)
		return ADCLI_SUCCESS;

	for (i = 0; enroll->ldap_urls[i] != NULL; i++) {

		ver = LDAP_VERSION3;
		ret = ldap_initialize (&ldap, enroll->ldap_urls[i]);
		if (ret == 0)
			ret = ldap_set_option (ldap, LDAP_OPT_PROTOCOL_VERSION, &ver);
		if (ret != 0) {
			enroll_err (enroll, "Couldn't initialize LDAP connection for URL: %s: %s",
			            enroll->ldap_urls[i], ldap_err2string (ret));
			res = ADCLI_ERR_CONNECTION;
			continue;
		}

		status = gss_krb5_ccache_name (&minor, enroll->admin_ccache_name, NULL);

		/* TODO: Proper error reporting for GSSAPI */
		assert (status == 0);

		ret = ldap_sasl_interactive_bind_s (ldap, NULL, "GSSAPI", NULL, NULL,
		                                    LDAP_SASL_QUIET, sasl_interact, NULL);

		if (ret == LDAP_SUCCESS) {
			res = ADCLI_SUCCESS;
			enroll->ldap = ldap;
			break;
		}

		if (ldap_get_option(ldap, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void*)&info) != 0)
			info = NULL;

		ldap_unbind_ext_s (ldap, NULL, NULL);

		/* TODO: Proper error reporting for LDAP */
		assert (status == 0);

		if (ret == LDAP_AUTH_UNKNOWN) {
			enroll_err (enroll, "Couldn't log into LDAP server: %s: %s: %s",
			            enroll->ldap_urls[i], ldap_err2string (ret),
			            info);
			res = ADCLI_ERR_CREDENTIALS;

		} else {
			enroll_err (enroll, "Couldn't connect and login to LDAP server: %s: %s: %s",
			            enroll->ldap_urls[i], ldap_err2string (ret),
			            info);
			res = ADCLI_ERR_CONNECTION;
		}

		if (info != NULL)
			ldap_memfree (info);
	}

	return res;
}

static adcli_result
enroll_with_context (adcli_enroll_ctx *enroll)
{
	adcli_result res = ADCLI_SUCCESS;

	/* Basic discovery and figuring out enroll params */
	res = enroll_ensure_host_fqdn (res, enroll);
	res = enroll_ensure_domain_and_host_netbios (res, enroll);
	res = enroll_ensure_domain_realm (res, enroll);
	res = enroll_ensure_ldap_urls (res, enroll);

	if (res != ADCLI_SUCCESS)
		return res;

	/* TODO: Create a valid password */

	/* Login with admin credentials now, setup login ccache */
	res = enroll_prep_kerberos_and_kinit (enroll);
	if (res != ADCLI_SUCCESS)
		return res;

	/* - Connect to LDAP server */
	res = enroll_connect_to_ldap (enroll);
	if (res != ADCLI_SUCCESS)
		return res;

	/* - Figure out the naming context */

	/* - Figure out the domain short name */

	/* - Search for computer account */

	/* - Update computer account or create */

	/* - Write out password to host keytab */

	return res;
}

static void
enroll_clear_state (adcli_enroll_ctx *enroll)
{
	if (enroll->ldap)
		ldap_unbind_ext_s (enroll->ldap, NULL, NULL);
	enroll->ldap = NULL;

	if (enroll->ccache)
		krb5_cc_close (enroll->k5, enroll->ccache);
	enroll->ccache = NULL;

	if (enroll->k5)
		krb5_free_context (enroll->k5);
	enroll->k5 = NULL;
}

adcli_result
adcli_enroll (const char *domain,
              adcli_enroll_ctx *enroll)
{
	adcli_enroll_ctx *allocated = NULL;
	adcli_result result = 0;

	if (enroll == NULL)
		enroll = allocated = adcli_enroll_ctx_new ();

	enroll_clear_state (enroll);

	free (enroll->domain_name);
	enroll->domain_name = NULL;

	if (domain != NULL) {
		enroll->domain_name = strdup (domain);
		if (enroll->domain_name == NULL)
			result = ADCLI_ERR_MEMORY;
	}

	if (result == 0)
		result = enroll_with_context (enroll);

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

	free (enroll->domain_name);
	free (enroll->domain_realm);

	free (enroll->host_fqdn);
	free (enroll->host_netbios);

	adcli_enroll_set_admin_name (enroll, NULL);
	adcli_enroll_set_admin_password (enroll, NULL);
	adcli_enroll_set_admin_password_func (enroll, NULL, NULL, NULL);

	enroll_clear_state (enroll);
	_adcli_strv_free (enroll->ldap_urls);

	free (enroll);
}

adcli_result
adcli_enroll_set_message_func (adcli_enroll_ctx *enroll,
                               adcli_message_func message_func,
                               void *data,
                               adcli_destroy_func destroy_data)
{
	if (enroll->message_destroy)
		(enroll->message_destroy) (enroll->message_data);
	enroll->message_func = message_func;
	enroll->message_destroy = destroy_data;
	enroll->message_data = data;
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

const char *
adcli_enroll_get_admin_name (adcli_enroll_ctx *enroll)
{
	return enroll->admin_name;
}

adcli_result
adcli_enroll_set_admin_name (adcli_enroll_ctx *enroll,
                             const char *value)
{
	return set_enroll_string_value (&enroll->admin_name, value);
}

const char *
adcli_enroll_get_admin_password (adcli_enroll_ctx *enroll)
{
	return enroll->admin_password;
}

adcli_result
adcli_enroll_set_admin_password (adcli_enroll_ctx *enroll,
                                 const char *value)
{
	return set_enroll_string_value (&enroll->admin_password, value);
}

adcli_result
adcli_enroll_set_admin_password_func (adcli_enroll_ctx *enroll,
                                      adcli_password_func password_func,
                                      void *data,
                                      adcli_destroy_func destroy_data)
{
	if (enroll->password_destroy)
		(enroll->password_destroy) (enroll->password_data);
	enroll->password_func = password_func;
	enroll->password_data = data;
	enroll->password_destroy = destroy_data;
	return ADCLI_SUCCESS;
}

krb5_ccache
adcli_enroll_get_admin_ccache (adcli_enroll_ctx *enroll)
{
	return enroll->ccache;
}

const char *
adcli_enroll_get_admin_ccache_name (adcli_enroll_ctx *enroll)
{
	return enroll->admin_ccache_name;
}

adcli_result
adcli_enroll_set_admin_ccache_name (adcli_enroll_ctx *enroll,
                                    const char *ccname)
{
	char *newval = NULL;

	if (ccname == enroll->admin_ccache_name)
		return ADCLI_SUCCESS;

	if (ccname) {
		newval = strdup (ccname);
		if (newval == NULL)
			return ADCLI_ERR_MEMORY;
	}

	if (enroll->admin_ccache_name) {
		if (enroll->admin_ccache_name_is_krb5)
			krb5_free_string (enroll->k5, enroll->admin_ccache_name);
		else
			free (enroll->admin_ccache_name);
	}

	if (enroll->ccache) {
		krb5_cc_close (enroll->k5, enroll->ccache);
		enroll->ccache = NULL;
	}

	enroll->admin_ccache_name = newval;
	enroll->admin_ccache_name_is_krb5 = 0;
	return ADCLI_SUCCESS;
}
