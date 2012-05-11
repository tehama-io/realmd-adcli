
#include "config.h"

#include "adcli.h"
#include "adprivate.h"

#include <gssapi/gssapi_krb5.h>
#include <krb5/krb5.h>
#include <ldap.h>
#include <sasl/sasl.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct _adcli_conn_ctx {
	int refs;

	/* Input/output params */
	char *admin_name;
	char *admin_password;
	char *admin_ccache_name;
	int admin_ccache_name_is_krb5;

	adcli_password_func password_func;
	adcli_destroy_func password_destroy;
	void *password_data;

	char *host_fqdn;
	char *domain_name;
	char *domain_realm;
	char **ldap_urls;
	char *naming_context;

	adcli_message_func message_func;
	adcli_destroy_func message_destroy;
	void *message_data;

	/* Enroll state */
	LDAP *ldap;
	int ldap_authenticated;
	krb5_context k5;
	krb5_ccache ccache;
};

static void
messagev (adcli_message_func func,
          void *message_data,
          adcli_message_type type,
          const char *format,
          va_list va)
{
	char buffer[2048];
	int ret;

	if (func == NULL)
		return;

	ret = vsnprintf (buffer, sizeof (buffer), format, va);
	if (ret > 0)
		(func) (type, buffer, message_data);
}

void
_adcli_err (adcli_conn *conn,
            const char *format,
            ...)
{
	va_list va;
	va_start (va, format);
	messagev (conn->message_func, conn->message_data,
	          ADCLI_MESSAGE_ERROR, format, va);
	va_end (va);
}

void
_adcli_warn (adcli_conn *conn,
             const char *format,
             ...)
{
	va_list va;
	va_start (va, format);
	messagev (conn->message_func, conn->message_data,
	          ADCLI_MESSAGE_ERROR, format, va);
	va_end (va);
}

void
_adcli_info (adcli_conn *conn,
             const char *format,
             ...)
{
	va_list va;
	va_start (va, format);
	messagev (conn->message_func, conn->message_data,
	          ADCLI_MESSAGE_INFO, format, va);
	va_end (va);
}

static adcli_result
ensure_host_fqdn (adcli_result res,
                  adcli_conn *conn)
{
	char hostname[HOST_NAME_MAX + 1];
	struct addrinfo hints;
	struct addrinfo *ai;
	int ret;

	if (res != ADCLI_SUCCESS)
		return res;

	if (conn->host_fqdn) {
		_adcli_info (conn, "Using fully qualified name: %s", conn->host_fqdn);
		return ADCLI_SUCCESS;
	}

	ret = gethostname (hostname, sizeof (hostname));
	if (ret < 0) {
		_adcli_err (conn, "Couldn't get local hostname: %s", strerror (errno));
		return ADCLI_ERR_SYSTEM;
	}

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME;
	ret = getaddrinfo (hostname, NULL, &hints, &ai);

	switch (ret) {
	case 0:
		if (ai->ai_canonname) {
			_adcli_info (conn, "Resolved local host name %s into "
			             "fully qualified name: %s", ai->ai_canonname,
			             hostname);
			conn->host_fqdn = strdup (ai->ai_canonname);
			freeaddrinfo (ai);
			return conn->host_fqdn ? ADCLI_SUCCESS : ADCLI_ERR_MEMORY;
		}
		freeaddrinfo (ai);
		/* fall through */

	case EAI_AGAIN:
	case EAI_FAIL:
	case EAI_NODATA:
	case EAI_NONAME:
		_adcli_warn (conn, "Couldn't find qualified domain name, "
		             "proceeding with local host name instead: %s%s%s",
		             hostname,
		             ret == 0 ? "" : ": ",
		             ret == 0 ? "" : gai_strerror (ret));
		conn->host_fqdn = strdup (hostname);
		return conn->host_fqdn ? ADCLI_SUCCESS : ADCLI_ERR_MEMORY;

	case EAI_MEMORY:
		return ADCLI_ERR_MEMORY;

	default:
		_adcli_err (conn, "Couldn't resolve host name: %s: %s",
		            hostname, gai_strerror (ret));
		return ADCLI_ERR_DNS;
	}

	assert (0 && "not reached");
}

static adcli_result
ensure_domain_and_host_netbios (adcli_result res,
                                adcli_conn *conn)
{
	const char *dom;

	if (res != ADCLI_SUCCESS)
		return res;

	if (conn->domain_name) {
		_adcli_info (conn, "Using domain name: %s", conn->domain_name);
		return ADCLI_SUCCESS;
	}

	assert (conn->host_fqdn != NULL);

	/* Use the FQDN minus the last part */
	dom = strchr (conn->host_fqdn, '.');

	/* If no dot, or dot is first or last, then fail */
	if (dom == NULL || dom == conn->host_fqdn || dom[1] == '\0') {
		_adcli_err (conn, "Couldn't determine the domain name from host name: %s",
		            conn->host_fqdn);
		return ADCLI_ERR_DNS;
	}

	conn->domain_name = strdup (dom + 1);
	if (conn->domain_name) {
		_adcli_info (conn, "Calculated domain name from host fqdn: %s",
		             conn->domain_name);
	}

	return conn->domain_name ? ADCLI_SUCCESS : ADCLI_ERR_MEMORY;
}

static adcli_result
ensure_domain_realm (adcli_result res,
                     adcli_conn *conn)
{
	if (res != ADCLI_SUCCESS)
		return res;

	if (conn->domain_realm) {
		_adcli_info (conn, "Using domain realm: %s", conn->domain_name);
		return ADCLI_SUCCESS;
	}

	conn->domain_realm = strdup (conn->domain_name);
	if (!conn->domain_realm)
		return ADCLI_ERR_MEMORY;

	_adcli_strup (conn->domain_realm);
	_adcli_info (conn, "Calculated domain realm from name: %s",
	             conn->domain_realm);
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
ensure_ldap_urls (adcli_result res,
                  adcli_conn *conn)
{
	adcli_srvinfo *srv;
	char *rrname;
	char *string;
	int ret;

	if (res != ADCLI_SUCCESS)
		return res;

	if (conn->ldap_urls) {
		if (conn->message_func) {
			string = _adcli_strv_join (conn->ldap_urls, " ");
			_adcli_info (conn, "Using LDAP urls: %s", string);
			free (string);
		}
		return ADCLI_SUCCESS;
	}

	if (asprintf (&rrname, "_ldap._tcp.%s", conn->domain_name) < 0)
		return ADCLI_ERR_MEMORY;

	ret = _adcli_getsrvinfo (rrname, &srv);

	if (ret != 0) {
		_adcli_err (conn, "Couldn't resolve SRV record: %s: %s",
		            rrname, gai_strerror (ret));
		free (rrname);
		return ADCLI_ERR_DNS;
	}

	ret = srvinfo_to_ldap_urls (srv, &conn->ldap_urls);
	_adcli_freesrvinfo (srv);

	if (ret == 0 && conn->message_func) {
		string = _adcli_strv_join (conn->ldap_urls, " ");
		_adcli_info (conn, "Resolved LDAP urls from SRV record: %s: %s",
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
ensure_k5_ctx (adcli_conn *conn)
{
	krb5_error_code code;

	if (conn->k5)
		return ADCLI_SUCCESS;

	code = krb5_init_context (&conn->k5);
	if (code == ENOMEM) {
		return ADCLI_ERR_MEMORY;
	} else if (code != 0) {
		_adcli_err (conn, "Failed to create kerberos conn: %s",
		            krb5_get_error_message (conn->k5, code));
		return ADCLI_ERR_SYSTEM;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
ensure_admin_password (adcli_conn *conn)
{
	char *prompt;

	if (conn->admin_ccache_name != NULL ||
	    conn->admin_password != NULL)
		return ADCLI_SUCCESS;

	if (conn->password_func) {
		if (asprintf (&prompt, "Password for %s: ", conn->admin_name) < 0)
			return ADCLI_ERR_MEMORY;
		conn->admin_password = (conn->password_func) (prompt, conn->password_data);
		free (prompt);
	}

	if (conn->admin_password == NULL) {
		_adcli_err (conn, "No admin password or credential cache specified");
		return ADCLI_ERR_CREDENTIALS;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
prep_kerberos_and_kinit (adcli_conn *conn)
{
	krb5_error_code code;
	krb5_ccache ccache;
	adcli_result res;
	char *name;

	res = ensure_k5_ctx (conn);
	if (res != ADCLI_SUCCESS)
		return res;

	if (conn->admin_ccache_name != NULL)
		return ADCLI_SUCCESS;

	/* Build out the admin principal name */
	if (!conn->admin_name) {
		if (asprintf (&conn->admin_name, "Administrator@%s", conn->domain_realm) < 0)
			return ADCLI_ERR_MEMORY;
	} else if (strchr (conn->admin_name, '@') == NULL) {
		if (asprintf (&name, "%s@%s", conn->admin_name, conn->domain_realm) < 0)
			return ADCLI_ERR_MEMORY;
		free (conn->admin_name);
		conn->admin_name = name;
	}

	res = ensure_admin_password (conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Initialize the credential cache */
	code = krb5_cc_new_unique (conn->k5, "MEMORY", NULL, &ccache);
	if (code == ENOMEM) {
		return ADCLI_ERR_MEMORY;
	} else if (code != 0) {
		_adcli_err (conn, "Failed to create credential cache: %s",
		            krb5_get_error_message (conn->k5, code));
		return ADCLI_ERR_SYSTEM;
	}

	code = kinit_with_password_and_ccache (conn->k5, conn->admin_name,
	                                       conn->admin_password, ccache);

	if (code == 0) {
		code = krb5_cc_get_full_name (conn->k5, ccache,
		                              &conn->admin_ccache_name);
		if (code == 0) {
			conn->ccache = ccache;
			conn->admin_ccache_name_is_krb5 = 1;
			ccache = NULL;
			res = ADCLI_SUCCESS;
		} else if (code == ENOMEM) {
			res = ADCLI_ERR_MEMORY;
		} else {
			_adcli_err (conn, "Couldn't get credential cache name");
			res = ADCLI_ERR_SYSTEM;
		}
	} else if (code == ENOMEM) {
		res = ADCLI_ERR_MEMORY;
	} else {
		_adcli_err (conn, "Couldn't authenticate as admin: %s",
		            conn->admin_name);
		res = ADCLI_ERR_CREDENTIALS;
	}

	if (ccache != NULL)
		krb5_cc_close (conn->k5, ccache);
	return res;

}

static adcli_result
_adcli_ldap_handle_failure (adcli_conn *conn,
                            const char *desc,
                            const char *arg,
                            LDAP *ldap,
                            adcli_result defres)
{
	char *info;
	int code;

	if (ldap_get_option (ldap, LDAP_OPT_RESULT_CODE, &code) != 0)
		code = LDAP_LOCAL_ERROR;

	if (code == LDAP_NO_MEMORY)
		return ADCLI_ERR_MEMORY;

	if (ldap_get_option (ldap, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void*)&info) != 0)
		info = NULL;

	_adcli_err (conn, "%s%s%s: %s",
	            desc,
	            arg ? ": " : "",
	            arg ? arg : "",
	            info ? info : ldap_err2string (code));

	return defres;
}

static adcli_result
connect_and_lookup_naming (adcli_conn *conn,
                           const char *ldap_url)
{
	char *attrs[] = { "defaultNamingContext", NULL, };
	LDAPMessage *results;
	adcli_result res;
	struct berval **vals;
	LDAPMessage *entry;
	LDAP *ldap;
	char *val;
	int ret;
	int ver;

	assert (conn->ldap == NULL);

	ver = LDAP_VERSION3;
	ret = ldap_initialize (&ldap, ldap_url);

	if (ret == LDAP_NO_MEMORY)
		return ADCLI_ERR_MEMORY;
	else if (ret != 0) {
		_adcli_err (conn, "Couldn't initialize LDAP connection: %s: %s",
		            ldap_url, ldap_err2string (ret));
		return ADCLI_ERR_CONNECTION;
	}

	if (ldap_set_option (ldap, LDAP_OPT_PROTOCOL_VERSION, &ver) != 0) {
		_adcli_err (conn, "Couldn't use LDAP protocol version 3");
		ldap_unbind_ext_s (ldap, NULL, NULL);
		return ADCLI_ERR_SYSTEM;
	}

	/*
	 * We perform this lookup whether or not we want to lookup the
	 * naming context, as it also connects to the LDAP server.
	 *
	 * We really don't want to connect on authenticate (later) as then
	 * we can't reliably tell the difference between a connection and
	 * a credential/auth problem.
	 */
	ret = ldap_search_ext_s (ldap, "", LDAP_SCOPE_BASE, "(objectClass=*)",
	                         attrs, 0, NULL, NULL, NULL, -1, &results);
	if (ret != LDAP_SUCCESS) {
		res = _adcli_ldap_handle_failure (conn, "Couldn't connect to LDAP server",
		                                  ldap_url, ldap, ADCLI_ERR_CONNECTION);
		ldap_unbind_ext_s (ldap, NULL, NULL);
		return res;
	}

	if (conn->naming_context == NULL) {
		entry = ldap_first_message (ldap, results);
		if (entry != NULL) {
			vals = ldap_get_values_len (ldap, entry, "defaultNamingContext");
			if (vals != NULL) {
				if (vals[0]) {
					val = _adcli_strndup (vals[0]->bv_val,
					                      vals[0]->bv_len);
					conn->naming_context = val;
				}
				ldap_value_free_len (vals);
			}
		}
	}

	ldap_msgfree (results);

	if (conn->naming_context == NULL) {
		_adcli_err (conn, "No valid LDAP naming context on server: %s",
		            ldap_url);
		ldap_unbind_ext_s (ldap, NULL, NULL);
		return ADCLI_ERR_CONNECTION;
	}

	conn->ldap = ldap;
	return ADCLI_SUCCESS;
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
connect_to_directory (adcli_conn *conn)
{
	adcli_result res = ADCLI_ERR_CONNECTION;
	int i;

	if (conn->ldap)
		return ADCLI_SUCCESS;

	if (conn->ldap_urls == NULL || conn->ldap_urls[0] == NULL) {
		_adcli_err (conn, "No active directory server to connect to");
		return ADCLI_ERR_CONNECTION;
	}

	for (i = 0; conn->ldap_urls[i] != NULL; i++) {
		res = connect_and_lookup_naming (conn, conn->ldap_urls[i]);
		if (res == ADCLI_SUCCESS || res == ADCLI_ERR_MEMORY)
			return res;
	}

	return res;
}

static adcli_result
authenticate_to_directory (adcli_conn *conn)
{
	OM_uint32 status;
	OM_uint32 minor;
	int ret;

	if (conn->ldap_authenticated)
		return ADCLI_SUCCESS;

	assert (conn->ldap);
	assert (conn->admin_ccache_name != NULL);

	status = gss_krb5_ccache_name (&minor, conn->admin_ccache_name, NULL);
	if (status != 0) {
		_adcli_err (conn, "Couldn't setup GSSAPI with the kerberos credential cache");
		return ADCLI_ERR_SYSTEM;
	}

	ret = ldap_sasl_interactive_bind_s (conn->ldap, NULL, "GSSAPI", NULL, NULL,
	                                    LDAP_SASL_QUIET, sasl_interact, NULL);

	if (ret != 0)
		return _adcli_ldap_handle_failure (conn, "Couldn't authenticate to active directory",
		                                   NULL, conn->ldap, ADCLI_ERR_CREDENTIALS);

	conn->ldap_authenticated = 1;
	return ADCLI_SUCCESS;
}


static void
conn_clear_state (adcli_conn *conn)
{
	conn->ldap_authenticated = 0;

	if (conn->ldap)
		ldap_unbind_ext_s (conn->ldap, NULL, NULL);
	conn->ldap = NULL;

	if (conn->ccache)
		krb5_cc_close (conn->k5, conn->ccache);
	conn->ccache = NULL;

	if (conn->k5)
		krb5_free_context (conn->k5);
	conn->k5 = NULL;
}

adcli_result
adcli_conn_connect (adcli_conn *conn)
{
	adcli_result res = ADCLI_SUCCESS;

	/* Basic discovery and figuring out conn params */
	res = ensure_host_fqdn (res, conn);
	res = ensure_domain_and_host_netbios (res, conn);
	res = ensure_domain_realm (res, conn);
	res = ensure_ldap_urls (res, conn);

	if (res != ADCLI_SUCCESS)
		return res;

	/* Login with admin credentials now, setup login ccache */
	res = prep_kerberos_and_kinit (conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* - Connect to LDAP server */
	res = connect_to_directory (conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* - And finally authenticate */
	return authenticate_to_directory (conn);
}

adcli_conn *
adcli_conn_new (const char *domain_name)
{
	adcli_conn *conn;
	adcli_result res;

	conn = calloc (1, sizeof (adcli_conn));
	if (conn == NULL)
		return NULL;

	conn->refs = 1;

	res = adcli_conn_set_domain_name (conn, NULL);
	if (res != ADCLI_SUCCESS) {
		free (conn);
		conn = NULL;
	}

	return conn;
}

static void
conn_free (adcli_conn *conn)
{
	free (conn->domain_name);
	free (conn->domain_realm);

	free (conn->host_fqdn);

	adcli_conn_set_admin_name (conn, NULL);
	adcli_conn_set_admin_password (conn, NULL);
	adcli_conn_set_password_func (conn, NULL, NULL, NULL);
	adcli_conn_set_message_func (conn, NULL, NULL, NULL);

	conn_clear_state (conn);
	_adcli_strv_free (conn->ldap_urls);

	free (conn);
}

adcli_conn *
adcli_conn_ref (adcli_conn *conn)
{
	conn->refs++;
	return conn;
}

void
adcli_conn_unref (adcli_conn *conn)
{
	if (conn == NULL)
		return;

	if (--(conn->refs) > 0)
		return;

	conn_free (conn);
}

adcli_result
adcli_conn_set_message_func (adcli_conn *conn,
                             adcli_message_func message_func,
                             void *data,
                             adcli_destroy_func destroy_data)
{
	if (conn->message_destroy)
		(conn->message_destroy) (conn->message_data);
	conn->message_func = message_func;
	conn->message_destroy = destroy_data;
	conn->message_data = data;
	return ADCLI_SUCCESS;
}

const char *
adcli_conn_get_host_fqdn (adcli_conn *conn)
{
	return conn->host_fqdn;
}

adcli_result
adcli_conn_set_host_fqdn (adcli_conn *conn,
                          const char *value)
{
	return _adcli_set_str_field (&conn->host_fqdn, value);
}

const char *
adcli_conn_get_domain_name (adcli_conn *conn)
{
	return conn->domain_name;
}

adcli_result
adcli_conn_set_domain_name (adcli_conn *conn,
                            const char *value)
{
	return _adcli_set_str_field (&conn->domain_name, value);
}

const char *
adcli_conn_get_domain_realm (adcli_conn *conn)
{
	return conn->domain_realm;
}

adcli_result
adcli_conn_set_domain_realm (adcli_conn *conn,
                             const char *value)
{
	return _adcli_set_str_field (&conn->domain_realm, value);
}

const char **
adcli_conn_get_ldap_urls (adcli_conn *conn)
{
	return (const char **)conn->ldap_urls;
}

adcli_result
adcli_conn_set_ldap_urls (adcli_conn *conn,
                          const char **value)
{
	char **newval = NULL;

	if (conn->ldap_urls == (char **)value)
		return ADCLI_SUCCESS;

	if (value) {
		newval = _adcli_strv_dup ((char **)value);
		if (newval == NULL)
			return ADCLI_ERR_MEMORY;
	}

	_adcli_strv_free (conn->ldap_urls);
	conn->ldap_urls = newval;

	return ADCLI_SUCCESS;
}

adcli_result
adcli_conn_add_ldap_url (adcli_conn *conn,
                         const char *value)
{
	char *newval;

	newval = strdup (value);
	if (newval == NULL)
		return ADCLI_ERR_MEMORY;

	conn->ldap_urls = _adcli_strv_add (conn->ldap_urls, newval, NULL);
	if (conn->ldap_urls == NULL)
		return ADCLI_ERR_MEMORY;

	return ADCLI_SUCCESS;
}

const char *
adcli_conn_get_admin_name (adcli_conn *conn)
{
	return conn->admin_name;
}

adcli_result
adcli_conn_set_admin_name (adcli_conn *conn,
                           const char *value)
{
	return _adcli_set_str_field (&conn->admin_name, value);
}

const char *
adcli_conn_get_admin_password (adcli_conn *conn)
{
	return conn->admin_password;
}

adcli_result
adcli_conn_set_admin_password (adcli_conn *conn,
                               const char *value)
{
	return _adcli_set_str_field (&conn->admin_password, value);
}

adcli_result
adcli_conn_set_password_func (adcli_conn *conn,
                              adcli_password_func password_func,
                              void *data,
                              adcli_destroy_func destroy_data)
{
	if (conn->password_destroy)
		(conn->password_destroy) (conn->password_data);
	conn->password_func = password_func;
	conn->password_data = data;
	conn->password_destroy = destroy_data;
	return ADCLI_SUCCESS;
}

krb5_ccache
adcli_conn_get_admin_ccache (adcli_conn *conn)
{
	return conn->ccache;
}

const char *
adcli_conn_get_admin_ccache_name (adcli_conn *conn)
{
	return conn->admin_ccache_name;
}

adcli_result
adcli_conn_set_admin_ccache_name (adcli_conn *conn,
                                  const char *ccname)
{
	char *newval = NULL;

	if (ccname == conn->admin_ccache_name)
		return ADCLI_SUCCESS;

	if (ccname) {
		newval = strdup (ccname);
		if (newval == NULL)
			return ADCLI_ERR_MEMORY;
	}

	if (conn->admin_ccache_name) {
		if (conn->admin_ccache_name_is_krb5)
			krb5_free_string (conn->k5, conn->admin_ccache_name);
		else
			free (conn->admin_ccache_name);
	}

	if (conn->ccache) {
		krb5_cc_close (conn->k5, conn->ccache);
		conn->ccache = NULL;
	}

	conn->admin_ccache_name = newval;
	conn->admin_ccache_name_is_krb5 = 0;
	return ADCLI_SUCCESS;
}

const char *
adcli_conn_get_naming_context (adcli_conn *conn)
{
	return conn->naming_context;
}
