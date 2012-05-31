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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "adcli.h"
#include "adprivate.h"
#include "getsrvinfo.h"

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
	char *domain_server;
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
	return_if_fail (ret >= 0);

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
		return ADCLI_ERR_UNEXPECTED;
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
			return_unexpected_if_fail (conn->host_fqdn != NULL);
			freeaddrinfo (ai);
			return ADCLI_SUCCESS;
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
		return_unexpected_if_fail (conn->host_fqdn != NULL);
		return ADCLI_SUCCESS;

	case EAI_MEMORY:
		return_unexpected_if_reached ();

	default:
		_adcli_err (conn, "Couldn't resolve host name: %s: %s",
		            hostname, gai_strerror (ret));
		return ADCLI_ERR_FAIL;
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
		return ADCLI_ERR_FAIL;
	}

	conn->domain_name = strdup (dom + 1);
	return_unexpected_if_fail (conn->domain_name != NULL);

	_adcli_info (conn, "Calculated domain name from host fqdn: %s",
	             conn->domain_name);

	return ADCLI_SUCCESS;
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
	return_unexpected_if_fail (conn->domain_realm != NULL);

	_adcli_str_up (conn->domain_realm);
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
			return_unexpected_if_reached ();
		urls = _adcli_strv_add (urls, url, &length);
		return_unexpected_if_fail (urls != NULL);
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
	char *url;
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

	/* If a server was explicitly set, then use that */
	if (conn->domain_server) {
		if (asprintf (&url, "ldap://%s", conn->domain_server) < 0)
			return_unexpected_if_reached ();
		conn->ldap_urls = _adcli_strv_add (NULL, url, NULL);
		return_unexpected_if_fail (conn->ldap_urls != NULL);

		_adcli_info (conn, "Using LDAP urls: %s", url);
		return ADCLI_SUCCESS;
	}

	if (asprintf (&rrname, "_ldap._tcp.%s", conn->domain_name) < 0)
		return_unexpected_if_reached ();

	ret = _adcli_getsrvinfo (rrname, &srv);

	switch (ret) {
	case 0:
		ret = srvinfo_to_ldap_urls (srv, &conn->ldap_urls);
		_adcli_freesrvinfo (srv);
		res = ADCLI_SUCCESS;
		break;

	case EAI_NONAME:
	case EAI_AGAIN:
		_adcli_err (conn, "No LDAP SRV records for domain: %s: %s",
		            rrname, gai_strerror (ret));
		res = ADCLI_ERR_DIRECTORY;
		break;

	default:
		_adcli_err (conn, "Couldn't resolve SRV record: %s: %s",
		            rrname, gai_strerror (ret));
		res = ADCLI_ERR_FAIL;
		break;
	}

	if (res == ADCLI_SUCCESS && conn->message_func) {
		string = _adcli_strv_join (conn->ldap_urls, " ");
		_adcli_info (conn, "Resolved LDAP urls from SRV record: %s: %s",
		             rrname, string);
		free (string);
	}

	free (rrname);
	return res;
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
	return_val_if_fail (code == 0, code);

	code = krb5_get_init_creds_opt_set_out_ccache (k5, opt, ccache);
	return_val_if_fail (code == 0, code);

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
		return_unexpected_if_reached ();

	} else if (code != 0) {
		_adcli_err (conn, "Failed to create kerberos context: %s",
		            krb5_get_error_message (conn->k5, code));
		return ADCLI_ERR_UNEXPECTED;
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
			return_unexpected_if_reached ();
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
			return_unexpected_if_reached ();
	} else if (strchr (conn->admin_name, '@') == NULL) {
		if (asprintf (&name, "%s@%s", conn->admin_name, conn->domain_realm) < 0)
			return_unexpected_if_reached ();
		free (conn->admin_name);
		conn->admin_name = name;
	}

	res = ensure_admin_password (conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Initialize the credential cache */
	code = krb5_cc_new_unique (conn->k5, "MEMORY", NULL, &ccache);
	return_unexpected_if_fail (code == 0);

	code = kinit_with_password_and_ccache (conn->k5, conn->admin_name,
	                                       conn->admin_password, ccache);

	if (code == 0) {
		code = krb5_cc_get_full_name (conn->k5, ccache,
		                              &conn->admin_ccache_name);
		return_unexpected_if_fail (code == 0);

		conn->ccache = ccache;
		conn->admin_ccache_name_is_krb5 = 1;
		ccache = NULL;
		res = ADCLI_SUCCESS;

	} else if (code == ENOMEM) {
		return_unexpected_if_reached ();

	} else {
		_adcli_err (conn, "Couldn't authenticate as admin: %s: %s", conn->admin_name,
		            krb5_get_error_message (conn->k5, code));
		res = ADCLI_ERR_CREDENTIALS;
	}

	if (ccache != NULL)
		krb5_cc_close (conn->k5, ccache);
	return res;

}

static adcli_result
connect_and_lookup_naming (adcli_conn *conn,
                           const char *ldap_url)
{
	char *attrs[] = { "defaultNamingContext", NULL, };
	LDAPMessage *results;
	adcli_result res;
	LDAPURLDesc *urli;
	LDAP *ldap;
	int ret;
	int ver;

	assert (conn->ldap == NULL);

	ver = LDAP_VERSION3;
	ret = ldap_initialize (&ldap, ldap_url);

	if (ret == LDAP_NO_MEMORY)
		return_unexpected_if_reached ();

	else if (ret != 0) {
		_adcli_err (conn, "Couldn't initialize LDAP connection: %s: %s",
		            ldap_url, ldap_err2string (ret));
		return ADCLI_ERR_CONFIG;
	}

	if (ldap_set_option (ldap, LDAP_OPT_PROTOCOL_VERSION, &ver) != 0)
		return_unexpected_if_reached ();

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
		res = _adcli_ldap_handle_failure (conn, ldap, "Couldn't connect to LDAP server",
		                                  ldap_url, ADCLI_ERR_DIRECTORY);
		ldap_unbind_ext_s (ldap, NULL, NULL);
		return res;
	}

	if (conn->naming_context == NULL)
		conn->naming_context = _adcli_ldap_parse_value (ldap, results,
		                                                "defaultNamingContext");

	ldap_msgfree (results);

	if (conn->naming_context == NULL) {
		_adcli_err (conn, "No valid LDAP naming context on server: %s", ldap_url);
		ldap_unbind_ext_s (ldap, NULL, NULL);
		return ADCLI_ERR_DIRECTORY;
	}

	conn->ldap = ldap;

	/* Make note of the server that we connected to */
	ret = ldap_url_parse (ldap_url, &urli);
	return_unexpected_if_fail (ret == LDAP_SUCCESS);

	if (urli->lud_host && urli->lud_host[0])
		adcli_conn_set_domain_server (conn, urli->lud_host);

	ldap_free_urldesc (urli);

	return ADCLI_SUCCESS;
}

static int
sasl_interact (LDAP *ld,
               unsigned flags,
               void *defaults,
               void *interact)
{
	sasl_interact_t *in = (sasl_interact_t *)interact;
	return_val_if_fail (ld != NULL, LDAP_PARAM_ERROR);

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
			return LDAP_UNAVAILABLE;
		}
		in++;
	}

	return LDAP_SUCCESS;
}

static adcli_result
connect_to_directory (adcli_conn *conn)
{
	adcli_result res = ADCLI_ERR_UNEXPECTED;
	int i;

	if (conn->ldap)
		return ADCLI_SUCCESS;

	if (conn->ldap_urls == NULL || conn->ldap_urls[0] == NULL) {
		_adcli_err (conn, "No active directory server to connect to");
		return ADCLI_ERR_CONFIG;
	}

	for (i = 0; conn->ldap_urls[i] != NULL; i++) {
		res = connect_and_lookup_naming (conn, conn->ldap_urls[i]);
		if (res == ADCLI_SUCCESS || res == ADCLI_ERR_UNEXPECTED)
			return res;
	}

	return res;
}

static adcli_result
authenticate_to_directory (adcli_conn *conn)
{
	OM_uint32 status;
	OM_uint32 minor;
	int opt;
	int ret;

	if (conn->ldap_authenticated)
		return ADCLI_SUCCESS;

	assert (conn->ldap);
	assert (conn->admin_ccache_name != NULL);

	/* Sets the credential cache GSSAPI to use (for this thread) */
	status = gss_krb5_ccache_name (&minor, conn->admin_ccache_name, NULL);
	return_unexpected_if_fail (status == 0);

	/* Clumsily tell ldap + cyrus-sasl that we want encryption */
	opt = 1;
	ret = ldap_set_option (conn->ldap, LDAP_OPT_X_SASL_SSF_MIN, &opt);
	return_unexpected_if_fail (ret == 0);

	ret = ldap_sasl_interactive_bind_s (conn->ldap, NULL, "GSSAPI", NULL, NULL,
	                                    LDAP_SASL_QUIET, sasl_interact, NULL);

	/* Clear the credential cache GSSAPI to use (for this thread) */
	status = gss_krb5_ccache_name (&minor, NULL, NULL);
	return_unexpected_if_fail (status == 0);

	if (ret != 0) {
		return _adcli_ldap_handle_failure (conn, conn->ldap,
		                                   "Couldn't authenticate to active directory",
		                                   NULL, ADCLI_ERR_CREDENTIALS);
	}

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

	return_unexpected_if_fail (conn != NULL);

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

	/* TODO: Figure out the domain short name */
}

adcli_conn *
adcli_conn_new (const char *domain_name)
{
	adcli_conn *conn;

	conn = calloc (1, sizeof (adcli_conn));
	return_val_if_fail (conn != NULL, NULL);

	conn->refs = 1;
	adcli_conn_set_domain_name (conn, domain_name);
	return conn;
}

static void
conn_free (adcli_conn *conn)
{
	free (conn->domain_name);
	free (conn->domain_realm);
	free (conn->domain_server);

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
	return_val_if_fail (conn != NULL, NULL);

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

void
adcli_conn_set_message_func (adcli_conn *conn,
                             adcli_message_func message_func,
                             void *data,
                             adcli_destroy_func destroy_data)
{
	return_if_fail (conn != NULL);

	if (conn->message_destroy)
		(conn->message_destroy) (conn->message_data);
	conn->message_func = message_func;
	conn->message_destroy = destroy_data;
	conn->message_data = data;
}

const char *
adcli_conn_get_host_fqdn (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->host_fqdn;
}

void
adcli_conn_set_host_fqdn (adcli_conn *conn,
                          const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->host_fqdn, value);
}

const char *
adcli_conn_get_domain_name (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->domain_name;
}

void
adcli_conn_set_domain_name (adcli_conn *conn,
                            const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->domain_name, value);
}

const char *
adcli_conn_get_domain_realm (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->domain_realm;
}

void
adcli_conn_set_domain_realm (adcli_conn *conn,
                             const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->domain_realm, value);
}

const char *
adcli_conn_get_domain_server (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->domain_server;
}

void
adcli_conn_set_domain_server (adcli_conn *conn,
                              const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->domain_server, value);
}

const char **
adcli_conn_get_ldap_urls (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return (const char **)conn->ldap_urls;
}

void
adcli_conn_set_ldap_urls (adcli_conn *conn,
                          const char **value)
{
	return_if_fail (conn != NULL);
	_adcli_strv_set (&conn->ldap_urls, value);
}

void
adcli_conn_add_ldap_url (adcli_conn *conn,
                         const char *value)
{
	return_if_fail (conn != NULL);
	return_if_fail (value != NULL);

	conn->ldap_urls = _adcli_strv_add (conn->ldap_urls, strdup (value), NULL);
	return_if_fail (conn->ldap_urls != NULL);
}

LDAP *
adcli_conn_get_ldap_connection (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->ldap;
}

krb5_context
adcli_conn_get_krb5_context (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);

	if (ensure_k5_ctx (conn) != ADCLI_SUCCESS)
		return NULL;

	return conn->k5;
}

const char *
adcli_conn_get_admin_name (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->admin_name;
}

void
adcli_conn_set_admin_name (adcli_conn *conn,
                           const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->admin_name, value);
}

const char *
adcli_conn_get_admin_password (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->admin_password;
}

void
adcli_conn_set_admin_password (adcli_conn *conn,
                               const char *value)
{
	return_if_fail (conn != NULL);
	_adcli_str_set (&conn->admin_password, value);
}

void
adcli_conn_set_password_func (adcli_conn *conn,
                              adcli_password_func password_func,
                              void *data,
                              adcli_destroy_func destroy_data)
{
	return_if_fail (conn != NULL);

	if (conn->password_destroy)
		(conn->password_destroy) (conn->password_data);
	conn->password_func = password_func;
	conn->password_data = data;
	conn->password_destroy = destroy_data;
}

krb5_ccache
adcli_conn_get_admin_ccache (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->ccache;
}

const char *
adcli_conn_get_admin_ccache_name (adcli_conn *conn)
{
	return_val_if_fail (conn != NULL, NULL);
	return conn->admin_ccache_name;
}

void
adcli_conn_set_admin_ccache_name (adcli_conn *conn,
                                  const char *ccname)
{
	char *newval = NULL;

	return_if_fail (conn != NULL);

	if (ccname) {
		newval = strdup (ccname);
		return_if_fail (newval != NULL);
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
}

const char *
adcli_conn_get_naming_context (adcli_conn *conn)
{
	return conn->naming_context;
}
