
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
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

struct _adcli_enroll {
	int refs;
	adcli_conn *conn;

	char *host_fqdn;
	char *host_netbios;
	char *host_password;
	size_t host_password_len;
	char *domain_netbios;

	char *preferred_ou;
	int preferred_ou_validated;
	char *computer_container;
	char *computer_account;

#if 0
	krb5_keytab host_keytab;
#endif
};

static adcli_result
ensure_host_fqdn (adcli_result res,
                  adcli_enroll *enroll)
{
	const char *fqdn;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->host_fqdn) {
		_adcli_err (enroll->conn, "Using fully qualified name: %s",
		            enroll->host_fqdn);
		return ADCLI_SUCCESS;
	}

	/* By default use our actual host name discovered during connecting */
	fqdn = adcli_conn_get_host_fqdn (enroll->conn);
	adcli_enroll_set_host_fqdn (enroll, fqdn);
	return ADCLI_SUCCESS;
}

static adcli_result
ensure_host_netbios (adcli_result res,
                     adcli_enroll *enroll)
{
	const char *dom;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->host_netbios) {
		_adcli_info (enroll->conn, "Using host netbios name: %s",
		             enroll->host_netbios);
		return ADCLI_SUCCESS;
	}

	assert (enroll->host_fqdn != NULL);

	/* Use the FQDN minus the last part */
	dom = strchr (enroll->host_fqdn, '.');

	/* If no dot, or dot is first or last, then fail */
	if (dom == NULL || dom == enroll->host_fqdn || dom[1] == '\0') {
		_adcli_err (enroll->conn,
		            "Couldn't determine the netbios name from host name: %s",
		            enroll->host_fqdn);
		return ADCLI_ERR_CONFIG;
	}

	enroll->host_netbios = strndup (enroll->host_fqdn, dom - enroll->host_fqdn);
	return_unexpected_if_fail (enroll->host_netbios);

	_adcli_str_up (enroll->host_netbios);
	_adcli_info (enroll->conn, "Calculated host netbios name from fqdn: %s",
	             enroll->host_netbios);
	return ADCLI_SUCCESS;
}

static adcli_result
ensure_host_password (adcli_result res,
                      adcli_enroll *enroll)
{
	const int length = 120;
	krb5_context k5;
	krb5_error_code code;
	krb5_data buffer;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->host_password)
		return ADCLI_SUCCESS;

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	/*
	 * TODO: the MS documentation says their servers only use ASCII
	 * characters between 32 and 122 inclusive. Should we do that as well?
	 */

	buffer.length = length;
	buffer.data = malloc (length);
	return_unexpected_if_fail (buffer.data != NULL);

	code = krb5_c_random_make_octets (k5, &buffer);
	return_unexpected_if_fail (code == 0);

	enroll->host_password = buffer.data;
	enroll->host_password_len = length;
	return ADCLI_SUCCESS;
}

static adcli_result
validate_preferred_ou (adcli_enroll *enroll)
{
	const char *objectClass = "organizationalUnit";
	struct berval bv;
	const char *base;
	LDAP *ldap;
	int ret;

	assert (enroll->preferred_ou != NULL);

	if (enroll->preferred_ou_validated)
		return ADCLI_SUCCESS;

	base = adcli_conn_get_naming_context (enroll->conn);
	assert (base != NULL);

	/* If it's equal to the base, give it a pass */
	if (strcasecmp (enroll->preferred_ou, base) == 0) {
		enroll->preferred_ou_validated = 1;
		return ADCLI_SUCCESS;
	}

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	bv.bv_val = (char *)objectClass;
	bv.bv_len = strlen (objectClass);

	ret = ldap_compare_ext_s (ldap, enroll->preferred_ou,
	                          "objectClass", &bv, NULL, NULL);

	if (ret == LDAP_COMPARE_TRUE) {
		enroll->preferred_ou_validated = 1;
		return ADCLI_SUCCESS;

	} else if (ret == LDAP_COMPARE_FALSE) {
		_adcli_err (enroll->conn,
		            "The computer organizational unit is invalid: %s",
		            enroll->preferred_ou);
		return ADCLI_ERR_CONFIG;

	} else {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't check preferred organizational unit",
		                                   enroll->preferred_ou, ADCLI_ERR_DIRECTORY);
	}
}

static adcli_result
lookup_preferred_ou (adcli_enroll *enroll)
{
	char *attrs[] = { "preferredOU", NULL };
	LDAPMessage *results;
	const char *base;
	LDAP *ldap;
	int ret;

	assert (enroll->preferred_ou == NULL);

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);
	base = adcli_conn_get_naming_context (enroll->conn);
	assert (base != NULL);

	/*
	 * TODO: The objectClass here is documented, but seems like its wrong.
	 * Needs testing against a domain with the preferredOU attribute.
	 * My domain doesn't have this preferred OU attribute, so this has always
	 * failed so far.
	 */
	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE, "(objectClass=computer)",
	                         attrs, 0, NULL, NULL, NULL, -1, &results);

	if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't lookup preferred organizational unit",
		                                   NULL, ADCLI_ERR_DIRECTORY);
	}

	enroll->preferred_ou = _adcli_ldap_parse_value (ldap, results, "preferredOU");
	if (enroll->preferred_ou == NULL) {
		_adcli_info (enroll->conn, "No preferred organizational unit found, "
		             "using directory base: %s", base);
		enroll->preferred_ou = strdup (base);
		return_unexpected_if_fail (enroll->preferred_ou != NULL);
	}

	ldap_msgfree (results);
	return ADCLI_SUCCESS;
}

static adcli_result
lookup_computer_container (adcli_enroll *enroll)
{
	char *attrs[] = { "wellKnownObjects", NULL };
	char *prefix = "B:32:AA312825768811D1ADED00C04FD8D5CD:";
	int prefix_len;
	LDAPMessage *results;
	LDAP *ldap;
	char **values;
	int ret;
	int i;

	assert (enroll->preferred_ou != NULL);

	if (enroll->computer_container)
		return ADCLI_SUCCESS;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	ret = ldap_search_ext_s (ldap, enroll->preferred_ou, LDAP_SCOPE_BASE,
	                         "(objectClass=*)", attrs, 0, NULL, NULL,
	                         NULL, -1, &results);

	if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't lookup computer container",
		                                   NULL, ADCLI_ERR_DIRECTORY);
	}

	values = _adcli_ldap_parse_values (ldap, results, "wellKnownObjects");
	ldap_msgfree (results);

	prefix_len = strlen (prefix);
	for (i = 0; values && values[i]; i++) {
		if (strncmp (values[i], prefix, prefix_len) == 0) {
			enroll->computer_container = strdup (values[i] + prefix_len);
			return_unexpected_if_fail (enroll->computer_container != NULL);
			_adcli_info (enroll->conn, "Found well known computer container at: %s",
			             enroll->computer_container);
			break;
		}
	}

	_adcli_strv_free (values);

	/* Try harder */
	if (!enroll->computer_container) {
		ret = ldap_search_ext_s (ldap, enroll->preferred_ou, LDAP_SCOPE_BASE,
		                         "(&(objectClass=container)(cn=Computers))",
		                         attrs, 0, NULL, NULL, NULL, -1, &results);
		if (ret == LDAP_SUCCESS) {
			enroll->computer_container = _adcli_ldap_parse_dn (ldap, results);
			if (enroll->computer_container) {
				_adcli_info (enroll->conn, "Well known computer container not "
				             "found, but found suitable one at: %s",
				             enroll->computer_container);
			}
		}

		ldap_msgfree (results);
	}

	if (!enroll->computer_container) {
		_adcli_err (enroll->conn, "Couldn't find a computer container for the "
		            "computer account in: %s", enroll->preferred_ou);
		return ADCLI_ERR_DIRECTORY;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
build_computer_account (adcli_enroll *enroll)
{
	assert (enroll->computer_container);

	free (enroll->computer_account);
	enroll->computer_account = NULL;

	if (asprintf (&enroll->computer_account, "CN=%s,%s", enroll->host_netbios,
	              enroll->computer_container) < 0)
		return_unexpected_if_reached ();

	_adcli_info (enroll->conn, "Calculated computer account: %s", enroll->computer_account);
	return ADCLI_SUCCESS;
}

static void
enroll_clear_state (adcli_enroll *enroll)
{

}

adcli_result
adcli_enroll_join (adcli_enroll *enroll)
{
	adcli_result res = ADCLI_SUCCESS;

	res = adcli_conn_connect (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Basic discovery and figuring out enroll params */
	res = ensure_host_fqdn (res, enroll);
	res = ensure_host_netbios (res, enroll);
	res = ensure_host_password (res, enroll);

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->computer_account == NULL) {

		/* Now we need to find or validate the preferred ou */
		if (enroll->preferred_ou)
			res = validate_preferred_ou (enroll);
		else
			res = lookup_preferred_ou (enroll);
		if (res != ADCLI_SUCCESS)
			return res;

		/* Now need to find or validate the computer container */
		res = lookup_computer_container (enroll);
		if (res != ADCLI_SUCCESS)
			return res;

		res = build_computer_account (enroll);
		if (res != ADCLI_SUCCESS)
			return res;
	}

	/* - Figure out the domain short name */

	/* - Update computer account or create */

	/* - Write out password to host keytab */

	return res;
}

adcli_enroll *
adcli_enroll_new (adcli_conn *conn)
{
	adcli_enroll *enroll;

	return_val_if_fail (conn != NULL, NULL);

	enroll = calloc (1, sizeof (adcli_enroll));
	return_val_if_fail (enroll != NULL, NULL);

	enroll->conn = adcli_conn_ref (conn);
	enroll->refs = 1;
	return enroll;
}

adcli_enroll *
adcli_enroll_ref (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	enroll->refs++;
	return enroll;
}

static void
enroll_free (adcli_enroll *enroll)
{
	if (enroll == NULL)
		return;

	free (enroll->host_fqdn);
	free (enroll->host_netbios);
	free (enroll->preferred_ou);
	free (enroll->computer_container);
	free (enroll->computer_account);

	adcli_enroll_set_host_password (enroll, NULL, 0);

	enroll_clear_state (enroll);
	adcli_conn_unref (enroll->conn);
	free (enroll);
}

void
adcli_enroll_unref (adcli_enroll *enroll)
{
	if (enroll == NULL)
		return;

	if (--(enroll->refs) > 0)
		return;

	enroll_free (enroll);
}

const char *
adcli_enroll_get_host_fqdn (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->host_fqdn;
}

void
adcli_enroll_set_host_fqdn (adcli_enroll *enroll,
                            const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->host_fqdn, value);
}

const char *
adcli_enroll_get_host_netbios (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->host_netbios;
}

void
adcli_enroll_set_host_netbios (adcli_enroll *enroll,
                               const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->host_netbios, value);
}

const char *
adcli_enroll_get_preferred_ou (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->preferred_ou;
}

void
adcli_enroll_set_preferred_ou (adcli_enroll *enroll,
                               const char *value)
{
	return_if_fail (enroll != NULL);

	if (value == enroll->preferred_ou)
		return;

	enroll->preferred_ou_validated = 0;
	_adcli_str_set (&enroll->preferred_ou, value);
}

const char *
adcli_enroll_get_computer_container (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->computer_container;
}

void
adcli_enroll_set_computer_container (adcli_enroll *enroll,
                                     const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->computer_account, value);
}

const char *
adcli_enroll_get_computer_account (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->computer_account;
}

void
adcli_enroll_set_computer_account (adcli_enroll *enroll,
                                   const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->computer_account, value);
}

char *
adcli_enroll_get_host_password (adcli_enroll *enroll,
                                size_t *length)
{
	return_val_if_fail (enroll != NULL, NULL);
	return_val_if_fail (length != NULL, NULL);
	*length = enroll->host_password_len;
	return enroll->host_password;
}

void
adcli_enroll_set_host_password (adcli_enroll *enroll,
                                const char *host_password,
                                ssize_t host_password_len)
{
	char *newval = NULL;

	return_if_fail (enroll != NULL);
	return_if_fail (host_password != NULL || host_password_len == 0);

	if (host_password == enroll->host_password &&
	    host_password_len == enroll->host_password_len)
		return;

	if (host_password) {
		newval = malloc (host_password_len);
		return_if_fail (newval != NULL);
		memcpy (newval, host_password, host_password_len);
	}

	if (enroll->host_password) {
		_adcli_mem_clear (enroll->host_password, enroll->host_password_len);
		free (enroll->host_password);
	}

	enroll->host_password = newval;
	enroll->host_password_len = host_password_len;
}
