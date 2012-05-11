
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
	char *computer_ou;
	int computer_ou_validated;

#if 0
	char *host_password;
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
		return ADCLI_ERR_DNS;
	}

	enroll->host_netbios = strndup (enroll->host_fqdn, dom - enroll->host_fqdn);
	return_unexpected_if_fail (enroll->host_netbios);

	_adcli_str_up (enroll->host_netbios);
	_adcli_info (enroll->conn, "Calculated host netbios name from fqdn: %s",
	             enroll->host_netbios);
	return ADCLI_SUCCESS;
}

static adcli_result
validate_computer_ou_objectclass (adcli_enroll *enroll,
                                  LDAP *ldap,
                                  const char *objectClass)
{
	struct berval bv;
	int ret;

	assert (enroll->computer_ou != NULL);

	bv.bv_val = (char *)objectClass;
	bv.bv_len = strlen (objectClass);

	ret = ldap_compare_ext_s (ldap, enroll->computer_ou,
	                          "objectClass", &bv, NULL, NULL);

	if (ret == LDAP_COMPARE_TRUE) {
		enroll->computer_ou_validated = 1;

	} else if (ret != LDAP_COMPARE_FALSE) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't check computer ou",
		                                   enroll->computer_ou, ADCLI_ERR_DNS);
	}

	return ADCLI_SUCCESS;
}

static adcli_result
validate_computer_ou (adcli_enroll *enroll)
{
	adcli_result res;
	LDAP *ldap;

	assert (enroll->computer_ou != NULL);

	if (enroll->computer_ou_validated)
		return ADCLI_SUCCESS;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	/*
	 * TODO: Check whether Windows 2008 controlers use organizationalUnit.
	 * My 2003 functional level server uses container.
	 */
	res = validate_computer_ou_objectclass (enroll, ldap, "organizationalUnit");
	if (res == ADCLI_SUCCESS && !enroll->computer_ou_validated)
		res = validate_computer_ou_objectclass (enroll, ldap, "container");
	if (res != ADCLI_SUCCESS)
		return res;

	if (!enroll->computer_ou_validated) {
		_adcli_err (enroll->conn,
		            "The computer organizational unit is invalid: %s",
		            enroll->computer_ou);
		return ADCLI_ERR_DNS;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
lookup_preferred_computer_ou (adcli_enroll *enroll,
                              LDAP *ldap,
                              const char *base)
{
	char *attrs[] = { "preferredOU", NULL };
	LDAPMessage *results;
	int ret;

	assert (enroll->computer_ou == NULL);

	/*
	 * TODO: The objectClass here is documented, but seems like its wrong.
	 * Needs testing against a domain with the preferredOU attribute.
	 * FWIW, Windows 2003 functional level doesn't have preferredOU.
	 */
	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE, "(objectClass=computer)",
	                         attrs, 0, NULL, NULL, NULL, -1, &results);

	if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't lookup preferred organizational unit",
		                                   NULL, ADCLI_ERR_CONNECTION);
	}

	enroll->computer_ou = _adcli_ldap_parse_value (ldap, results, "preferredOU");

	ldap_msgfree (results);
	return ADCLI_SUCCESS;
}

static adcli_result
lookup_wellknown_computer_ou (adcli_enroll *enroll,
                              LDAP *ldap,
                              const char *base)
{
	char *attrs[] = { "wellKnownObjects", NULL };
	char *prefix = "B:32:AA312825768811D1ADED00C04FD8D5CD:";
	int prefix_len;
	LDAPMessage *results;
	char **values;
	int ret;
	int i;

	assert (enroll->computer_ou == NULL);

	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE, "(objectClass=*)",
	                         attrs, 0, NULL, NULL, NULL, -1, &results);

	if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (enroll->conn, ldap,
		                                   "Couldn't lookup well known organizational unit",
		                                   NULL, ADCLI_ERR_CONNECTION);
	}

	values = _adcli_ldap_parse_values (ldap, results, "wellKnownObjects");
	ldap_msgfree (results);

	prefix_len = strlen (prefix);
	for (i = 0; values && values[i]; i++) {
		if (strncmp (values[i], prefix, prefix_len) == 0) {
			enroll->computer_ou = strdup (values[i] + prefix_len);
			return_unexpected_if_fail (enroll->computer_ou != NULL);
		}
	}

	_adcli_strv_free (values);
	return ADCLI_SUCCESS;
}

static adcli_result
lookup_computer_ou (adcli_enroll *enroll)
{
	adcli_result res;
	const char *base;
	LDAP *ldap;

	assert (enroll->computer_ou == NULL);

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	base = adcli_conn_get_naming_context (enroll->conn);
	assert (base != NULL);

	res = lookup_preferred_computer_ou (enroll, ldap, base);
	if (res == ADCLI_SUCCESS && enroll->computer_ou == NULL)
		res = lookup_wellknown_computer_ou (enroll, ldap, base);

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->computer_ou == NULL) {
		_adcli_err (enroll->conn, "No preferred organizational unit found");
		return ADCLI_ERR_DNS;

	}

	/* No need to validate this ou, as we just looked it up */
	enroll->computer_ou_validated = 1;
	return res;
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

	if (res != ADCLI_SUCCESS)
		return res;

	/* Now we need to find or validate the computer ou */
	if (enroll->computer_ou)
		res = validate_computer_ou (enroll);
	else
		res = lookup_computer_ou (enroll);
	if (res != ADCLI_SUCCESS)
		return res;

	/* TODO: Create a valid password */

	/* - Figure out the domain short name */

	/* - Search for computer account */

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
	free (enroll->computer_ou);

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
adcli_enroll_get_computer_ou (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->computer_ou;
}

void
adcli_enroll_set_computer_ou (adcli_enroll *enroll,
                              const char *value)
{
	return_if_fail (enroll != NULL);

	if (value == enroll->computer_ou)
		return;

	enroll->computer_ou_validated = 0;
	_adcli_str_set (&enroll->computer_ou, value);
}
