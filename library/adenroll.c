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

#include "adenroll.h"
#include "adprivate.h"
#include "seq.h"

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

static krb5_enctype v60_later_enctypes[] = {
	ENCTYPE_AES256_CTS_HMAC_SHA1_96,
	ENCTYPE_AES128_CTS_HMAC_SHA1_96,
	ENCTYPE_DES3_CBC_SHA1,
	ENCTYPE_ARCFOUR_HMAC,
	ENCTYPE_DES_CBC_MD5,
	ENCTYPE_DES_CBC_CRC,
	0
};

static krb5_enctype v51_earlier_enctypes[] = {
	ENCTYPE_DES_CBC_CRC,
	ENCTYPE_DES_CBC_MD5,
	ENCTYPE_ARCFOUR_HMAC,
	0
};

struct _adcli_enroll {
	int refs;
	adcli_conn *conn;

	char *host_fqdn;
	int host_fqdn_explicit;
	char *computer_name;
	int computer_name_explicit;
	char *computer_sam;
	char *computer_password;
	int computer_password_explicit;
	int reset_password;
	krb5_principal computer_principal;

	char *domain_ou;
	int domain_ou_validated;
	int domain_ou_explicit;
	char *computer_dn;
	char *computer_container;
	LDAPMessage *computer_attributes;

	char **service_names;
	char **service_principals;
	int service_principals_explicit;

	char *user_principal;
	int user_princpal_generate;

	char *os_name;
	char *os_version;
	char *os_service_pack;

	krb5_kvno kvno;
	char *keytab_name;
	int keytab_name_is_krb5;
	krb5_keytab keytab;
	krb5_principal *keytab_principals;
	krb5_enctype *keytab_enctypes;
	int keytab_enctypes_explicit;
	unsigned int computer_password_lifetime;
	int computer_password_lifetime_explicit;
};

static adcli_result
ensure_host_fqdn (adcli_result res,
                  adcli_enroll *enroll)
{
	const char *fqdn;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->host_fqdn) {
		_adcli_info ("Using fully qualified name: %s",
		             enroll->host_fqdn);
		return ADCLI_SUCCESS;
	}

	if (enroll->host_fqdn_explicit) {
		_adcli_info ("Not setting fully qualified name");
		return ADCLI_SUCCESS;
	}

	/* By default use our actual host name discovered during connecting */
	fqdn = adcli_conn_get_host_fqdn (enroll->conn);
	_adcli_str_set (&enroll->host_fqdn, fqdn);
	return ADCLI_SUCCESS;
}

static adcli_result
ensure_computer_name (adcli_result res,
                      adcli_enroll *enroll)
{
	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->computer_name) {
		_adcli_info ("Enrolling computer name: %s",
		             enroll->computer_name);
		return ADCLI_SUCCESS;
	}

	if (!enroll->host_fqdn) {
		_adcli_err ("No host name from which to determine the computer name");
		return ADCLI_ERR_CONFIG;
	}

	enroll->computer_name = _adcli_calc_netbios_name (enroll->host_fqdn);
	if (enroll->computer_name == NULL)
		return ADCLI_ERR_CONFIG;

	return ADCLI_SUCCESS;
}

static adcli_result
ensure_computer_sam (adcli_result res,
                     adcli_enroll *enroll)
{
	krb5_error_code code;
	krb5_context k5;

	if (res != ADCLI_SUCCESS)
		return res;

	free (enroll->computer_sam);
	enroll->computer_sam = NULL;

	if (asprintf (&enroll->computer_sam, "%s$", enroll->computer_name) < 0)
		return_unexpected_if_fail (enroll->computer_sam != NULL);

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	if (enroll->computer_principal)
		krb5_free_principal (k5, enroll->computer_principal);
	enroll->computer_principal = NULL;

	code = _adcli_krb5_build_principal (k5, enroll->computer_sam,
	                                    adcli_conn_get_domain_realm (enroll->conn),
	                                    &enroll->computer_principal);
	return_unexpected_if_fail (code == 0);

	return ADCLI_SUCCESS;
}

static int
filter_password_chars (char *password,
                       int length)
{
	int i, j;

	/*
	 * The MS documentation says their servers only use ASCII characters
	 * between 32 and 122 inclusive. We do that as well, and filter out
	 * all other random characters. We also remove certain characters
	 * special for use in a shell.
	 */
	for (i = 0, j = 0; i < length; i++) {
		if (password[i] >= 32 && password[i] <= 122 &&
		    strchr (" !'\"$`", password[i]) == NULL)
			password[j++] = password[i];
	}

	/* return the number of valid characters remaining */
	return j;
}

static char *
generate_host_password  (adcli_enroll *enroll,
                         size_t length)
{
	char *password;
	krb5_context k5;
	krb5_error_code code;
	krb5_data buffer;
	int at;

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_val_if_fail (k5 != NULL, NULL);

	password = malloc (length + 1);
	return_val_if_fail (password != NULL, NULL);

	at = 0;
	while (at != length) {
		buffer.length = length - at;
		buffer.data = password + at;

		code = krb5_c_random_make_octets (k5, &buffer);
		return_val_if_fail (code == 0, NULL);

		at += filter_password_chars (buffer.data, buffer.length);
		assert (at <= length);
	}

	/* This null termination works around a bug in krb5 */
	password[length] = '\0';
	return password;
}

static adcli_result
ensure_computer_password (adcli_result res,
                      adcli_enroll *enroll)
{
	const int length = 120;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->computer_password)
		return ADCLI_SUCCESS;

	if (enroll->reset_password) {
		assert (enroll->computer_name != NULL);
		enroll->computer_password = _adcli_calc_reset_password (enroll->computer_name);
		return_unexpected_if_fail (enroll->computer_password != NULL);
		_adcli_info ("Using default reset computer password");

	} else {
		enroll->computer_password = generate_host_password (enroll, length);
		return_unexpected_if_fail (enroll->computer_password != NULL);
		_adcli_info ("Generated %d character computer password", length);
	}


	return ADCLI_SUCCESS;
}

static adcli_result
ensure_service_names (adcli_result res,
                      adcli_enroll *enroll)
{
	int length = 0;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->service_names || enroll->service_principals)
		return ADCLI_SUCCESS;

	/* The default ones specified by MS */
	enroll->service_names = _adcli_strv_add (enroll->service_names,
	                                         strdup ("host"), &length);
	enroll->service_names = _adcli_strv_add (enroll->service_names,
	                                         strdup ("RestrictedKrbHost"), &length);
	return ADCLI_SUCCESS;
}

static adcli_result
ensure_service_principals (adcli_result res,
                           adcli_enroll *enroll)
{
	char *name;
	int length = 0;
	int i;

	if (res != ADCLI_SUCCESS)
		return res;

	assert (enroll->keytab_principals == NULL);

	if (!enroll->service_principals) {
		assert (enroll->service_names != NULL);

		for (i = 0; enroll->service_names[i] != NULL; i++) {
			if (asprintf (&name, "%s/%s", enroll->service_names[i], enroll->computer_name) < 0)
				return_unexpected_if_reached ();
			enroll->service_principals = _adcli_strv_add (enroll->service_principals,
			                                              name, &length);

			if (enroll->host_fqdn) {
				if (asprintf (&name, "%s/%s", enroll->service_names[i], enroll->host_fqdn) < 0)
					return_unexpected_if_reached ();
				enroll->service_principals = _adcli_strv_add (enroll->service_principals,
				                                              name, &length);
			}
		}
	}

	return ADCLI_SUCCESS;
}

static adcli_result
ensure_keytab_principals (adcli_result res,
                          adcli_enroll *enroll)
{
	krb5_context k5;
	krb5_error_code code;
	int count;
	int at, i;

	/* Prepare the principals we're going to add to the keytab */

	return_unexpected_if_fail (enroll->service_principals);
	count = _adcli_strv_len (enroll->service_principals);

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	enroll->keytab_principals = calloc (count + 3, sizeof (krb5_principal));
	at = 0;

	/* First add the principal for the computer account name */
	code = krb5_copy_principal (k5, enroll->computer_principal,
	                            &enroll->keytab_principals[at++]);
	return_unexpected_if_fail (code == 0);

	/* Next, optionally add the user principal */
	if (enroll->user_principal) {
		code = krb5_parse_name (k5, enroll->user_principal,
		                        &enroll->keytab_principals[at++]);
		if (code != 0) {
			if (code != 0) {
				_adcli_err ("Couldn't parse kerberos user principal: %s: %s",
				            enroll->user_principal,
				            krb5_get_error_message (k5, code));
				return ADCLI_ERR_CONFIG;
			}
		}
	}

	/* Now add the principals for all the various services */

	for (i = 0; i < count; i++) {
		code = _adcli_krb5_build_principal (k5, enroll->service_principals[i],
		                                    adcli_conn_get_domain_realm (enroll->conn),
		                                    &enroll->keytab_principals[at++]);
		if (code != 0) {
			_adcli_err ("Couldn't parse kerberos service principal: %s: %s",
			            enroll->service_principals[i],
			            krb5_get_error_message (k5, code));
			return ADCLI_ERR_CONFIG;
		}
	}

	return ADCLI_SUCCESS;
}

static adcli_result
ensure_user_principal (adcli_result res,
                       adcli_enroll *enroll)
{
	char *name;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->user_princpal_generate) {
		name = strdup (enroll->computer_name);
		return_unexpected_if_fail (name != NULL);

		_adcli_str_down (name);

		assert (enroll->user_principal == NULL);
		if (asprintf (&enroll->user_principal, "host/%s@%s",
		              name, adcli_conn_get_domain_realm (enroll->conn)) < 0)
			return_unexpected_if_reached ();

		free (name);
	}

	if (enroll->user_principal)
		_adcli_info ("With user principal: %s", enroll->user_principal);

	return ADCLI_SUCCESS;
}

static adcli_result
lookup_computer_container (adcli_enroll *enroll,
                           LDAP *ldap)
{
	char *attrs[] = { "wellKnownObjects", NULL };
	char *prefix = "B:32:AA312825768811D1ADED00C04FD8D5CD:";
	int prefix_len;
	LDAPMessage *results;
	const char *base;
	char **values;
	int ret;
	int i;

	if (enroll->computer_container)
		return ADCLI_SUCCESS;

	base = enroll->domain_ou;
	if (base == NULL)
		base = adcli_conn_get_default_naming_context (enroll->conn);
	assert (base != NULL);

	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE,
	                         "(objectClass=*)", attrs, 0, NULL, NULL,
	                         NULL, -1, &results);

	if (ret == LDAP_NO_SUCH_OBJECT && enroll->domain_ou) {
		_adcli_err ("The organizational unit does not exist: %s", enroll->domain_ou);
		return enroll->domain_ou_explicit ? ADCLI_ERR_CONFIG : ADCLI_ERR_DIRECTORY;

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't lookup computer container: %s", base);
	}

	values = _adcli_ldap_parse_values (ldap, results, "wellKnownObjects");
	ldap_msgfree (results);

	prefix_len = strlen (prefix);
	for (i = 0; values && values[i]; i++) {
		if (strncmp (values[i], prefix, prefix_len) == 0) {
			enroll->computer_container = strdup (values[i] + prefix_len);
			return_unexpected_if_fail (enroll->computer_container != NULL);
			_adcli_info ("Found well known computer container at: %s",
			             enroll->computer_container);
			break;
		}
	}

	_adcli_strv_free (values);

	/* Try harder */
	if (!enroll->computer_container) {
		ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE,
		                         "(&(objectClass=container)(cn=Computers))",
		                         attrs, 0, NULL, NULL, NULL, -1, &results);
		if (ret == LDAP_SUCCESS) {
			enroll->computer_container = _adcli_ldap_parse_dn (ldap, results);
			if (enroll->computer_container) {
				_adcli_info ("Well known computer container not "
				             "found, but found suitable one at: %s",
				             enroll->computer_container);
			}
		}

		ldap_msgfree (results);
	}

	if (!enroll->computer_container && enroll->domain_ou) {
		_adcli_warn ("Couldn't find a computer container in the ou, "
		             "creating computer account directly in: %s", enroll->domain_ou);
		enroll->computer_container = strdup (enroll->domain_ou);
		return_unexpected_if_fail (enroll->computer_container != NULL);
	}

	if (!enroll->computer_container) {
		_adcli_err ("Couldn't find location to create computer accounts");
		return ADCLI_ERR_DIRECTORY;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
calculate_computer_account (adcli_enroll *enroll,
                            LDAP *ldap)
{
	adcli_result res;

	assert (enroll->computer_dn == NULL);

	/* Now need to find or validate the computer container */
	res = lookup_computer_container (enroll, ldap);
	if (res != ADCLI_SUCCESS)
		return res;

	assert (enroll->computer_container);

	free (enroll->computer_dn);
	enroll->computer_dn = NULL;

	if (asprintf (&enroll->computer_dn, "CN=%s,%s", enroll->computer_name, enroll->computer_container) < 0)
		return_unexpected_if_reached ();

	_adcli_info ("Calculated computer account: %s", enroll->computer_dn);
	return ADCLI_SUCCESS;
}

static adcli_result
create_computer_account (adcli_enroll *enroll,
                         LDAP *ldap)
{
	char *vals_objectClass[] = { "computer", NULL };
	LDAPMod objectClass = { LDAP_MOD_ADD, "objectClass", { vals_objectClass, } };
	char *vals_sAMAccountName[] = { enroll->computer_sam, NULL };
	LDAPMod sAMAccountName = { LDAP_MOD_ADD, "sAMAccountName", { vals_sAMAccountName, } };
	char *vals_userAccountControl[] = { "69632", NULL }; /* WORKSTATION_TRUST_ACCOUNT | DONT_EXPIRE_PASSWD */
	LDAPMod userAccountControl = { LDAP_MOD_REPLACE, "userAccountControl", { vals_userAccountControl, } };

	int ret;

	LDAPMod *mods[] = {
		&objectClass,
		&sAMAccountName,
		&userAccountControl,
		NULL,
	};

	ret = ldap_add_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);

	/*
	 * Hand to head. This is really dumb... AD returns
	 * OBJECT_CLASS_VIOLATION when the 'admin' account doesn't have
	 * enough permission to create this computer account.
	 *
	 * Additionally LDAP_UNWILLING_TO_PERFORM and LDAP_CONSTRAINT_VIOLATION
	 * are seen on various Windows Servers as responses to this case.
	 *
	 * TODO: Perhaps some missing attributes are auto-generated when
	 * the administrative credentials have sufficient permissions, and
	 * those missing attributes cause the object class violation. However
	 * I've tried to screw around with this, and can't find the missing
	 * attributes. They may be hidden, like unicodePwd.
	 */

	if (ret == LDAP_INSUFFICIENT_ACCESS || ret == LDAP_OBJECT_CLASS_VIOLATION ||
	    ret == LDAP_UNWILLING_TO_PERFORM || ret == LDAP_CONSTRAINT_VIOLATION) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to modify computer account: %s",
		                                   enroll->computer_dn);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't create computer account: %s",
		                                   enroll->computer_dn);
	}

	_adcli_info ("Created computer account: %s", enroll->computer_dn);
	return ADCLI_SUCCESS;
}

static int
filter_for_necessary_updates (adcli_enroll *enroll,
                              LDAP *ldap,
                              LDAPMessage *entry,
                              LDAPMod **mods)
{
	struct berval **vals;
	int match;
	int out;
	int in;

	for (in = 0, out = 0; mods[in] != NULL; in++) {
		match = 0;

		/* Never update these attributes */
		if (strcasecmp (mods[in]->mod_type, "objectClass") == 0)
			continue;

		/* If no entry, then no filtering */
		if (entry != NULL) {
			vals = ldap_get_values_len (ldap, entry, mods[in]->mod_type);
			if (vals != NULL) {
				match = _adcli_ldap_have_in_mod (mods[in], vals);
				ldap_value_free_len (vals);
			}
		}

		if (!match)
			mods[out++] = mods[in];
	}

	mods[out] = NULL;
	return out;
}

static adcli_result
validate_computer_account (adcli_enroll *enroll,
                           int allow_overwrite,
                           int already_exists)
{
	assert (enroll->computer_dn != NULL);

	if (already_exists && !allow_overwrite) {
		_adcli_err ("The computer account %s already exists",
		            enroll->computer_name);
		return ADCLI_ERR_CONFIG;
	}

	/* Do we have an explicitly requested ou? */
	if (enroll->domain_ou && enroll->domain_ou_explicit && already_exists) {
		if (!_adcli_ldap_dn_has_ancestor (enroll->computer_dn, enroll->domain_ou)) {
			_adcli_err ("The computer account %s already exists, "
			            "but is not in the desired organizational unit.",
			            enroll->computer_name);
			return ADCLI_ERR_CONFIG;
		}
	}

	return ADCLI_SUCCESS;
}

static adcli_result
delete_computer_account (adcli_enroll *enroll,
                         LDAP *ldap)
{
	int ret;

	ret = ldap_delete_ext_s (ldap, enroll->computer_dn, NULL, NULL);
	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to delete computer account: %s",
		                                   enroll->computer_dn);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't delete computer account: %s",
		                                   enroll->computer_dn);
	} else {
		_adcli_info ("Deleted computer account at: %s", enroll->computer_dn);
	}

	return ADCLI_SUCCESS;
}

static adcli_result
locate_computer_account (adcli_enroll *enroll,
                         LDAP *ldap,
                         LDAPMessage **rresults,
                         LDAPMessage **rentry)
{
	char *attrs[] = { "1.1", NULL };
	LDAPMessage *results = NULL;
	LDAPMessage *entry = NULL;
	const char *base;
	char *value;
	char *filter;
	char *dn;
	int ret = 0;

	/* If we don't yet know our computer dn, then try and find it */
	value = _adcli_ldap_escape_filter (enroll->computer_sam);
	return_unexpected_if_fail (value != NULL);
	if (asprintf (&filter, "(&(objectClass=computer)(sAMAccountName=%s))", value) < 0)
		return_unexpected_if_reached ();
	free (value);

	base = adcli_conn_get_default_naming_context (enroll->conn);
	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_SUB, filter, attrs, 0,
	                         NULL, NULL, NULL, 1, &results);

	free (filter);

	/* ldap_search_ext_s() can return results *and* an error. */
	if (ret == LDAP_SUCCESS) {
		entry = ldap_first_entry (ldap, results);

		/* If we found a computer account, make note of dn */
		if (entry) {
			dn = ldap_get_dn (ldap, entry);
			free (enroll->computer_dn);
			enroll->computer_dn = strdup (dn);
			return_unexpected_if_fail (enroll->computer_dn != NULL);
			_adcli_info ("Found computer account for %s at: %s",
			             enroll->computer_sam, dn);
			ldap_memfree (dn);

		} else {
			ldap_msgfree (results);
			results = NULL;
			_adcli_info ("Computer account for %s does not exist",
			             enroll->computer_sam);
		}

	} else {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't lookup computer account: %s",
		                                   enroll->computer_sam);
	}

	if (rresults)
		*rresults = results;
	else
		ldap_msgfree (results);
	if (rentry) {
		assert (rresults != NULL);
		*rentry = entry;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
load_computer_account (adcli_enroll *enroll,
                       LDAP *ldap,
                       LDAPMessage **rresults,
                       LDAPMessage **rentry)
{
	char *attrs[] = { "1.1", NULL };
	LDAPMessage *results = NULL;
	LDAPMessage *entry = NULL;
	int ret;

	ret = ldap_search_ext_s (ldap, enroll->computer_dn, LDAP_SCOPE_BASE,
	                         "(objectClass=computer)", attrs, 0,
	                         NULL, NULL, NULL, -1, &results);

	if (ret == LDAP_SUCCESS) {
		entry = ldap_first_entry (ldap, results);
		if (entry) {
			_adcli_info ("Found computer account for %s at: %s",
			             enroll->computer_sam, enroll->computer_dn);
		}

	} else if (ret == LDAP_NO_SUCH_OBJECT) {
		results = entry = NULL;

	} else {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't check computer account: %s",
		                                   enroll->computer_dn);
	}

	if (rresults)
		*rresults = results;
	else
		ldap_msgfree (results);
	if (rentry) {
		assert (rresults != NULL);
		*rentry = entry;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
locate_or_create_computer_account (adcli_enroll *enroll,
                                   int allow_overwrite)
{
	LDAPMessage *results = NULL;
	LDAPMessage *entry = NULL;
	adcli_result res;
	int searched = 0;
	LDAP *ldap;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	/* Try to find the computer account */
	if (!enroll->computer_dn) {
		res = locate_computer_account (enroll, ldap, &results, &entry);
		if (res != ADCLI_SUCCESS)
			return res;
		searched = 1;
	}

	/* Next try and come up with where we think it should be */
	if (enroll->computer_dn == NULL) {
		res = calculate_computer_account (enroll, ldap);
		if (res != ADCLI_SUCCESS)
			return res;
	}

	assert (enroll->computer_dn != NULL);

	/* Have we seen an account yet? */
	if (!searched) {
		res = load_computer_account (enroll, ldap, &results, &entry);
		if (res != ADCLI_SUCCESS)
			return res;
	}

	res = validate_computer_account (enroll, allow_overwrite, entry != NULL);
	if (res == ADCLI_SUCCESS && entry == NULL)
		res = create_computer_account (enroll, ldap);

	if (results)
		ldap_msgfree (results);

	return res;
}

static adcli_result
set_password_with_user_creds (adcli_enroll *enroll)
{
	krb5_error_code code;
	krb5_ccache ccache;
	krb5_context k5;
	krb5_data result_string = { 0, };
	krb5_data result_code_string = { 0, };
	adcli_result res;
	int result_code;
	char *message;

	assert (enroll->computer_password != NULL);
	assert (enroll->computer_principal != NULL);

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	ccache = adcli_conn_get_login_ccache (enroll->conn);
	return_unexpected_if_fail (ccache != NULL);

	memset (&result_string, 0, sizeof (result_string));
	memset (&result_code_string, 0, sizeof (result_code_string));

	code = krb5_set_password_using_ccache (k5, ccache, enroll->computer_password,
	                                       enroll->computer_principal, &result_code,
	                                       &result_code_string, &result_string);

	if (code != 0) {
		_adcli_err ("Couldn't set password for computer account: %s: %s",
		            enroll->computer_sam, krb5_get_error_message (k5, code));
		/* TODO: Parse out these values */
		res = ADCLI_ERR_DIRECTORY;

	} else if (result_code != 0) {
#ifdef HAVE_KRB5_CHPW_MESSAGE
		if (krb5_chpw_message (k5, &result_string, &message) != 0)
			message = NULL;
#else
		message = NULL;
		if (result_string.length)
			message = _adcli_str_dupn (result_string.data, result_string.length);
#endif
		_adcli_err ("Cannot set computer password: %.*s%s%s",
		            (int)result_code_string.length, result_code_string.data,
		            message ? ": " : "", message ? message : "");
		res = ADCLI_ERR_CREDENTIALS;
#ifdef HAVE_KRB5_CHPW_MESSAGE
		krb5_free_string (k5, message);
#else
		free (message);
#endif
	} else {
		_adcli_info ("Set computer password");
		res = ADCLI_SUCCESS;
	}

	krb5_free_data_contents (k5, &result_string);
	krb5_free_data_contents (k5, &result_code_string);

	return res;
}

static adcli_result
set_password_with_computer_creds (adcli_enroll *enroll)
{
	krb5_error_code code;
	krb5_creds creds;
	krb5_data result_string = { 0, };
	krb5_data result_code_string = { 0, };
	krb5_context k5;
	int result_code;
	adcli_result res;
	char *message;

	memset (&creds, 0, sizeof (creds));

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	code = _adcli_kinit_computer_creds (enroll->conn, "kadmin/changepw", NULL, &creds);
	if (code != 0) {
		_adcli_err ("Couldn't get change password ticket for computer account: %s: %s",
		            enroll->computer_sam, krb5_get_error_message (k5, code));
		return ADCLI_ERR_DIRECTORY;
	}

	code = krb5_change_password (k5, &creds, enroll->computer_password,
	                             &result_code, &result_code_string, &result_string);

	krb5_free_cred_contents (k5, &creds);

	if (code != 0) {
		_adcli_err ("Couldn't change password for computer account: %s: %s",
		            enroll->computer_sam, krb5_get_error_message (k5, code));
		/* TODO: Parse out these values */
		res = ADCLI_ERR_DIRECTORY;

	} else if (result_code != 0) {
#ifdef HAVE_KRB5_CHPW_MESSAGE
		if (krb5_chpw_message (k5, &result_string, &message) != 0)
			message = NULL;
#else
		message = NULL;
		if (result_string.length)
			message = _adcli_str_dupn (result_string.data, result_string.length);
#endif
		_adcli_err ("Cannot change computer password: %.*s%s%s",
		            (int)result_code_string.length, result_code_string.data,
		            message ? ": " : "", message ? message : "");
		res = ADCLI_ERR_CREDENTIALS;
#ifdef HAVE_KRB5_CHPW_MESSAGE
		krb5_free_string (k5, message);
#else
		free (message);
#endif
	} else {
		_adcli_info ("Changed computer password");
		if (enroll->kvno > 0) {
			enroll->kvno++;
		        _adcli_info ("kvno incremented to %d", enroll->kvno);
		}
		res = ADCLI_SUCCESS;
	}

	krb5_free_data_contents (k5, &result_string);
	krb5_free_data_contents (k5, &result_code_string);

	return res;
}

static adcli_result
set_computer_password (adcli_enroll *enroll)
{
	if (adcli_conn_get_login_type (enroll->conn) == ADCLI_LOGIN_COMPUTER_ACCOUNT)
		return set_password_with_computer_creds (enroll);
	else
		return set_password_with_user_creds (enroll);
}

static adcli_result
retrieve_computer_account (adcli_enroll *enroll)
{
	adcli_result res = ADCLI_SUCCESS;
	unsigned long kvno;
	char *value;
	LDAP *ldap;
	char *end;
	int ret;

	char *attrs[] =  {
		"msDS-KeyVersionNumber",
		"msDS-supportedEncryptionTypes",
		"dNSHostName",
		"servicePrincipalName",
		"operatingSystem",
		"operatingSystemVersion",
		"operatingSystemServicePack",
		"pwdLastSet",
		NULL,
	};

	assert (enroll->computer_dn != NULL);
	assert (enroll->computer_attributes == NULL);

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	ret = ldap_search_ext_s (ldap, enroll->computer_dn, LDAP_SCOPE_BASE,
	                         "(objectClass=*)", attrs, 0, NULL, NULL, NULL, -1,
	                         &enroll->computer_attributes);

	if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't retrieve computer account info: %s",
		                                   enroll->computer_dn);
	}

	/* Update the kvno */
	if (enroll->kvno == 0) {
		value = _adcli_ldap_parse_value (ldap, enroll->computer_attributes, "msDS-KeyVersionNumber");
		if (value != NULL) {
			kvno = strtoul (value, &end, 10);
			if (end == NULL || *end != '\0') {
				_adcli_err ("Invalid kvno '%s' for computer account in directory: %s",
				            value, enroll->computer_dn);
				res = ADCLI_ERR_DIRECTORY;

			} else {
				enroll->kvno = kvno;

				_adcli_info ("Retrieved kvno '%s' for computer account in directory: %s",
				             value, enroll->computer_dn);
			}

			free (value);

		} else {
			/* Apparently old AD didn't have this attribute, use zero */
			enroll->kvno = 0;

			_adcli_info ("No kvno found for computer account in directory: %s",
			             enroll->computer_dn);
		}
	}

	return res;
}

static adcli_result
update_and_calculate_enctypes (adcli_enroll *enroll)
{
	char *value = NULL;
	krb5_enctype *read_enctypes;
	char *vals_supportedEncryptionTypes[] = { NULL, NULL };
	LDAPMod mod = { LDAP_MOD_REPLACE, "msDS-supportedEncryptionTypes", { vals_supportedEncryptionTypes, } };
	LDAPMod *mods[2] = { &mod, NULL };
	int is_2008_or_later;
	char *new_value;
	LDAP *ldap;
	int ret;

	/*
	 * Because we're using a keytab we want the server to be aware of the
	 * encryption types supported on the client, because we can't dynamically
	 * use a new one that's thrown at us.
	 *
	 * If the encryption types are not explicitly set by the caller of this
	 * library, then see if the account already has some encryption types
	 * marked on it.
	 *
	 * If not, write our default set to the account.
	 *
	 * Note that Windows 2003 and earlier have a standard set of encryption
	 * types, and no msDS-supportedEncryptionTypes attribute.
	 */

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_unexpected_if_fail (ldap != NULL);

	is_2008_or_later = adcli_conn_server_has_capability (enroll->conn, ADCLI_CAP_V60_OID);

	/* In 2008 or later, use the msDS-supportedEncryptionTypes attribute */
	if (is_2008_or_later) {
		value = _adcli_ldap_parse_value (ldap, enroll->computer_attributes,
		                                 "msDS-supportedEncryptionTypes");

		if (!enroll->keytab_enctypes_explicit && value != NULL) {
			read_enctypes = _adcli_krb5_parse_enctypes (value);
			if (read_enctypes == NULL) {
				_adcli_warn ("Invalid or unsupported encryption types are set on "
				             "the computer account (%s).", value);
			} else {
				free (enroll->keytab_enctypes);
				enroll->keytab_enctypes = read_enctypes;
			}
		}

	/* In 2003 or earlier, standard set of enc types */
	} else {
		value = _adcli_krb5_format_enctypes (v51_earlier_enctypes);
	}

	new_value = _adcli_krb5_format_enctypes (adcli_enroll_get_keytab_enctypes (enroll));
	if (new_value == NULL) {
		free (value);
		_adcli_warn ("The encryption types desired are not available in active directory");
		return ADCLI_ERR_CONFIG;
	}

	/* If we already have this value, then don't need to update */
	if (value && strcmp (new_value, value) == 0) {
		free (value);
		free (new_value);
		return ADCLI_SUCCESS;
	}
	free (value);

	if (!is_2008_or_later) {
		free (new_value);
		_adcli_warn ("Server does not support setting encryption types");
		return ADCLI_SUCCESS;
	}

	vals_supportedEncryptionTypes[0] = new_value;

	if (filter_for_necessary_updates (enroll, ldap, enroll->computer_attributes, mods) == 0)
		ret = 0;
	else
		ret = ldap_modify_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);

	free (new_value);

	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to set encryption types on computer account: %s",
		                                   enroll->computer_dn);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't set encryption types on computer account: %s",
		                                   enroll->computer_dn);
	}

	return ADCLI_SUCCESS;
}

static adcli_result
update_computer_attribute (adcli_enroll *enroll,
                           LDAP *ldap,
                           LDAPMod **mods)
{
	adcli_result res = ADCLI_SUCCESS;
	char *string;
	int ret;

	/* See if there are any changes to be made? */
	if (filter_for_necessary_updates (enroll, ldap, enroll->computer_attributes, mods) == 0)
		return ADCLI_SUCCESS;

	string = _adcli_ldap_mods_to_string (mods);
	return_unexpected_if_fail (string != NULL);

	_adcli_info ("Modifying computer account: %s", string);

	ret = ldap_modify_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);

	if (ret != LDAP_SUCCESS) {
		_adcli_warn ("Couldn't set %s on computer account: %s: %s",
		             string, enroll->computer_dn, ldap_err2string (ret));
		res = ADCLI_ERR_DIRECTORY;
	}

	free (string);
	return res;
}

static void
update_computer_account (adcli_enroll *enroll)
{
	int res = 0;
	LDAP *ldap;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_if_fail (ldap != NULL);

	{
		char *vals_dNSHostName[] = { enroll->host_fqdn, NULL };
		LDAPMod dNSHostName = { LDAP_MOD_REPLACE, "dNSHostName", { vals_dNSHostName, } };
		LDAPMod *mods[] = { &dNSHostName, NULL };

		res |= update_computer_attribute (enroll, ldap, mods);
	}

	if (res == ADCLI_SUCCESS) {
		char *vals_userAccountControl[] = { "69632", NULL }; /* WORKSTATION_TRUST_ACCOUNT | DONT_EXPIRE_PASSWD */
		LDAPMod userAccountControl = { LDAP_MOD_REPLACE, "userAccountControl", { vals_userAccountControl, } };
		LDAPMod *mods[] = { &userAccountControl, NULL };

		res |= update_computer_attribute (enroll, ldap, mods);
	}

	if (res == ADCLI_SUCCESS) {
		char *vals_operatingSystem[] = { enroll->os_name, NULL };
		LDAPMod operatingSystem = { LDAP_MOD_REPLACE, "operatingSystem", { vals_operatingSystem, } };
		char *vals_operatingSystemVersion[] = { enroll->os_version, NULL };
		LDAPMod operatingSystemVersion = { LDAP_MOD_REPLACE, "operatingSystemVersion", { vals_operatingSystemVersion, } };
		char *vals_operatingSystemServicePack[] = { enroll->os_service_pack, NULL };
		LDAPMod operatingSystemServicePack = { LDAP_MOD_REPLACE, "operatingSystemServicePack", { vals_operatingSystemServicePack, } };
		LDAPMod *mods[] = { &operatingSystem, &operatingSystemVersion, &operatingSystemServicePack, NULL };

		res |= update_computer_attribute (enroll, ldap, mods);
	}

	if (res == ADCLI_SUCCESS) {
		char *vals_userPrincipalName[] = { enroll->user_principal, NULL };
		LDAPMod userPrincipalName = { LDAP_MOD_REPLACE, "userPrincipalName", { vals_userPrincipalName, }, };
		LDAPMod *mods[] = { &userPrincipalName, NULL, };

		res |= update_computer_attribute (enroll, ldap, mods);
	}

	if (res != 0)
		_adcli_info ("Updated existing computer account: %s", enroll->computer_dn);
}

static adcli_result
update_service_principals (adcli_enroll *enroll)
{
	LDAPMod servicePrincipalName = { LDAP_MOD_REPLACE, "servicePrincipalName", { enroll->service_principals, } };
	LDAPMod *mods[] = { &servicePrincipalName, NULL, };
	LDAP *ldap;
	int ret;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	return_unexpected_if_fail (ldap != NULL);

	/* See if there are any changes to be made? */
	if (filter_for_necessary_updates (enroll, ldap, enroll->computer_attributes, mods) == 0)
		return ADCLI_SUCCESS;

	ret = ldap_modify_ext_s (ldap, enroll->computer_dn, mods, NULL, NULL);
	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to set service principals on computer account: %s",
		                                   enroll->computer_dn);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't set service principals on computer account %s",
		                                   enroll->computer_dn);
	}

	return ADCLI_SUCCESS;
}

static adcli_result
ensure_host_keytab (adcli_result res,
                    adcli_enroll *enroll)
{
	krb5_context k5;
	krb5_error_code code;
	char *name;

	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->keytab)
		return ADCLI_SUCCESS;

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	res = _adcli_krb5_open_keytab (k5, enroll->keytab_name, &enroll->keytab);
	if (res != ADCLI_SUCCESS)
		return res;

	if (!enroll->keytab_name) {
		name = malloc (MAX_KEYTAB_NAME_LEN + 1);
		return_unexpected_if_fail (name != NULL);

		code = krb5_kt_get_name (k5, enroll->keytab, name, MAX_KEYTAB_NAME_LEN + 1);
		return_unexpected_if_fail (code == 0);

		enroll->keytab_name = name;
		enroll->keytab_name_is_krb5 = 1;
	}

	_adcli_info ("Using keytab: %s", enroll->keytab_name);
	return ADCLI_SUCCESS;
}

static krb5_boolean
load_keytab_entry (krb5_context k5,
                   krb5_keytab_entry *entry,
                   void *data)
{
	adcli_enroll *enroll = data;
	krb5_error_code code;
	krb5_principal principal;
	const char *realm;
	size_t len;
	char *value;
	char *name;

	/* Skip over any entry without a principal or realm */
	principal = entry->principal;
	if (!principal || !principal->realm.length)
		return TRUE;

	/* Use the first keytab entry as realm */
	realm = adcli_conn_get_domain_realm (enroll->conn);
	if (!realm) {
		value = _adcli_str_dupn (principal->realm.data, principal->realm.length);
		adcli_conn_set_domain_realm (enroll->conn, value);
		_adcli_info ("Found realm in keytab: %s", value);
		realm = adcli_conn_get_domain_realm (enroll->conn);
		free (value);
	}

	/* Only look at entries that match the realm */
	len = strlen (realm);
	if (principal->realm.length != len && strncmp (realm, principal->realm.data, len) != 0)
		return TRUE;

	code = krb5_unparse_name_flags (k5, principal, KRB5_PRINCIPAL_UNPARSE_NO_REALM, &name);
	return_val_if_fail (code == 0, FALSE);

	len = strlen (name);

	if (!enroll->service_principals_explicit) {
		if (!_adcli_strv_has (enroll->service_principals, name) && strchr (name, '/')) {
			value = strdup (name);
			return_val_if_fail (value != NULL, FALSE);
			_adcli_info ("Found service principal in keytab: %s", value);
			enroll->service_principals = _adcli_strv_add (enroll->service_principals, value, NULL);
		}
	}

	if (!enroll->host_fqdn_explicit && !enroll->computer_name_explicit) {

		/* Automatically use the netbios name */
		if (!enroll->computer_name && len > 1 && _adcli_str_is_up (name) &&
		    _adcli_str_has_suffix (name, "$") && !strchr (name, '/')) {
			enroll->computer_name = name;
			name[len - 1] = '\0';
			_adcli_info ("Found computer name in keytab: %s", name);
			name = NULL;

		} else if (!enroll->host_fqdn && _adcli_str_has_prefix (name, "host/") && strchr (name, '.')) {
			/* Skip host/ prefix */
			enroll->host_fqdn = name + 5;
			_adcli_info ("Found host qualified name in keytab: %s", name);
			name = NULL;
		}
	}

	free (name);
	return TRUE;
}

static adcli_result
load_host_keytab (adcli_enroll *enroll)
{
	krb5_error_code code;
	adcli_result res;
	krb5_context k5;
	krb5_keytab keytab;

	res = _adcli_krb5_init_context (&k5);
	if (res != ADCLI_SUCCESS)
		return res;

	res = _adcli_krb5_open_keytab (k5, enroll->keytab_name, &keytab);
	if (res == ADCLI_SUCCESS) {
		code = _adcli_krb5_keytab_enumerate (k5, keytab, load_keytab_entry, enroll);
		if (code != 0) {
			_adcli_err ("Couldn't enumerate keytab: %s: %s",
		                    enroll->keytab_name, krb5_get_error_message (k5, code));
			res = ADCLI_ERR_FAIL;
		}
		krb5_kt_close (k5, keytab);
	}

	krb5_free_context (k5);
	return ADCLI_SUCCESS;
}

typedef struct {
	krb5_kvno kvno;
	krb5_principal principal;
	int matched;
} match_principal_kvno;

static krb5_boolean
match_principal_and_kvno (krb5_context k5,
                          krb5_keytab_entry *entry,
                          void *data)
{
	match_principal_kvno *closure = data;

	assert (closure->principal);

	/*
	 * Don't match entries with kvno - 1 so that existing sessions
	 * will still work.
	 */

	if (entry->vno + 1 == closure->kvno)
		return 0;

	/* Is this the principal we're looking for? */
	if (krb5_principal_compare (k5, entry->principal, closure->principal)) {
		closure->matched = 1;
		return 1;
	}

	return 0;
}

#define DEFAULT_SALT 1

static krb5_data *
build_principal_salts (adcli_enroll *enroll,
                       krb5_context k5,
                       krb5_principal principal)
{
	krb5_error_code code;
	krb5_data *salts;
	const int count = 3;
	int i = 0;

	salts = calloc (count, sizeof (krb5_data));
	return_val_if_fail (salts != NULL, NULL);

	/* Build up the salts, first a standard kerberos salt */
	code = krb5_principal2salt (k5, principal, &salts[i++]);
	return_val_if_fail (code == 0, NULL);

	/* Then a Windows 2003 computer account salt */
	code = _adcli_krb5_w2k3_salt (k5, principal, enroll->computer_name, &salts[i++]);
	return_val_if_fail (code == 0, NULL);

	/* And lastly a null salt */
	salts[i++].data = NULL;

	assert (count == i);
	return salts;
}

static void
free_principal_salts (krb5_context k5,
                      krb5_data *salts)
{
	int i;

	for (i = 0; salts[i].data != NULL; i++)
		krb5_free_data_contents (k5, salts + i);

	free (salts);
}

static adcli_result
add_principal_to_keytab (adcli_enroll *enroll,
                         krb5_context k5,
                         krb5_principal principal,
                         const char *principal_name,
                         int *which_salt)
{
	match_principal_kvno closure;
	krb5_data password;
	krb5_error_code code;
	krb5_data *salts;
	krb5_enctype *enctypes;

	/* Remove old stuff from the keytab for this principal */

	closure.kvno = enroll->kvno;
	closure.principal = principal;
	closure.matched = 0;

	code = _adcli_krb5_keytab_clear (k5, enroll->keytab,
	                                 match_principal_and_kvno, &closure);

	if (code != 0) {
		_adcli_err ("Couldn't update keytab: %s: %s",
		            enroll->keytab_name, krb5_get_error_message (k5, code));
		return ADCLI_ERR_FAIL;
	}

	if (closure.matched) {
		_adcli_info ("Cleared old entries from keytab: %s",
		             enroll->keytab_name);
	}

	password.data = enroll->computer_password;
	password.length = strlen (enroll->computer_password);

	enctypes = adcli_enroll_get_keytab_enctypes (enroll);

	/*
	 * So we need to discover which salt to use. As a side effect we are
	 * also testing that our account works.
	 */

	salts = build_principal_salts (enroll, k5, principal);
	return_unexpected_if_fail (salts != NULL);

	if (*which_salt < 0) {
		code = _adcli_krb5_keytab_discover_salt (k5, principal, enroll->kvno, &password,
		                                         enctypes, salts, which_salt);
		if (code != 0) {
			_adcli_warn ("Couldn't authenticate with keytab while discovering which salt to use: %s: %s",
			             principal_name, krb5_get_error_message (k5, code));
			*which_salt = DEFAULT_SALT;
		} else {
			assert (*which_salt >= 0);
			_adcli_info ("Discovered which keytab salt to use");
		}
	}

	code = _adcli_krb5_keytab_add_entries (k5, enroll->keytab, principal,
	                                       enroll->kvno, &password, enctypes, &salts[*which_salt]);

	free_principal_salts (k5, salts);

	if (code != 0) {
		_adcli_err ("Couldn't add keytab entries: %s: %s",
		            enroll->keytab_name, krb5_get_error_message (k5, code));
		return ADCLI_ERR_FAIL;
	}


	_adcli_info ("Added the entries to the keytab: %s: %s",
	             principal_name, enroll->keytab_name);
	return ADCLI_SUCCESS;
}

static adcli_result
update_keytab_for_principals (adcli_enroll *enroll)
{
	krb5_context k5;
	adcli_result res;
	int which_salt = -1;
	char *name;
	int i;

	assert (enroll->keytab_principals != NULL);

	k5 = adcli_conn_get_krb5_context (enroll->conn);
	return_unexpected_if_fail (k5 != NULL);

	for (i = 0; enroll->keytab_principals[i] != 0; i++) {
		if (krb5_unparse_name (k5, enroll->keytab_principals[i], &name) != 0)
			name = "";
		res = add_principal_to_keytab (enroll, k5, enroll->keytab_principals[i],
		                               name, &which_salt);
		krb5_free_unparsed_name (k5, name);

		if (res != ADCLI_SUCCESS)
			return res;
	}

	return ADCLI_SUCCESS;
}

static void
enroll_clear_state (adcli_enroll *enroll)
{
	krb5_context k5;
	int i;

	if (enroll->keytab_principals) {
		k5 = adcli_conn_get_krb5_context (enroll->conn);
		return_if_fail (k5 != NULL);

		for (i = 0; enroll->keytab_principals[i] != NULL; i++)
			krb5_free_principal (k5, enroll->keytab_principals[i]);

		free (enroll->keytab_principals);
		enroll->keytab_principals = NULL;
	}

	if (enroll->keytab) {
		k5 = adcli_conn_get_krb5_context (enroll->conn);
		return_if_fail (k5 != NULL);

		krb5_kt_close (k5, enroll->keytab);
		enroll->keytab = NULL;
	}

	free (enroll->computer_sam);
	enroll->computer_sam = NULL;

	if (enroll->computer_principal) {
		k5 = adcli_conn_get_krb5_context (enroll->conn);
		return_if_fail (k5 != NULL);

		krb5_free_principal (k5, enroll->computer_principal);
		enroll->computer_principal = NULL;
	}

	if (!enroll->computer_password_explicit) {
		free (enroll->computer_password);
		enroll->computer_password = NULL;
	}

	free (enroll->computer_dn);
	enroll->computer_dn = NULL;

	free (enroll->computer_container);
	enroll->computer_container = NULL;

	if (!enroll->service_principals_explicit) {
		_adcli_strv_free (enroll->service_principals);
		enroll->service_principals = NULL;
	}

	if (enroll->user_princpal_generate) {
		free (enroll->user_principal);
		enroll->user_principal = NULL;
	}

	enroll->kvno = 0;

	if (enroll->computer_attributes) {
		ldap_msgfree (enroll->computer_attributes);
		enroll->computer_attributes = NULL;
	}

	if (!enroll->domain_ou_explicit) {
		free (enroll->domain_ou);
		enroll->domain_ou = NULL;
	}
}

adcli_result
adcli_enroll_prepare (adcli_enroll *enroll,
                      adcli_enroll_flags flags)
{
	adcli_result res = ADCLI_SUCCESS;

	return_unexpected_if_fail (enroll != NULL);

	adcli_clear_last_error ();

	/* Basic discovery and figuring out enroll params */
	res = ensure_host_fqdn (res, enroll);
	res = ensure_computer_name (res, enroll);
	res = ensure_computer_sam (res, enroll);
	res = ensure_user_principal (res, enroll);
	res = ensure_computer_password (res, enroll);
	if (!(flags & ADCLI_ENROLL_NO_KEYTAB))
		res = ensure_host_keytab (res, enroll);
	res = ensure_service_names (res, enroll);
	res = ensure_service_principals (res, enroll);
	res = ensure_keytab_principals (res, enroll);

	return res;
}

static adcli_result
enroll_join_or_update_tasks (adcli_enroll *enroll,
		             adcli_enroll_flags flags)
{
	adcli_result res;

	if (!(flags & ADCLI_ENROLL_PASSWORD_VALID)) {
		res = set_computer_password (enroll);
		if (res != ADCLI_SUCCESS)
			return res;
	}

	/* kvno is not needed if no keytab */
	if (flags & ADCLI_ENROLL_NO_KEYTAB)
		enroll->kvno = -1;

	/* Get information about the computer account if needed */
	if (enroll->computer_attributes == NULL) {
		res = retrieve_computer_account (enroll);
		if (res != ADCLI_SUCCESS)
			return res;
	}

	/* We ignore failures of setting these fields */
	update_and_calculate_enctypes (enroll);
	update_computer_account (enroll);
	update_service_principals (enroll);

	if (flags & ADCLI_ENROLL_NO_KEYTAB)
		return ADCLI_SUCCESS;

	/*
	 * Salting in the keytab is wild, we need to autodetect the format
	 * that we use for salting.
	 */

	return update_keytab_for_principals (enroll);
}

adcli_result
adcli_enroll_join (adcli_enroll *enroll,
                   adcli_enroll_flags flags)
{
	adcli_result res = ADCLI_SUCCESS;

	return_unexpected_if_fail (enroll != NULL);

	adcli_clear_last_error ();
	enroll_clear_state (enroll);

	res = adcli_conn_discover (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	res = adcli_enroll_prepare (enroll, flags);
	if (res != ADCLI_SUCCESS)
		return res;

	/* This is where it really happens */
	res = locate_or_create_computer_account (enroll, flags & ADCLI_ENROLL_ALLOW_OVERWRITE);
	if (res != ADCLI_SUCCESS)
		return res;

	return enroll_join_or_update_tasks (enroll, flags);
}

adcli_result
adcli_enroll_load (adcli_enroll *enroll)
{
	adcli_result res;

	adcli_clear_last_error ();

	/* Load default info from keytab */
	res = load_host_keytab (enroll);
	if (res != ADCLI_SUCCESS)
		return res;

	if (enroll->computer_name)
		enroll->computer_name_explicit = 1;
	if (enroll->host_fqdn)
		enroll->host_fqdn_explicit = 1;
	if (enroll->service_principals)
		enroll->service_principals_explicit = 1;

	return ADCLI_SUCCESS;
}

adcli_result
adcli_enroll_update (adcli_enroll *enroll,
		     adcli_enroll_flags flags)
{
	adcli_result res = ADCLI_SUCCESS;
	LDAP *ldap;
	char *value;

	return_unexpected_if_fail (enroll != NULL);

	adcli_clear_last_error ();
	enroll_clear_state (enroll);

	res = adcli_conn_discover (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	res = adcli_enroll_prepare (enroll, flags);
	if (res != ADCLI_SUCCESS)
		return res;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	/* Find the computer dn */
	if (!enroll->computer_dn) {
		res = locate_computer_account (enroll, ldap, NULL, NULL);
		if (res != ADCLI_SUCCESS)
			return res;
		if (!enroll->computer_dn) {
			_adcli_err ("No computer account for %s exists", enroll->computer_sam);
			return ADCLI_ERR_CONFIG;
		}
	}

	/* Get information about the computer account */
	res = retrieve_computer_account (enroll);
	if (res != ADCLI_SUCCESS)
		return res;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	value = _adcli_ldap_parse_value (ldap,
	                                 enroll->computer_attributes,
	                                 "pwdLastSet");

	if (_adcli_check_nt_time_string_lifetime (value,
	                adcli_enroll_get_computer_password_lifetime (enroll))) {
		flags |= ADCLI_ENROLL_NO_KEYTAB;
		flags |= ADCLI_ENROLL_PASSWORD_VALID;
	}
	free (value);

	return enroll_join_or_update_tasks (enroll, flags);
}

adcli_result
adcli_enroll_delete (adcli_enroll *enroll,
                     adcli_enroll_flags delete_flags)
{
	adcli_result res = ADCLI_SUCCESS;
	LDAP *ldap;

	return_unexpected_if_fail (enroll != NULL);

	adcli_clear_last_error ();
	enroll_clear_state (enroll);

	res = adcli_conn_discover (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Basic discovery and figuring out enroll params */
	res = ensure_host_fqdn (res, enroll);
	res = ensure_computer_name (res, enroll);
	res = ensure_computer_sam (res, enroll);

	if (res != ADCLI_SUCCESS)
		return res;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	/* Find the computer dn */
	if (!enroll->computer_dn) {
		res = locate_computer_account (enroll, ldap, NULL, NULL);
		if (res != ADCLI_SUCCESS)
			return res;
		if (!enroll->computer_dn) {
			_adcli_err ("No computer account for %s exists",
			            enroll->computer_sam);
			return ADCLI_ERR_CONFIG;
		}
	}

	return delete_computer_account (enroll, ldap);
}

adcli_result
adcli_enroll_password (adcli_enroll *enroll,
                       adcli_enroll_flags password_flags)
{
	adcli_result res = ADCLI_SUCCESS;
	LDAP *ldap;

	return_unexpected_if_fail (enroll != NULL);

	adcli_clear_last_error ();
	enroll_clear_state (enroll);

	res = adcli_conn_discover (enroll->conn);
	if (res != ADCLI_SUCCESS)
		return res;

	/* Basic discovery and figuring out enroll params */
	res = ensure_host_fqdn (res, enroll);
	res = ensure_computer_name (res, enroll);
	res = ensure_computer_sam (res, enroll);
	res = ensure_computer_password (res, enroll);

	if (res != ADCLI_SUCCESS)
		return res;

	ldap = adcli_conn_get_ldap_connection (enroll->conn);
	assert (ldap != NULL);

	/* Find the computer dn */
	if (!enroll->computer_dn) {
		res = locate_computer_account (enroll, ldap, NULL, NULL);
		if (res != ADCLI_SUCCESS)
			return res;
		if (!enroll->computer_dn) {
			_adcli_err ("No computer account for %s exists",
			            enroll->computer_sam);
			return ADCLI_ERR_CONFIG;
		}
	}

	return set_computer_password (enroll);
}

adcli_enroll *
adcli_enroll_new (adcli_conn *conn)
{
	adcli_enroll *enroll;
	const char *value;

	return_val_if_fail (conn != NULL, NULL);

	enroll = calloc (1, sizeof (adcli_enroll));
	return_val_if_fail (enroll != NULL, NULL);

	enroll->conn = adcli_conn_ref (conn);
	enroll->refs = 1;

	/* Use the latter sections of host triple as OS name */
	value = strchr (HOST_TRIPLET, '-');
	if (value == NULL)
		value = HOST_TRIPLET;
	else
		value++;
	enroll->os_name = strdup (value);
	return_val_if_fail (enroll->os_name != NULL, NULL);

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

	enroll_clear_state (enroll);

	free (enroll->computer_sam);
	free (enroll->domain_ou);
	free (enroll->computer_dn);
	free (enroll->keytab_enctypes);

	free (enroll->os_name);
	free (enroll->os_version);
	free (enroll->os_service_pack);

	free (enroll->user_principal);
	_adcli_strv_free (enroll->service_names);
	_adcli_strv_free (enroll->service_principals);
	_adcli_password_free (enroll->computer_password);

	adcli_enroll_set_keytab_name (enroll, NULL);

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
	enroll->host_fqdn_explicit = 1;
}

const char *
adcli_enroll_get_computer_name (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->computer_name;
}

void
adcli_enroll_set_computer_name (adcli_enroll *enroll,
                                const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->computer_name, value);
	enroll->computer_name_explicit = (value != NULL);
}

const char *
adcli_enroll_get_domain_ou (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->domain_ou;
}

void
adcli_enroll_set_domain_ou (adcli_enroll *enroll,
                            const char *value)
{
	return_if_fail (enroll != NULL);

	enroll->domain_ou_validated = 0;
	_adcli_str_set (&enroll->domain_ou, value);
	enroll->domain_ou_explicit = (value != NULL);
}

const char *
adcli_enroll_get_computer_dn (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->computer_dn;
}

void
adcli_enroll_set_computer_dn (adcli_enroll *enroll,
                              const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->computer_dn, value);
}

const char *
adcli_enroll_get_computer_password (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->computer_password;
}

void
adcli_enroll_set_computer_password (adcli_enroll *enroll,
                                    const char *password)
{
	char *newval = NULL;

	return_if_fail (enroll != NULL);

	if (password) {
		newval = strdup (password);
		return_if_fail (newval != NULL);
	}

	if (enroll->computer_password)
		_adcli_password_free (enroll->computer_password);

	enroll->computer_password = newval;
	enroll->computer_password_explicit = (newval != NULL);
}

void
adcli_enroll_reset_computer_password (adcli_enroll *enroll)
{
	return_if_fail (enroll != NULL);

	_adcli_password_free (enroll->computer_password);
	enroll->computer_password = NULL;
	enroll->computer_password_explicit = 0;
	enroll->reset_password = 1;
}

const char **
adcli_enroll_get_service_names (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);

	if (ensure_service_names (ADCLI_SUCCESS, enroll) != ADCLI_SUCCESS)
		return_val_if_reached (NULL);

	return (const char **)enroll->service_names;
}

void
adcli_enroll_set_service_names (adcli_enroll *enroll,
                                const char **value)
{
	return_if_fail (enroll != NULL);
	_adcli_strv_set (&enroll->service_names, value);
}

void
adcli_enroll_add_service_name (adcli_enroll *enroll,
                               const char *value)
{
	return_if_fail (enroll != NULL);
	return_if_fail (value != NULL);

	enroll->service_names = _adcli_strv_add (enroll->service_names, strdup (value), NULL);
	return_if_fail (enroll->service_names != NULL);
}

const char **
adcli_enroll_get_service_principals  (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return (const char **)enroll->service_principals;
}

void
adcli_enroll_set_service_principals (adcli_enroll *enroll,
                                     const char **value)
{
	return_if_fail (enroll != NULL);
	_adcli_strv_set (&enroll->service_principals, value);
	enroll->service_principals_explicit = (value != NULL);
}

krb5_kvno
adcli_enroll_get_kvno (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, 0);
	return enroll->kvno;
}

void
adcli_enroll_set_kvno (adcli_enroll *enroll,
                       krb5_kvno value)
{
	return_if_fail (enroll != NULL);
	enroll->kvno = value;
}

krb5_keytab
adcli_enroll_get_keytab (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->keytab;
}

const char *
adcli_enroll_get_keytab_name (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->keytab_name;
}

void
adcli_enroll_set_keytab_name (adcli_enroll *enroll,
                              const char *value)
{
	char *newval = NULL;
	krb5_context k5;

	return_if_fail (enroll != NULL);

	if (enroll->keytab_name) {
		if (enroll->keytab_name_is_krb5) {
			k5 = adcli_conn_get_krb5_context (enroll->conn);
			return_if_fail (k5 != NULL);
			krb5_free_string (k5, enroll->keytab_name);
		} else {
			free (enroll->keytab_name);
		}
	}

	if (enroll->keytab) {
		k5 = adcli_conn_get_krb5_context (enroll->conn);
		return_if_fail (k5 != NULL);
		krb5_kt_close (k5, enroll->keytab);
		enroll->keytab = NULL;
	}

	if (value) {
		newval = strdup (value);
		return_if_fail (newval != NULL);
	}

	enroll->keytab_name = newval;
	enroll->keytab_name_is_krb5 = 0;
}

krb5_enctype *
adcli_enroll_get_keytab_enctypes (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	if (enroll->keytab_enctypes)
		return enroll->keytab_enctypes;

	if (adcli_conn_server_has_capability (enroll->conn, ADCLI_CAP_V60_OID))
		return v60_later_enctypes;
	else
		return v51_earlier_enctypes;
}

void
adcli_enroll_set_keytab_enctypes (adcli_enroll *enroll,
                                  krb5_enctype *value)
{
	krb5_enctype *newval = NULL;
	int len;

	if (value) {
		for (len = 0; value[len] != 0; len++);
		newval = malloc (sizeof (krb5_enctype) * (len + 1));
		return_if_fail (newval != NULL);
		memcpy (newval, value, sizeof (krb5_enctype) * (len + 1));
	}

	free (enroll->keytab_enctypes);
	enroll->keytab_enctypes = newval;
	enroll->keytab_enctypes_explicit = (newval != NULL);
}

const char *
adcli_enroll_get_os_name (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->os_name;
}

void
adcli_enroll_set_os_name (adcli_enroll *enroll,
                          const char *value)
{
	return_if_fail (enroll != NULL);
	if (value && value[0] == '\0')
		value = NULL;
	_adcli_str_set (&enroll->os_name, value);
}

const char *
adcli_enroll_get_os_version (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->os_version;
}

void
adcli_enroll_set_os_version (adcli_enroll *enroll,
                             const char *value)
{
	return_if_fail (enroll != NULL);
	if (value && value[0] == '\0')
		value = NULL;
	_adcli_str_set (&enroll->os_version, value);
}

const char *
adcli_enroll_get_os_service_pack (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->os_service_pack;
}

void
adcli_enroll_set_os_service_pack (adcli_enroll *enroll,
                                  const char *value)
{
	return_if_fail (enroll != NULL);
	if (value && value[0] == '\0')
		value = NULL;
	_adcli_str_set (&enroll->os_service_pack, value);
}

const char *
adcli_enroll_get_user_principal (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, NULL);
	return enroll->user_principal;
}

void
adcli_enroll_set_user_principal (adcli_enroll *enroll,
                                 const char *value)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->user_principal, value);
	enroll->user_princpal_generate = 0;
}

void
adcli_enroll_auto_user_principal (adcli_enroll *enroll)
{
	return_if_fail (enroll != NULL);
	_adcli_str_set (&enroll->user_principal, NULL);
	enroll->user_princpal_generate = 1;
}

#define DEFAULT_HOST_PW_LIFETIME 30

unsigned int
adcli_enroll_get_computer_password_lifetime (adcli_enroll *enroll)
{
	return_val_if_fail (enroll != NULL, DEFAULT_HOST_PW_LIFETIME);
	if (enroll->computer_password_lifetime_explicit) {
		return enroll->computer_password_lifetime;
	}
	return DEFAULT_HOST_PW_LIFETIME;
}

void
adcli_enroll_set_computer_password_lifetime (adcli_enroll *enroll,
                                   unsigned int lifetime)
{
	return_if_fail (enroll != NULL);
	enroll->computer_password_lifetime = lifetime;

	enroll->computer_password_lifetime_explicit = 1;
}
