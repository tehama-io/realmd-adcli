/*
 * adcli
 *
 * Copyright (C) 2013 Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "aduser.h"
#include "adprivate.h"
#include "seq.h"

#include <assert.h>
#include <stdio.h>

struct _adcli_user {
	int refs;
	adcli_conn *conn;

	char *sam_name;
	char *user_dn;
	char *user_ou;
	char *user_container;
};

adcli_user *
adcli_user_new (adcli_conn *conn,
                const char *sam_name)
{
	adcli_user *user;

	return_val_if_fail (conn != NULL, NULL);
	return_val_if_fail (sam_name != NULL, NULL);

	user = calloc (1, sizeof (adcli_user));
	return_val_if_fail (user != NULL, NULL);

	user->conn = adcli_conn_ref (conn);
	user->refs = 1;

	user->sam_name = strdup (sam_name);
	return_val_if_fail (user->sam_name != NULL, NULL);

	return user;

}

adcli_user *
adcli_user_ref (adcli_user *user)
{
	return_val_if_fail (user != NULL, NULL);
	user->refs++;
	return user;

}

static void
user_free (adcli_user *user)
{
	free (user->sam_name);
	free (user->user_container);
	free (user->user_dn);
	free (user->user_ou);
	adcli_conn_unref (user->conn);
	free (user);
}

void
adcli_user_unref (adcli_user *user)
{
	if (user == NULL)
		return;

	if (--(user->refs) > 0)
		return;

	user_free (user);
}

static adcli_result
update_user_from_domain (adcli_user *user,
                         LDAP *ldap)
{
	const char *attrs[] = { "1.1", NULL };
	LDAPMessage *results;
	LDAPMessage *entry;
	const char *base;
	char *filter;
	char *value;
	int ret;

	value = _adcli_ldap_escape_filter (user->sam_name);
	return_unexpected_if_fail (value != NULL);

	if (asprintf (&filter, "(&(objectClass=user)(sAMAccountName=%s))", value) < 0)
		return_unexpected_if_reached ();

	base = adcli_conn_get_default_naming_context (user->conn);
	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_SUB, filter, (char **)attrs,
	                         0, NULL, NULL, NULL, -1, &results);

	free (filter);
	free (value);

	if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (user->conn, ldap,
		                                   "Couldn't search for user",
		                                   user->sam_name, ADCLI_ERR_DIRECTORY);
	}

	entry = ldap_first_entry (ldap, results);
	ldap_memfree (user->user_dn);
	user->user_dn = NULL;

	/* Entry, use its dn */
	if (entry != NULL) {
		user->user_dn = ldap_get_dn (ldap, entry);
		return_unexpected_if_fail (user->user_dn != NULL);
	}

	ldap_msgfree (results);
	return ADCLI_SUCCESS;
}

static adcli_result
lookup_user_container (adcli_user *user,
                       LDAP *ldap)
{
	char *attrs[] = { "wellKnownObjects", NULL };
	char *prefix = "B:32:A9D1CA15768811D1ADED00C04FD8D5CD:";
	int prefix_len;
	LDAPMessage *results;
	const char *base;
	char **values;
	int ret;
	int i;

	if (user->user_container)
		return ADCLI_SUCCESS;

	base = user->user_ou;
	if (base == NULL)
		base = adcli_conn_get_default_naming_context (user->conn);
	assert (base != NULL);

	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE,
	                         "(objectClass=*)", attrs, 0, NULL, NULL,
	                         NULL, -1, &results);

	if (ret == LDAP_NO_SUCH_OBJECT && user->user_ou) {
		_adcli_err (user->conn, "The organizational unit does not exist: %s", user->user_ou);
		return ADCLI_ERR_DIRECTORY;

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (user->conn, ldap,
		                                   "Couldn't lookup user container",
		                                   NULL, ADCLI_ERR_DIRECTORY);
	}

	values = _adcli_ldap_parse_values (ldap, results, "wellKnownObjects");
	ldap_msgfree (results);

	prefix_len = strlen (prefix);
	for (i = 0; values && values[i]; i++) {
		if (strncmp (values[i], prefix, prefix_len) == 0) {
			user->user_container = strdup (values[i] + prefix_len);
			return_unexpected_if_fail (user->user_container != NULL);
			_adcli_info (user->conn, "Found well known user container at: %s",
			             user->user_container);
			break;
		}
	}

	_adcli_strv_free (values);

	/* Try harder */
	if (!user->user_container) {
		ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE,
		                         "(&(objectClass=container)(cn=Users))",
		                         attrs, 0, NULL, NULL, NULL, -1, &results);
		if (ret == LDAP_SUCCESS) {
			user->user_container = _adcli_ldap_parse_dn (ldap, results);
			if (user->user_container) {
				_adcli_info (user->conn, "Well known user container not "
				             "found, but found suitable one at: %s",
				             user->user_container);
			}
		}

		ldap_msgfree (results);
	}

	if (!user->user_container && user->user_ou) {
		_adcli_warn (user->conn, "Couldn't find a user container in the ou, "
		             "creating user account directly in: %s", user->user_ou);
		user->user_container = strdup (user->user_ou);
		return_unexpected_if_fail (user->user_container != NULL);
	}

	if (!user->user_container) {
		_adcli_err (user->conn, "Couldn't find location to create user accounts");
		return ADCLI_ERR_DIRECTORY;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
calculate_user_account (adcli_user *user,
                        LDAP *ldap)
{
	adcli_result res;

	/* Now need to find or validate the user container */
	res = lookup_user_container (user, ldap);
	if (res != ADCLI_SUCCESS)
		return res;

	assert (user->user_container);

	free (user->user_dn);
	user->user_dn = NULL;

	if (asprintf (&user->user_dn, "CN=%s,%s", user->sam_name, user->user_container) < 0)
		return_unexpected_if_reached ();

	_adcli_info (user->conn, "Calculated user account: %s", user->user_dn);
	return ADCLI_SUCCESS;
}

adcli_result
adcli_user_create (adcli_user *user,
                   adcli_attrs *attrs)
{
	adcli_result res;
	char *string;
	LDAP *ldap;
	int ret;

	ldap = adcli_conn_get_ldap_connection (user->conn);
	return_unexpected_if_fail (ldap != NULL);

	/* Find the user */
	res = update_user_from_domain (user, ldap);
	if (res != ADCLI_SUCCESS)
		return res;

	if (user->user_dn) {
		_adcli_err (user->conn, "The user %s already exists in the domain", user->sam_name);
		return ADCLI_ERR_CONFIG;
	}

	res = calculate_user_account (user, ldap);
	if (res != ADCLI_SUCCESS)
		return res;

	assert (user->user_dn);

	/* Fill in the work attributes */
	seq_filter (attrs->mods, &attrs->len, NULL,
	            _adcli_ldap_filter_for_add, _adcli_ldap_mod_free);

	adcli_attrs_set (attrs, "objectClass", "user");
	adcli_attrs_set (attrs, "cn", user->sam_name);
	adcli_attrs_set (attrs, "userAccountControl", "514") /* NORMAL_ACCOUNT | ACCOUNTDISABLE */;
	adcli_attrs_set (attrs, "sAMAccountName", user->sam_name);

	if (!adcli_attrs_have (attrs, "displayName"))
		adcli_attrs_set (attrs, "displayName", user->sam_name);
	if (!adcli_attrs_have (attrs, "name"))
		adcli_attrs_set (attrs, "name", user->sam_name);
	if (!adcli_attrs_have (attrs, "userPrincipalName")) {
		if (asprintf (&string, "%s@%s", user->sam_name, adcli_conn_get_domain_name (user->conn)) < 0)
			return_unexpected_if_reached ();
		adcli_attrs_take (attrs, "userPrincipalName", string);
	}

	string = _adcli_ldap_mods_to_string (attrs->mods);
	_adcli_info (user->conn, "Creating user account with attributes: %s", string);
	free (string);

	ret = ldap_add_ext_s (ldap, user->user_dn, attrs->mods, NULL, NULL);

	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (user->conn, ldap,
		                                   "Insufficient permissions to create user account",
		                                   user->user_dn,
		                                   ADCLI_ERR_CREDENTIALS);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (user->conn, ldap,
		                                   "Couldn't create user account",
		                                   user->user_dn,
		                                   ADCLI_ERR_DIRECTORY);
	}

	_adcli_info (user->conn, "Created user account: %s", user->user_dn);
	return ADCLI_SUCCESS;
}

adcli_result
adcli_user_delete (adcli_user *user)
{
	adcli_result res;
	LDAP *ldap;
	int ret;

	ldap = adcli_conn_get_ldap_connection (user->conn);
	return_unexpected_if_fail (ldap != NULL);

	/* Find the user */
	res = update_user_from_domain (user, ldap);
	if (res != ADCLI_SUCCESS)
		return res;

	if (!user->user_dn) {
		_adcli_err (user->conn, "Cannot find the user %s in the domain", user->sam_name);
		return ADCLI_ERR_CONFIG;
	}

	ret = ldap_delete_ext_s (ldap, user->user_dn, NULL, NULL);

	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (user->conn, ldap,
		                                   "Insufficient permissions to delete user account",
		                                   user->user_dn,
		                                   ADCLI_ERR_CREDENTIALS);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (user->conn, ldap,
		                                   "Couldn't delete user account",
		                                   user->user_dn,
		                                   ADCLI_ERR_DIRECTORY);
	}

	_adcli_info (user->conn, "Deleted user account: %s", user->user_dn);
	return ADCLI_SUCCESS;
}

const char *
adcli_user_get_sam_name (adcli_user *user)
{
	return_val_if_fail (user != NULL, NULL);
	return user->sam_name;
}

const char *
adcli_user_get_ou (adcli_user *user)
{
	return_val_if_fail (user != NULL, NULL);
	return user->user_ou;
}

void
adcli_user_set_ou (adcli_user *user,
                   const char *ou)
{
	return_if_fail (user != NULL);
	_adcli_str_set (&user->user_ou, ou);
}
