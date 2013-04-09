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

#include "adentry.h"
#include "adprivate.h"
#include "seq.h"

#include <assert.h>
#include <stdio.h>

typedef adcli_result (* entry_builder) (adcli_entry *, adcli_attrs *);

struct _adcli_entry {
	int refs;
	adcli_conn *conn;
	const char *object_class;
	entry_builder builder;

	char *sam_name;
	char *entry_dn;
	char *domain_ou;
	char *entry_container;
};

static adcli_entry *
entry_new (adcli_conn *conn,
           const char *object_class,
           entry_builder builder,
           const char *sam_name)
{
	adcli_entry *entry;

	entry = calloc (1, sizeof (adcli_entry));
	return_val_if_fail (entry != NULL, NULL);

	entry->conn = adcli_conn_ref (conn);
	entry->refs = 1;

	entry->sam_name = strdup (sam_name);
	return_val_if_fail (entry->sam_name != NULL, NULL);

	entry->builder = builder;
	entry->object_class = object_class;
	return entry;
}

adcli_entry *
adcli_entry_ref (adcli_entry *entry)
{
	return_val_if_fail (entry != NULL, NULL);
	entry->refs++;
	return entry;

}

static void
entry_free (adcli_entry *entry)
{
	free (entry->sam_name);
	free (entry->entry_container);
	free (entry->entry_dn);
	free (entry->domain_ou);
	adcli_conn_unref (entry->conn);
	free (entry);
}

void
adcli_entry_unref (adcli_entry *entry)
{
	if (entry == NULL)
		return;

	if (--(entry->refs) > 0)
		return;

	entry_free (entry);
}

static adcli_result
update_entry_from_domain (adcli_entry *entry,
                          LDAP *ldap)
{
	const char *attrs[] = { "1.1", NULL };
	LDAPMessage *results;
	LDAPMessage *first;
	const char *base;
	char *filter;
	char *value;
	int ret;

	value = _adcli_ldap_escape_filter (entry->sam_name);
	return_unexpected_if_fail (value != NULL);

	if (asprintf (&filter, "(&(objectClass=%s)(sAMAccountName=%s))", entry->object_class, value) < 0)
		return_unexpected_if_reached ();

	base = adcli_conn_get_default_naming_context (entry->conn);
	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_SUB, filter, (char **)attrs,
	                         0, NULL, NULL, NULL, -1, &results);

	free (filter);
	free (value);

	if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't search for %s entry: %s",
		                                   entry->object_class, entry->sam_name);
	}

	ldap_memfree (entry->entry_dn);
	entry->entry_dn = NULL;

	/* Entry, use its dn */
	first = ldap_first_entry (ldap, results);
	if (first != NULL) {
		entry->entry_dn = ldap_get_dn (ldap, first);
		return_unexpected_if_fail (entry->entry_dn != NULL);
	}

	ldap_msgfree (results);
	return ADCLI_SUCCESS;
}

adcli_result
adcli_entry_load (adcli_entry *entry)
{
	LDAP *ldap;

	ldap = adcli_conn_get_ldap_connection (entry->conn);
	return_unexpected_if_fail (ldap != NULL);

	return update_entry_from_domain (entry, ldap);
}

static adcli_result
lookup_entry_container (adcli_entry *entry,
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

	if (entry->entry_container)
		return ADCLI_SUCCESS;

	base = entry->domain_ou;
	if (base == NULL)
		base = adcli_conn_get_default_naming_context (entry->conn);
	assert (base != NULL);

	ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE,
	                         "(objectClass=*)", attrs, 0, NULL, NULL,
	                         NULL, -1, &results);

	if (ret == LDAP_NO_SUCH_OBJECT && entry->domain_ou) {
		_adcli_err ("The organizational unit does not exist: %s", entry->domain_ou);
		return ADCLI_ERR_DIRECTORY;

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't lookup %s container",
		                                   entry->object_class);
	}

	values = _adcli_ldap_parse_values (ldap, results, "wellKnownObjects");
	ldap_msgfree (results);

	prefix_len = strlen (prefix);
	for (i = 0; values && values[i]; i++) {
		if (strncmp (values[i], prefix, prefix_len) == 0) {
			entry->entry_container = strdup (values[i] + prefix_len);
			return_unexpected_if_fail (entry->entry_container != NULL);
			_adcli_info ("Found well known %s container at: %s",
			             entry->object_class, entry->entry_container);
			break;
		}
	}

	_adcli_strv_free (values);

	/* Try harder */
	if (!entry->entry_container) {
		ret = ldap_search_ext_s (ldap, base, LDAP_SCOPE_BASE,
		                         "(&(objectClass=container)(cn=Users))",
		                         attrs, 0, NULL, NULL, NULL, -1, &results);
		if (ret == LDAP_SUCCESS) {
			entry->entry_container = _adcli_ldap_parse_dn (ldap, results);
			if (entry->entry_container) {
				_adcli_info ("Well known %s container not "
				             "found, but found suitable one at: %s",
				             entry->object_class, entry->entry_container);
			}
		}

		ldap_msgfree (results);
	}

	if (!entry->entry_container && entry->domain_ou) {
		_adcli_warn ("Couldn't find a %s container in the ou, "
		             "creating %s entry directly in: %s", entry->object_class,
		             entry->object_class, entry->domain_ou);
		entry->entry_container = strdup (entry->domain_ou);
		return_unexpected_if_fail (entry->entry_container != NULL);
	}

	if (!entry->entry_container) {
		_adcli_err ("Couldn't find location to create %s entry", entry->object_class);
		return ADCLI_ERR_DIRECTORY;
	}

	return ADCLI_SUCCESS;
}

static adcli_result
calculate_entry_dn (adcli_entry *entry,
                    LDAP *ldap)
{
	adcli_result res;

	/* Now need to find or validate the container */
	res = lookup_entry_container (entry, ldap);
	if (res != ADCLI_SUCCESS)
		return res;

	assert (entry->entry_container);

	free (entry->entry_dn);
	entry->entry_dn = NULL;

	if (asprintf (&entry->entry_dn, "CN=%s,%s", entry->sam_name, entry->entry_container) < 0)
		return_unexpected_if_reached ();

	_adcli_info ("Calculated %s entry: %s", entry->object_class, entry->entry_dn);
	return ADCLI_SUCCESS;
}

adcli_result
adcli_entry_create (adcli_entry *entry,
                    adcli_attrs *attrs)
{
	adcli_result res;
	char *string;
	LDAP *ldap;
	int ret;

	ldap = adcli_conn_get_ldap_connection (entry->conn);
	return_unexpected_if_fail (ldap != NULL);

	/* Find the entry */
	res = update_entry_from_domain (entry, ldap);
	if (res != ADCLI_SUCCESS)
		return res;

	if (entry->entry_dn) {
		_adcli_err ("The %s entry %s already exists in the domain",
		            entry->object_class, entry->sam_name);
		return ADCLI_ERR_CONFIG;
	}

	res = calculate_entry_dn (entry, ldap);
	if (res != ADCLI_SUCCESS)
		return res;

	assert (entry->entry_dn);

	adcli_attrs_replace (attrs, "objectClass", entry->object_class, NULL);
	adcli_attrs_replace (attrs, "cn", entry->sam_name, NULL);
	adcli_attrs_replace (attrs, "sAMAccountName", entry->sam_name, NULL);

	assert (entry->builder != NULL);
	res = (entry->builder) (entry, attrs);
	if (res != ADCLI_SUCCESS)
		return res;

	string = _adcli_ldap_mods_to_string (attrs->mods);
	_adcli_info ("Creating %s with attributes: %s", entry->object_class, string);
	free (string);

	/* Fill in the work attributes */
	seq_filter (attrs->mods, &attrs->len, NULL,
	            _adcli_ldap_filter_for_add, _adcli_ldap_mod_free);

	ret = ldap_add_ext_s (ldap, entry->entry_dn, attrs->mods, NULL, NULL);

	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to create %s entry: %s",
		                                   entry->object_class, entry->entry_dn);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't create %s entry: %s",
		                                   entry->object_class, entry->entry_dn);
	}

	_adcli_info ("Created %s entry: %s", entry->object_class, entry->entry_dn);
	return ADCLI_SUCCESS;
}

adcli_result
adcli_entry_modify (adcli_entry *entry,
                    adcli_attrs *attrs)
{
	adcli_result res;
	char *string;
	LDAP *ldap;
	int ret;

	ldap = adcli_conn_get_ldap_connection (entry->conn);
	return_unexpected_if_fail (ldap != NULL);

	/* Find the entry */
	res = update_entry_from_domain (entry, ldap);
	if (res != ADCLI_SUCCESS)
		return res;

	if (!entry->entry_dn) {
		_adcli_err ("Cannot find the %s entry %s in the domain",
		            entry->object_class, entry->sam_name);
		return ADCLI_ERR_CONFIG;
	}

	string = _adcli_ldap_mods_to_string (attrs->mods);
	_adcli_info ("Modifying %s entry attributes: %s", entry->object_class, string);
	free (string);

	ret = ldap_modify_ext_s (ldap, entry->entry_dn, attrs->mods, NULL, NULL);

	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to modify %s entry: %s",
		                                   entry->object_class, entry->entry_dn);

	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't modify %s entry: %s",
		                                   entry->object_class, entry->entry_dn);
	}

	_adcli_info ("Modified %s entry: %s", entry->object_class, entry->entry_dn);
	return ADCLI_SUCCESS;
}

adcli_result
adcli_entry_delete (adcli_entry *entry)
{
	adcli_result res;
	LDAP *ldap;
	int ret;

	ldap = adcli_conn_get_ldap_connection (entry->conn);
	return_unexpected_if_fail (ldap != NULL);

	/* Find the user */
	res = update_entry_from_domain (entry, ldap);
	if (res != ADCLI_SUCCESS)
		return res;

	if (!entry->entry_dn) {
		_adcli_err ("Cannot find the %s entry %s in the domain",
		            entry->object_class, entry->sam_name);
		return ADCLI_ERR_CONFIG;
	}

	ret = ldap_delete_ext_s (ldap, entry->entry_dn, NULL, NULL);

	if (ret == LDAP_INSUFFICIENT_ACCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_CREDENTIALS,
		                                   "Insufficient permissions to delete %s entry: %s",
		                                   entry->object_class, entry->entry_dn);
	} else if (ret != LDAP_SUCCESS) {
		return _adcli_ldap_handle_failure (ldap, ADCLI_ERR_DIRECTORY,
		                                   "Couldn't delete %s entry: %s",
		                                   entry->object_class, entry->entry_dn);
	}

	_adcli_info ("Deleted %s: %s", entry->object_class, entry->entry_dn);
	return ADCLI_SUCCESS;
}

const char *
adcli_entry_get_sam_name (adcli_entry *entry)
{
	return_val_if_fail (entry != NULL, NULL);
	return entry->sam_name;
}

const char *
adcli_entry_get_dn (adcli_entry *entry)
{
	return_val_if_fail (entry != NULL, NULL);
	return entry->entry_dn;
}

const char *
adcli_entry_get_domain_ou (adcli_entry *entry)
{
	return_val_if_fail (entry != NULL, NULL);
	return entry->domain_ou;
}

void
adcli_entry_set_domain_ou (adcli_entry *entry,
                           const char *ou)
{
	return_if_fail (entry != NULL);
	_adcli_str_set (&entry->domain_ou, ou);
}

static adcli_result
user_entry_builder (adcli_entry *entry,
                    adcli_attrs *attrs)
{
	char *string;

	adcli_attrs_replace (attrs, "userAccountControl", "514", NULL) /* NORMAL_ACCOUNT | ACCOUNTDISABLE */;
	if (!adcli_attrs_have (attrs, "displayName"))
		adcli_attrs_replace (attrs, "displayName", entry->sam_name, NULL);
	if (!adcli_attrs_have (attrs, "name"))
		adcli_attrs_replace (attrs, "name", entry->sam_name, NULL);
	if (!adcli_attrs_have (attrs, "userPrincipalName")) {
		if (asprintf (&string, "%s@%s", entry->sam_name, adcli_conn_get_domain_name (entry->conn)) < 0)
			return_unexpected_if_reached ();
		adcli_attrs_replace (attrs, "userPrincipalName", string, NULL);
		free (string);
	}

	return ADCLI_SUCCESS;
}

adcli_entry *
adcli_entry_new_user (adcli_conn *conn,
                      const char *sam_name)
{
	return_val_if_fail (conn != NULL, NULL);
	return_val_if_fail (sam_name != NULL, NULL);
	return entry_new (conn, "user", user_entry_builder, sam_name);
}

static adcli_result
group_entry_builder (adcli_entry *entry,
                     adcli_attrs *attrs)
{
	if (!adcli_attrs_have (attrs, "description"))
		adcli_attrs_replace (attrs, "description", entry->sam_name, NULL);
	if (!adcli_attrs_have (attrs, "name"))
		adcli_attrs_replace (attrs, "name", entry->sam_name, NULL);

	return ADCLI_SUCCESS;
}

adcli_entry *
adcli_entry_new_group (adcli_conn *conn,
                       const char *sam_name)
{
	return_val_if_fail (conn != NULL, NULL);
	return_val_if_fail (sam_name != NULL, NULL);
	return entry_new (conn, "group", group_entry_builder, sam_name);
}
