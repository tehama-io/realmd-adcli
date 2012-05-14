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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *
adcli_result_to_string (adcli_result res)
{
	switch (res) {
	case ADCLI_SUCCESS:
		return "Success";
	case ADCLI_ERR_UNEXPECTED:
		return "Unexpected or internal system error";
	case ADCLI_ERR_DIRECTORY:
		return "Problem with the Active Directory or connecting to it";
	case ADCLI_ERR_CREDENTIALS:
		return "The administrative credentials are invalid or access is denied";
	case ADCLI_ERR_CONFIG:
		return "The local system has an invalid configuration";
	case ADCLI_ERR_FAIL:
		return "Generic failure";
	}

	return_val_if_reached ("Unknown error");
}

void
_adcli_precond_failed (const char *message,
                       ...)
{
	va_list va;

	va_start (va, message);
	vfprintf (stderr, message, va);
	va_end (va);

	/* TODO: add logic to make these optionally fatal */
}

void
_adcli_strv_free (char **strv)
{
	int i;

	if (strv == NULL)
		return;

	for (i = 0; strv[i] != NULL; i++)
		free (strv[i]);
	free (strv);
}

char **
_adcli_strv_dup (char **strv)
{
	char **result = NULL;
	int length = 0;
	char *string;
	int i;

	if (strv == NULL)
		return NULL;

	for (i = 0; strv[i] != NULL; i++) {
		string = strdup (strv[i]);
		return_val_if_fail (string != NULL, NULL);
		result = _adcli_strv_add (result, string, &length);
		return_val_if_fail (result != NULL, NULL);
	}

	return result;
}

char *
_adcli_strv_join (char **strv,
                  const char *delim)
{
	char *result = NULL;
	int at = 0;
	int dlen;
	int slen;
	int i;

	dlen = strlen (delim);
	for (i = 0; strv[i] != NULL; i++) {
		slen = strlen (strv[i]);
		result = realloc (result, at + dlen + slen + 1);
		return_val_if_fail (result != NULL, NULL);
		if (at != 0) {
			memcpy (result + at, delim, dlen);
			at += dlen;
		}

		memcpy (result + at, strv[i], slen);
		at += slen;
		result[at] = '\0';
	}

	return result;
}

int
_adcli_strv_len (char **strv)
{
	int count = 0;

	if (!strv)
		return 0;

	while (*strv != NULL) {
		strv++;
		count++;
	}

	return count;
}

char **
_adcli_strv_add (char **strv,
                 char *string,
                 int *length)
{
	int len = 0;

	return_val_if_fail (string != NULL, NULL);

	if (length)
		len = *length;
	else
		len = _adcli_strv_len (strv);

	strv = realloc (strv, sizeof (char *) * (len + 2));
	return_val_if_fail (strv != NULL, NULL);

	strv[len] = string;
	strv[len + 1] = 0;
	if (length)
		*length = len + 1;

	return strv;
}

void
_adcli_str_up (char *str)
{
	while (*str != '\0') {
		*str = toupper (*str);
		str++;
	}
}

void
_adcli_str_set (char **field,
                const char *value)
{
	char *newval = NULL;

	if (*field == value)
		return;

	if (value) {
		newval = strdup (value);
		return_if_fail (newval != NULL);
	}

	free (*field);
	*field = newval;
}

void
_adcli_strv_set (char ***field,
                 const char **value)
{
	char **newval = NULL;

	if (*field == (char **)value)
		return;

	if (value) {
		newval = _adcli_strv_dup ((char **)value);
		return_if_fail (newval != NULL);
	}

	_adcli_strv_free (*field);
	*field = newval;
}

char *
_adcli_str_dupn (void *data,
                 size_t len)
{
	char *result;

	result = malloc (len + 1);
	return_val_if_fail (result, NULL);

	memcpy (result, data, len);
	result[len] = '\0';
	return result;
}

int
_adcli_mem_clear (void *data,
                  size_t length)
{
	volatile char *vp;
	int ret = 0;

	if (data == NULL)
		return 0;

	/*
	 * Cracktastic stuff here to help compilers not
	 * optimize this away
	 */

	vp = (volatile char*)data;
	while (length) {
		*vp = 0xAA;
		ret += *vp;
		vp++;
		length--;
	}

	return ret;
}

char *
_adcli_ldap_parse_value (LDAP *ldap,
                         LDAPMessage *results,
                         const char *attr_name)
{
	LDAPMessage *entry;
	struct berval **bvs;
	char *val = NULL;

	entry = ldap_first_entry (ldap, results);
	if (entry != NULL) {
		bvs = ldap_get_values_len (ldap, entry, attr_name);
		if (bvs != NULL) {
			if (bvs[0]) {
				val = _adcli_str_dupn (bvs[0]->bv_val, bvs[0]->bv_len);
				return_val_if_fail (val != NULL, NULL);
			}
			ldap_value_free_len (bvs);
		}
	}

	return val;
}

char **
_adcli_ldap_parse_values (LDAP *ldap,
                          LDAPMessage *results,
                          const char *attr_name)
{
	LDAPMessage *entry;
	struct berval **bvs;
	char **vals = NULL;
	int length = 0;
	char *val;
	int i;

	entry = ldap_first_entry (ldap, results);
	if (entry != NULL) {
		bvs = ldap_get_values_len (ldap, entry, attr_name);
		if (bvs != NULL) {
			for (i = 0; bvs[i] != NULL; i++) {
				val = _adcli_str_dupn (bvs[i]->bv_val,
				                       bvs[i]->bv_len);
				if (val != NULL)
					vals = _adcli_strv_add (vals, val, &length);
			}
			ldap_value_free_len (bvs);
		}
	}

	return vals;
}

char *
_adcli_ldap_parse_dn (LDAP *ldap,
                      LDAPMessage *results)
{
	LDAPMessage *entry;
	const char *dn;
	char *ret;

	entry = ldap_first_entry (ldap, results);
	if (entry != NULL) {
		dn = ldap_get_dn (ldap, entry);
		if (dn != NULL) {
			ret = strdup (dn);
			return_val_if_fail (ret != NULL, NULL);
		}
	}

	return ret;
}

int
_adcli_ldap_ber_case_equal (struct berval *one,
                            struct berval *two)
{
	int i;

	if (one->bv_len != two->bv_len)
		return 0;

	for (i = 0; i < one->bv_len; i++) {
		if (toupper (one->bv_val[i]) != toupper (two->bv_val[i]))
			return 0;
	}

	return 1;
}

int
_adcli_ldap_have_vals (struct berval **want,
                       struct berval **have)
{
	int i, j;

	for (i = 0; want[i] != NULL; i++) {
		int found = 0;
		for (j = 0; have[j] != NULL; j++) {
			if (_adcli_ldap_ber_case_equal (want[i], have[j])) {
				found = 1;
				break;
			}
		}
		if (!found)
			return 0;
	}

	return 1;
}

int
_adcli_ldap_have_mod (LDAPMod *mod,
                      struct berval **have)
{
	struct berval *vals;
	struct berval **pvals;
	int count;
	int i;

	/* Already in berval format, just compare */
	if (mod->mod_op & LDAP_MOD_BVALUES)
		return _adcli_ldap_have_vals (mod->mod_vals.modv_bvals, have);

	/* Count number of values */
	for (i = 0; mod->mod_vals.modv_strvals[i] != 0; i++)
		count++;

	vals = alloca (sizeof (struct berval) * (count));
	pvals = alloca (sizeof (struct berval *) * (count + 1));
	for (i = 0; i < count; i++) {
		vals[i].bv_val = mod->mod_vals.modv_strvals[i];
		vals[i].bv_len = strlen (vals[i].bv_val);
		pvals[i] = vals + i;
	}

	pvals[count] = NULL;
	return _adcli_ldap_have_vals (pvals, have);
}
