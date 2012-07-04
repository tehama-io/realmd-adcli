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

#include <gssapi/gssapi_krb5.h>
#include <krb5/krb5.h>
#include <ldap.h>
#include <sasl/sasl.h>

#include <ctype.h>

adcli_result
_adcli_ldap_handle_failure (adcli_conn *conn,
                            LDAP *ldap,
                            const char *desc,
                            const char *arg,
                            adcli_result defres)
{
	char *info;
	int code;

	if (ldap_get_option (ldap, LDAP_OPT_RESULT_CODE, &code) != 0)
		return_unexpected_if_reached ();

	if (code == LDAP_NO_MEMORY)
		return_unexpected_if_reached ();

	if (ldap_get_option (ldap, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void*)&info) != 0)
		info = NULL;

	_adcli_err (conn, "%s%s%s: %s",
	            desc,
	            arg ? ": " : "",
	            arg ? arg : "",
	            info ? info : ldap_err2string (code));

	return defres;
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
	char *ret = NULL;

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
	int count = 0;
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
