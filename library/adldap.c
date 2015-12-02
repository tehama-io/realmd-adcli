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

#include "adcli.h"
#include "adprivate.h"

#include <gssapi/gssapi_krb5.h>
#include <krb5/krb5.h>
#include <ldap.h>
#include <sasl/sasl.h>

#include <assert.h>
#include <ctype.h>

adcli_result
_adcli_ldap_handle_failure (LDAP *ldap,
                            adcli_result defres,
                            const char *desc,
                            ...)
{
	va_list va;
	char *message;
	char *info;
	int code;

	if (ldap_get_option (ldap, LDAP_OPT_RESULT_CODE, &code) != 0)
		return_unexpected_if_reached ();

	if (code == LDAP_NO_MEMORY)
		return_unexpected_if_reached ();

	if (ldap_get_option (ldap, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void*)&info) != 0)
		info = NULL;

	va_start (va, desc);
	if (vasprintf (&message, desc, va) < 0)
		return_unexpected_if_reached ();
	va_end (va);

	_adcli_err ("%s: %s",
	            message,
	            info ? info : ldap_err2string (code));

	free (message);
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
_adcli_ldap_have_in_mod (LDAPMod *mod,
                         struct berval **have)
{
	struct berval *vals;
	struct berval **pvals;
	int count = 0;
	int i;
	int ret;

	/* Already in berval format, just compare */
	if (mod->mod_op & LDAP_MOD_BVALUES)
		return _adcli_ldap_have_vals (mod->mod_vals.modv_bvals, have);

	/* Count number of values */
	for (i = 0; mod->mod_vals.modv_strvals[i] != 0; i++)
		count++;

	vals = malloc (sizeof (struct berval) * (count + 1));
	pvals = malloc (sizeof (struct berval *) * (count + 1));
	for (i = 0; i < count; i++) {
		vals[i].bv_val = mod->mod_vals.modv_strvals[i];
		vals[i].bv_len = strlen (vals[i].bv_val);
		pvals[i] = vals + i;
	}

	pvals[count] = NULL;
	ret = _adcli_ldap_have_vals (pvals, have);
	free (vals);
	free (pvals);

	return ret;
}

int
_adcli_ldap_filter_for_add (void *unused,
                            void *value)
{
	LDAPMod *mod = value;

	/* No need to care about this */
	if ((mod->mod_op & LDAP_MOD_OP) == LDAP_MOD_DELETE)
		return -1;

	if (mod->mod_op & LDAP_MOD_BVALUES) {
		if (mod->mod_vals.modv_bvals == NULL ||
		    mod->mod_vals.modv_bvals[0] == NULL)
			return -1;
		mod->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
	} else {
		if (mod->mod_vals.modv_strvals == NULL ||
		    mod->mod_vals.modv_strvals[0] == NULL)
			return -1;
		mod->mod_op = LDAP_MOD_ADD;
	}

	return 0;
}

#define LDAP_NO_ESCAPE "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_0123456789"
#define LDAP_HEX "0123456789abcdef"

char *
_adcli_ldap_escape_filter (const char *value)
{
	const char *in;
	char *out, *result;
	size_t pos;
	size_t len;

	assert (value != NULL);

	len = strlen (value);
	result = malloc ((len * 3) + 1);
	return_val_if_fail (result != NULL, NULL);

	in = value;
	out = result;

	while (*in != '\0') {
		pos = strspn (in, LDAP_NO_ESCAPE);
		if (pos > 0) {
			memcpy (out, in, pos);
			in += pos;
			out += pos;
		}

		while (*in != '\0' && !strchr (LDAP_NO_ESCAPE, *in)) {
			*(out++) = '\\';
			*(out++) = LDAP_HEX[*in >> 4 & 0xf];
			*(out++) = LDAP_HEX[*in & 0xf];
			in++;
		}
	}

	*out = 0;
	return result;
}

static int
berval_case_equals (const struct berval *v1,
                    const struct berval *v2)
{
	return (v1->bv_len == v2->bv_len &&
	        strncasecmp (v1->bv_val, v2->bv_val, v1->bv_len) == 0);
}

int
_adcli_ldap_dn_has_ancestor (const char *dn,
                             const char *ancestor)
{
	LDAPDN ld_dn;
	LDAPDN ld_suffix;
	LDAPRDN r_dn;
	LDAPRDN r_suffix;
	int ln_dn;
	int ln_suffix;
	int match = 0;
	int rc;
	int i, j;

	rc = ldap_str2dn (dn, &ld_dn, LDAP_DN_FORMAT_LDAPV3);
	return_val_if_fail (rc == LDAP_SUCCESS, 0);

	/* This is usually provided by user, be less whiny about formatting issues */
	rc = ldap_str2dn (ancestor, &ld_suffix, LDAP_DN_FORMAT_LDAPV3);
	if (rc != LDAP_SUCCESS)
		return 0;

	/* Calculate length of both */
	for (i = 0, ln_dn = 0; ld_dn[i] != NULL; i++)
		ln_dn++;
	for (i = 0, ln_suffix = 0; ld_suffix[i] != NULL; i++)
		ln_suffix++;

	match = (ln_suffix < ln_dn);
	for (i = 1; match && i <= ln_suffix; i++) {
		r_dn = ld_dn[ln_dn - i];
		r_suffix = ld_suffix[ln_suffix - i];
		for (j = 0; match && r_dn[j] != NULL && r_suffix[j] != NULL; j++) {
			if (!berval_case_equals (&(r_dn[j]->la_attr), &(r_suffix[j]->la_attr)) ||
			    !berval_case_equals (&(r_dn[j]->la_value), &(r_suffix[j]->la_value)))
				match = 0;
		}
	}

	ldap_dnfree (ld_dn);
	ldap_dnfree (ld_suffix);

	return match;
}

int
_adcli_ldap_mod_compar (void *match,
                        void *mod)
{
	return strcmp (((LDAPMod *)match)->mod_type,
	               ((LDAPMod *)mod)->mod_type);
}

LDAPMod *
_adcli_ldap_mod_new (int mod_op,
                     const char *type,
                     const char **values)
{
	LDAPMod *mod;

	mod = calloc (1, sizeof (LDAPMod));
	return_val_if_fail (mod != NULL, NULL);

	mod->mod_op = mod_op;
	mod->mod_type = strdup (type);
	return_val_if_fail (mod->mod_type != NULL, NULL);

	if (values) {
		mod->mod_vals.modv_strvals = _adcli_strv_dup ((char **)values);
		return_val_if_fail (mod->mod_vals.modv_strvals != NULL, NULL);
	}

	return mod;
}

LDAPMod *
_adcli_ldap_mod_new1 (int mod_op,
                      const char *type,
                      const char *value)
{
	const char *values[] = { value, NULL };
	return _adcli_ldap_mod_new (mod_op, type, values);
}

void
_adcli_ldap_mod_free (void *value)
{
	LDAPMod *mod = value;

	if (mod == NULL)
		return;

	free (mod->mod_type);

	if (mod->mod_op & LDAP_MOD_BVALUES)
		ldap_value_free_len (mod->mod_vals.modv_bvals);
	else
		_adcli_strv_free (mod->mod_vals.modv_strvals);
	free (mod);
}

char *
_adcli_ldap_mods_to_string (LDAPMod **mods)
{
	char **names;
	int names_len;
	char *string;
	int i;

	names = NULL;
	names_len = 0;

	for (i = 0; mods[i] != NULL; i++)
		names = _adcli_strv_add (names, strdup (mods[i]->mod_type), &names_len);
	string = _adcli_strv_join (names, ", ");

	_adcli_strv_free (names);
	return string;
}

#ifdef LDAP_TESTS

#include "seq.h"
#include "test.h"

static void
test_compar (void)
{
	LDAPMod one = { LDAP_MOD_ADD, "one" };
	LDAPMod two = { LDAP_MOD_ADD, "two" };
	LDAPMod same = { LDAP_MOD_REPLACE, "one" };

	assert (_adcli_ldap_mod_compar (&one, &two) < 0);
	assert (_adcli_ldap_mod_compar (&two, &one) > 0);
	assert (_adcli_ldap_mod_compar (&one, &one) == 0);
	assert (_adcli_ldap_mod_compar (&one, &same) == 0);
}

static void
test_new_free (void)
{
	const char *values[] = { "value", "two", "three", NULL };
	LDAPMod *mod;

	mod = _adcli_ldap_mod_new (LDAP_MOD_ADD, "test", values);
	assert (mod != NULL);

	assert (mod->mod_op == LDAP_MOD_ADD);
	assert_str_eq (mod->mod_type, "test");
	assert_num_eq (seq_count (mod->mod_vals.modv_strvals), 3);
	assert_str_eq (mod->mod_vals.modv_strvals[0], "value");
	assert_str_eq (mod->mod_vals.modv_strvals[1], "two");
	assert_str_eq (mod->mod_vals.modv_strvals[2], "three");
	assert (mod->mod_vals.modv_strvals[3] == NULL);

	_adcli_ldap_mod_free (mod);
}

static void
test_new1 (void)
{
	LDAPMod *mod;

	mod = _adcli_ldap_mod_new1 (LDAP_MOD_ADD, "test", "one");
	assert (mod != NULL);

	assert (mod->mod_op == LDAP_MOD_ADD);
	assert_str_eq (mod->mod_type, "test");
	assert_num_eq (seq_count (mod->mod_vals.modv_strvals), 1);
	assert_str_eq (mod->mod_vals.modv_strvals[0], "one");
	assert (mod->mod_vals.modv_strvals[1] == NULL);

	_adcli_ldap_mod_free (mod);
}

static void
test_new_null (void)
{
	LDAPMod *mod;

	mod = _adcli_ldap_mod_new (LDAP_MOD_ADD, "test", NULL);
	assert (mod != NULL);

	assert (mod->mod_op == LDAP_MOD_ADD);
	assert_str_eq (mod->mod_type, "test");
	assert_num_eq (seq_count (mod->mod_vals.modv_strvals), 0);
	assert (mod->mod_vals.modv_strvals == NULL);

	_adcli_ldap_mod_free (mod);
}

static void
test_free_null (void)
{
	_adcli_ldap_mod_free (NULL);
}

static void
test_to_string (void)
{
	char *vals_objectClass[] = { "computer", NULL };
	LDAPMod objectClass = { 0, "objectClass", { vals_objectClass, } };
	char *vals_sAMAccountName[] = { "value", NULL };
	LDAPMod sAMAccountName = { 0, "sAMAccountName", { vals_sAMAccountName, } };
	char *vals_userAccountControl[] = { "69632", NULL };
	LDAPMod userAccountControl = { 0, "userAccountControl", { vals_userAccountControl, } };

	LDAPMod *mods[] = {
		&objectClass,
		&sAMAccountName,
		&userAccountControl,
		NULL,
	};

	char *string;

	string = _adcli_ldap_mods_to_string (mods);
	assert_str_eq (string, "objectClass, sAMAccountName, userAccountControl");
	free (string);
}

int
main (int argc,
      char *argv[])
{
	test_func (test_compar, "/ldap/compar");
	test_func (test_new_free, "/ldap/new_free");
	test_func (test_new1, "/ldap/new1");
	test_func (test_new_null, "/ldap/new_null");
	test_func (test_free_null, "/ldap/free_null");
	test_func (test_to_string, "/ldap/to_string");
	return test_run (argc, argv);
}

#endif /* LDAP_TESTS */
