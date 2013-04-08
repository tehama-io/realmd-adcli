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

#include "adattrs.h"
#include "adprivate.h"
#include "seq.h"

#include <assert.h>
#include <stdlib.h>

adcli_attrs *
adcli_attrs_new (void)
{
	adcli_attrs *attrs;

	attrs = calloc (1, sizeof (adcli_attrs));
	return_val_if_fail (attrs != NULL, NULL);

	return attrs;
}

int
adcli_attrs_have (adcli_attrs *attrs,
                  const char *name)
{
	LDAPMod match = { 0, (char *)name, };
	LDAPMod *mod;

	return_val_if_fail (attrs != NULL, 0);
	return_val_if_fail (name != NULL, 0);

	mod = seq_lookup ((void **)attrs->mods, &attrs->len,
	                  &match, _adcli_ldap_mod_compar);

	return mod ? 1 : 0;
}

void
adcli_attrs_add (adcli_attrs *attrs,
                 const char *name,
                 const char *value)
{
	LDAPMod match = { 0, (char *)name, };
	LDAPMod *mod;

	return_if_fail (attrs != NULL);
	return_if_fail (name != NULL);
	return_if_fail (value != NULL);

	mod = seq_lookup ((void **)attrs->mods, &attrs->len,
	                  &match, _adcli_ldap_mod_compar);

	/* A new attribute */
	if (mod == NULL) {
		const char *values[] = { value, NULL };
		mod = _adcli_ldap_mod_new (LDAP_MOD_ADD, name, values);
		return_if_fail (mod != NULL);

		attrs->mods = (LDAPMod **)seq_insert ((void **)attrs->mods,
		                                      &attrs->len, mod,
		                                      _adcli_ldap_mod_compar,
		                                      _adcli_ldap_mod_free);

	/* Add a value */
	} else {
		mod->mod_vals.modv_strvals =
		     _adcli_strv_add (mod->mod_vals.modv_strvals,
		                      strdup (value), NULL);
	}
}

void
adcli_attrs_set (adcli_attrs *attrs,
                 const char *name,
                 const char *value)
{
	const char *values[] = { value, NULL };
	LDAPMod *mod;

	return_if_fail (attrs != NULL);
	return_if_fail (name != NULL);
	return_if_fail (value != NULL);

	mod = _adcli_ldap_mod_new (LDAP_MOD_ADD, name, values);
	return_if_fail (mod != NULL);

	attrs->mods = (LDAPMod **)seq_insert ((void **)attrs->mods,
	                                      &attrs->len, mod,
	                                      _adcli_ldap_mod_compar,
	                                      _adcli_ldap_mod_free);
}

void
adcli_attrs_take (adcli_attrs *attrs,
                  const char *name,
                  char *value)
{
	LDAPMod *mod;

	return_if_fail (attrs != NULL);
	return_if_fail (name != NULL);
	return_if_fail (value != NULL);

	mod = _adcli_ldap_mod_new (LDAP_MOD_ADD, name, NULL);
	return_if_fail (mod != NULL);

	mod->mod_vals.modv_strvals = _adcli_strv_add (NULL, value, 0);
	return_if_fail (mod->mod_vals.modv_strvals != NULL);

	attrs->mods = (LDAPMod **)seq_insert ((void **)attrs->mods,
	                                      &attrs->len, mod,
	                                      _adcli_ldap_mod_compar,
	                                      _adcli_ldap_mod_free);
}

void
adcli_attrs_free (adcli_attrs *attrs)
{
	if (!attrs)
		return;

	seq_free (attrs->mods, _adcli_ldap_mod_free);
	free (attrs);
}

#ifdef ATTRS_TESTS

#include "test.h"

static void
test_new_free (void)
{
	adcli_attrs *attrs;

	attrs = adcli_attrs_new ();
	assert (attrs != NULL);

	adcli_attrs_free (attrs);
}

static void
test_free_null (void)
{
	adcli_attrs_free (NULL);
}

static void
test_adda (void)
{
	adcli_attrs *attrs;

	attrs = adcli_attrs_new ();

	adcli_attrs_add (attrs, "blah", "value");
	adcli_attrs_add (attrs, "blah", "two");
	adcli_attrs_add (attrs, "blah", "three");

	adcli_attrs_add (attrs, "other", "wheee");

	assert_num_eq (attrs->len, 2);

	assert (attrs->mods[0]->mod_op == LDAP_MOD_ADD);
	assert_str_eq (attrs->mods[0]->mod_type, "blah");
	assert_num_eq (seq_count (attrs->mods[0]->mod_vals.modv_strvals), 3);
	assert_str_eq (attrs->mods[0]->mod_vals.modv_strvals[0], "value");
	assert_str_eq (attrs->mods[0]->mod_vals.modv_strvals[1], "two");
	assert_str_eq (attrs->mods[0]->mod_vals.modv_strvals[2], "three");
	assert (attrs->mods[0]->mod_vals.modv_strvals[3] == NULL);

	assert (attrs->mods[1]->mod_op == LDAP_MOD_ADD);
	assert_str_eq (attrs->mods[1]->mod_type, "other");
	assert_num_eq (seq_count (attrs->mods[1]->mod_vals.modv_strvals), 1);
	assert_str_eq (attrs->mods[1]->mod_vals.modv_strvals[0], "wheee");
	assert (attrs->mods[1]->mod_vals.modv_strvals[1] == NULL);

	adcli_attrs_free (attrs);
}

static void
test_set_take (void)
{
	adcli_attrs *attrs;

	attrs = adcli_attrs_new ();

	adcli_attrs_add (attrs, "blah", "value");
	adcli_attrs_add (attrs, "blah", "two");

	adcli_attrs_set (attrs, "blah", "new");

	adcli_attrs_take (attrs, "other", strdup ("wheee"));

	assert_num_eq (attrs->len, 2);

	assert (attrs->mods[0]->mod_op == LDAP_MOD_ADD);
	assert_str_eq (attrs->mods[0]->mod_type, "blah");
	assert_num_eq (seq_count (attrs->mods[0]->mod_vals.modv_strvals), 1);
	assert_str_eq (attrs->mods[0]->mod_vals.modv_strvals[0], "new");
	assert (attrs->mods[0]->mod_vals.modv_strvals[1] == NULL);

	assert (attrs->mods[1]->mod_op == LDAP_MOD_ADD);
	assert_str_eq (attrs->mods[1]->mod_type, "other");
	assert_num_eq (seq_count (attrs->mods[1]->mod_vals.modv_strvals), 1);
	assert_str_eq (attrs->mods[1]->mod_vals.modv_strvals[0], "wheee");
	assert (attrs->mods[1]->mod_vals.modv_strvals[1] == NULL);

	adcli_attrs_free (attrs);
}

int
main (int argc,
      char *argv[])
{
	test_func (test_new_free, "/attrs/new_free");
	test_func (test_free_null, "/attrs/free_null");
	test_func (test_adda, "/attrs/add");
	test_func (test_set_take, "/attrs/set_take");
	return test_run (argc, argv);
}

#endif /* ATTRS_TESTS */
