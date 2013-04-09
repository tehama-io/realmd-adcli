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
	LDAPMod match = { -1, (char *)name, };
	LDAPMod *mod;

	return_val_if_fail (attrs != NULL, 0);
	return_val_if_fail (name != NULL, 0);

	mod = seq_lookup ((void **)attrs->mods, &attrs->len,
	                  &match, _adcli_ldap_mod_compar);

	return mod ? 1 : 0;
}

static void
attrs_insert1 (adcli_attrs *attrs,
               int mod_op,
               const char *name,
               const char *value)
{
	LDAPMod match = { 0, (char *)name, };
	LDAPMod *mod;

	mod = seq_lookup ((void **)attrs->mods, &attrs->len,
	                  &match, _adcli_ldap_mod_compar);

	/* A new attribute */
	if (mod == NULL) {
		const char *values[] = { value, NULL };
		mod = _adcli_ldap_mod_new (mod_op, name, values);
		return_if_fail (mod != NULL);

		attrs->mods = (LDAPMod **)seq_insert ((void **)attrs->mods,
		                                      &attrs->len, mod,
		                                      _adcli_ldap_mod_compar,
		                                      _adcli_ldap_mod_free);

	/* Add a value */
	} else {
		return_if_fail (mod->mod_op == mod_op);
		mod->mod_vals.modv_strvals =
		     _adcli_strv_add (mod->mod_vals.modv_strvals,
		                      strdup (value), NULL);
	}
}

static void
attrs_insert (adcli_attrs *attrs,
              int mod_type,
              const char *name,
              const char **values)
{
	LDAPMod *mod;

	mod = _adcli_ldap_mod_new (mod_type, name, values);
	return_if_fail (mod != NULL);

	attrs->mods = (LDAPMod **)seq_insert ((void **)attrs->mods,
	                                      &attrs->len, mod,
	                                      _adcli_ldap_mod_compar,
	                                      _adcli_ldap_mod_free);
}

static void
attrs_insertv (adcli_attrs *attrs,
                   int mod_type,
                   const char *name,
                   const char *value,
                   va_list va)
{
	const char *fast[] = { value, NULL };
	char **values = NULL;
	int num = 0;

	fast[1] = va_arg(va, const char *);
	if (fast[1] == NULL) {
		attrs_insert (attrs, mod_type, name, fast);
		return;
	}

	values = seq_push (values, &num, (void *)fast[0]);
	values = seq_push (values, &num, (void *)fast[1]);

	while ((value = va_arg (va, const char *)) != NULL)
		values = seq_push (values, &num, (void *)value);

	attrs_insert (attrs, mod_type, name, (const char **)values);
	seq_free (values, NULL);
}

void
adcli_attrs_add1 (adcli_attrs *attrs,
                  const char *name,
                  const char *value)
{
	return_if_fail (attrs != NULL);
	return_if_fail (name != NULL);
	return_if_fail (value != NULL);

	attrs_insert1 (attrs, LDAP_MOD_ADD, name, value);
}

void
adcli_attrs_add (adcli_attrs *attrs,
                 const char *name,
                 const char *value,
                 ...)
{
	va_list va;

	return_if_fail (attrs != NULL);
	return_if_fail (name != NULL);
	return_if_fail (value != NULL);

	va_start (va, value);
	attrs_insertv (attrs, LDAP_MOD_ADD, name, value, va);
	va_end (va);
}


void
adcli_attrs_replace (adcli_attrs *attrs,
                     const char *name,
                     const char *value,
                     ...)
{
	va_list va;

	return_if_fail (attrs != NULL);
	return_if_fail (name != NULL);
	return_if_fail (value != NULL);

	va_start (va, value);
	attrs_insertv (attrs, LDAP_MOD_REPLACE, name, value, va);
	va_end (va);
}

void
adcli_attrs_delete1 (adcli_attrs *attrs,
                     const char *name,
                     const char *value)
{
	return_if_fail (attrs != NULL);
	return_if_fail (name != NULL);
	return_if_fail (value != NULL);

	attrs_insert1 (attrs, LDAP_MOD_DELETE, name, value);
}

void
adcli_attrs_delete (adcli_attrs *attrs,
                    const char *name,
                    const char *value,
                    ...)
{
	va_list va;

	return_if_fail (attrs != NULL);
	return_if_fail (name != NULL);
	return_if_fail (value != NULL);

	va_start (va, value);
	attrs_insertv (attrs, LDAP_MOD_DELETE, name, value, va);
	va_end (va);
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

	adcli_attrs_add (attrs, "blah", "value", "two", NULL);
	adcli_attrs_add1 (attrs, "blah", "three");

	adcli_attrs_add (attrs, "other", "wheee", NULL);

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
test_replace (void)
{
	adcli_attrs *attrs;

	attrs = adcli_attrs_new ();

	adcli_attrs_add1 (attrs, "blah", "value");
	adcli_attrs_add1 (attrs, "blah", "two");

	adcli_attrs_replace (attrs, "blah", "new", NULL);

	adcli_attrs_add (attrs, "other", "wheee", NULL);

	assert_num_eq (attrs->len, 2);

	assert (attrs->mods[0]->mod_op == LDAP_MOD_REPLACE);
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
	test_func (test_replace, "/attrs/replace");
	return test_run (argc, argv);
}

#endif /* ATTRS_TESTS */
