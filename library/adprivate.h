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

#ifndef ADPRIVATE_H_
#define ADPRIVATE_H_

#include "adattrs.h"
#include "adconn.h"

#include <stdarg.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

#include <ldap.h>

/* Utilities */

#if !defined(__cplusplus) && (__GNUC__ > 2)
#define GNUC_PRINTF(x, y) __attribute__((__format__(__printf__, x, y)))
#define GNUC_WARN_UNUSED __attribute__((warn_unused_result))
#else
#define GNUC_PRINTF(x, y)
#define GNUC_WARN_UNUSED
#endif

#define return_val_if_fail(x, v) \
	do { if (!(x)) { \
	     _adcli_precond_failed ("adcli: '%s' not true at %s\n", #x, __func__); \
	     return v; \
	} } while (0)

#define return_unexpected_if_fail(x) \
	return_val_if_fail ((x), ADCLI_ERR_UNEXPECTED)

#define return_if_fail(x) \
	do { if (!(x)) { \
	     _adcli_precond_failed ("adcli: '%s' not true at %s\n", #x, __func__); \
	     return; \
	} } while (0)

#define return_if_reached() \
	do { \
	     _adcli_precond_failed ("adcli: shouldn't be reached at %s\n", __func__); \
	     return; \
	} while (0)

#define return_val_if_reached(v) \
	do { \
	     _adcli_precond_failed ("adcli: shouldn't be reached at %s\n", __func__); \
	     return v; \
	} while (0)

#define return_unexpected_if_reached() \
	return_val_if_reached (ADCLI_ERR_UNEXPECTED)

static inline void
_adcli_precond_failed (const char *message,
                       ...) GNUC_PRINTF (1, 2);

static inline void
_adcli_precond_failed (const char *message,
                       ...)
{
	va_list va;
	va_start (va, message);
	vfprintf (stderr, message, va);
	va_end (va);
	/* TODO: add logic to make these optionally fatal */
}

void           _adcli_err                    (const char *format,
                                             ...) GNUC_PRINTF(1, 2);

void           _adcli_warn                   (const char *format,
                                             ...) GNUC_PRINTF(1, 2);

void           _adcli_info                   (const char *format,
                                             ...) GNUC_PRINTF(1, 2);

int            _adcli_strv_len               (char **strv);

char **        _adcli_strv_add               (char **strv,
                                              char *string,
                                              int *length) GNUC_WARN_UNUSED;

void           _adcli_strv_free              (char **strv);

char **        _adcli_strv_dup               (char **strv) GNUC_WARN_UNUSED;

char *         _adcli_strv_join              (char **strv,
                                              const char *delim);

void           _adcli_str_up                 (char *str);

void           _adcli_str_down               (char *str);

char *         _adcli_str_dupn               (void *data,
                                              size_t len);

void           _adcli_str_set                (char **field,
                                              const char *value);

void           _adcli_strv_set               (char ***field,
                                              const char **value);

int            _adcli_password_free          (char *password);

int            _adcli_write_all              (int fd,
                                              const char *buf,
                                              int len);

/* Connection helpers */

char *        _adcli_calc_reset_password     (const char *computer_name);

krb5_error_code  _adcli_kinit_computer_creds      (adcli_conn *conn,
                                                   const char *in_tkt_service,
                                                   krb5_ccache ccache,
                                                   krb5_creds *creds);

krb5_error_code  _adcli_kinit_user_creds          (adcli_conn *conn,
                                                   const char *in_tkt_service,
                                                   krb5_ccache ccache,
                                                   krb5_creds *creds);

/* LDAP helpers */

adcli_result  _adcli_ldap_handle_failure     (LDAP *ldap,
                                              adcli_result defres,
                                              const char *desc,
                                              ...) GNUC_PRINTF(3, 4);

char *        _adcli_ldap_parse_value        (LDAP *ldap,
                                              LDAPMessage *results,
                                              const char *attr_name);

char **       _adcli_ldap_parse_values       (LDAP *ldap,
                                              LDAPMessage *results,
                                              const char *attr_name);

char *        _adcli_ldap_parse_dn           (LDAP *ldap,
                                              LDAPMessage *results);

int           _adcli_ldap_ber_case_equal     (struct berval *one,
                                              struct berval *two);

int           _adcli_ldap_have_vals          (struct berval **want,
                                              struct berval **have);

int           _adcli_ldap_have_in_mod        (LDAPMod *want,
                                              struct berval **have);

char *        _adcli_ldap_escape_filter      (const char *value);

int           _adcli_ldap_dn_has_ancestor    (const char *dn,
                                              const char *ancestor);

int           _adcli_ldap_mod_compar         (void *match,
                                              void *mod);

int           _adcli_ldap_filter_for_add     (void *unused,
                                              void *mod);

LDAPMod *     _adcli_ldap_mod_new            (int mod_op,
                                              const char *type,
                                              const char **values);

LDAPMod *     _adcli_ldap_mod_new1           (int mod_op,
                                              const char *type,
                                              const char *value);

void          _adcli_ldap_mod_free           (void *mod);

char *        _adcli_ldap_mods_to_string     (LDAPMod **mods);

/* KRB5 helpers */

krb5_error_code  _adcli_krb5_build_principal      (krb5_context k5,
                                                   const char *user,
                                                   const char *realm,
                                                   krb5_principal *principal);

krb5_error_code  _adcli_krb5_keytab_clear         (krb5_context k5,
                                                   krb5_keytab keytab,
                                                   krb5_boolean (* match_func) (krb5_context,
                                                                krb5_keytab_entry *, void *),
                                                   void *match_data);

krb5_error_code  _adcli_krb5_keytab_clear_all     (krb5_context k5,
                                                   krb5_keytab keytab);

krb5_error_code  _adcli_krb5_keytab_add_entries   (krb5_context k5,
                                                   krb5_keytab keytab,
                                                   krb5_principal princpal,
                                                   krb5_kvno kvno,
                                                   krb5_data *password,
                                                   krb5_enctype *enctypes,
                                                   krb5_data *salt);

krb5_error_code  _adcli_krb5_keytab_test_salt     (krb5_context k5,
                                                   krb5_keytab scratch,
                                                   krb5_principal principal,
                                                   krb5_kvno kvno,
                                                   krb5_data *password,
                                                   krb5_enctype *enctypes,
                                                   krb5_data *salt);

krb5_error_code  _adcli_krb5_keytab_discover_salt (krb5_context k5,
                                                   krb5_principal principal,
                                                   krb5_kvno kvno,
                                                   krb5_data *password,
                                                   krb5_enctype *enctypes,
                                                   krb5_data *salts,
                                                   int *discovered);

krb5_error_code  _adcli_krb5_w2k3_salt            (krb5_context k5,
                                                   krb5_principal principal,
                                                   const char *host_netbios,
                                                   krb5_data *salt);

krb5_enctype *   _adcli_krb5_parse_enctypes       (const char *value);

char *           _adcli_krb5_format_enctypes      (krb5_enctype *enctypes);

struct _adcli_attrs {
	LDAPMod **mods;
	int len;
};

#endif /* ADPRIVATE_H_ */
