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

#ifndef ADPRIVATE_H_
#define ADPRIVATE_H_

#include "adconn.h"

#include <stdarg.h>
#include <limits.h>
#include <stdlib.h>

#include <ldap.h>

/* Utilities */

#if !defined(__cplusplus) && (__GNUC__ > 2)
#define GNUC_PRINTF(x, y) __attribute__((__format__(__printf__, x, y)))
#else
#define GNUC_PRINTF(x, y)
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

void           _adcli_precond_failed         (const char *message,
                                              ...) GNUC_PRINTF (1, 2);

int            _adcli_strv_len               (char **strv);

char **        _adcli_strv_add               (char **strv,
                                              char *string,
                                              int *length);

void           _adcli_strv_free              (char **strv);

char **        _adcli_strv_dup               (char **strv);

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

int            _adcli_mem_clear              (void *data,
                                              size_t length);

/* Connection helpers */

void          _adcli_err                     (adcli_conn *conn,
                                              const char *format,
                                              ...) GNUC_PRINTF(2, 3);

void          _adcli_warn                    (adcli_conn *conn,
                                              const char *format,
                                              ...) GNUC_PRINTF(2, 3);

void          _adcli_info                    (adcli_conn *conn,
                                              const char *format,
                                              ...) GNUC_PRINTF(2, 3);

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

adcli_result  _adcli_ldap_handle_failure     (adcli_conn *conn,
                                              LDAP *ldap,
                                              const char *desc,
                                              const char *arg,
                                              adcli_result defres);

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

int           _adcli_ldap_have_mod           (LDAPMod *want,
                                              struct berval **have);

LDAPMod **    _adcli_ldap_prune_empty_mods   (LDAPMod **mods);

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

#endif /* ADPRIVATE_H_ */
