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

#ifndef ADCONN_H_
#define ADCONN_H_

#include "adutil.h"

#include <krb5/krb5.h>
#include <ldap.h>

typedef enum {
	ADCLI_LOGIN_UNKNOWN = 0,
	ADCLI_LOGIN_COMPUTER_ACCOUNT = 1 << 1,
	ADCLI_LOGIN_USER_ACCOUNT = 1 << 2,
} adcli_login_type;

typedef void        (* adcli_message_func)           (adcli_message_type type,
                                                      const char *message,
                                                      void *data);

typedef char *      (* adcli_password_func)          (adcli_login_type type,
                                                      const char *name,
                                                      int flags,
                                                      void *data);

typedef void        (* adcli_destroy_func)           (void *data);

typedef struct _adcli_conn_ctx adcli_conn;

adcli_result        adcli_conn_discover              (adcli_conn *conn);

adcli_result        adcli_conn_connect               (adcli_conn *conn);

adcli_conn *        adcli_conn_new                   (const char *domain);

adcli_conn *        adcli_conn_ref                   (adcli_conn *conn);

void                adcli_conn_unref                 (adcli_conn *conn);

void                adcli_conn_set_message_func      (adcli_conn *conn,
                                                      adcli_message_func message_func,
                                                      void *data,
                                                      adcli_destroy_func destroy_func);

void                adcli_conn_set_password_func     (adcli_conn *conn,
                                                      adcli_password_func password_func,
                                                      void *data,
                                                      adcli_destroy_func destroy_data);

void                adcli_conn_clear_last_error      (adcli_conn *conn);

const char *        adcli_conn_get_last_error        (adcli_conn *conn);

const char *        adcli_conn_get_host_fqdn         (adcli_conn *conn);

void                adcli_conn_set_host_fqdn         (adcli_conn *conn,
                                                      const char *value);

const char *        adcli_conn_get_domain_name       (adcli_conn *conn);

void                adcli_conn_set_domain_name       (adcli_conn *conn,
                                                      const char *value);

const char *        adcli_conn_get_domain_realm      (adcli_conn *conn);

void                adcli_conn_set_domain_realm      (adcli_conn *conn,
                                                      const char *value);

const char *        adcli_conn_get_domain_server     (adcli_conn *conn);

void                adcli_conn_set_domain_server     (adcli_conn *conn,
                                                      const char *value);

const char *        adcli_conn_get_domain_short      (adcli_conn *conn);

const char **       adcli_conn_get_ldap_urls         (adcli_conn *conn);

void                adcli_conn_set_ldap_urls         (adcli_conn *conn,
                                                      const char **value);

void                adcli_conn_add_ldap_url          (adcli_conn *conn,
                                                      const char *value);

LDAP *              adcli_conn_get_ldap_connection   (adcli_conn *conn);

krb5_context        adcli_conn_get_krb5_context      (adcli_conn *conn);

const char *        adcli_conn_get_computer_name     (adcli_conn *conn);

void                adcli_conn_set_computer_name     (adcli_conn *conn,
                                                      const char *value);

const char *        adcli_conn_get_computer_password (adcli_conn *conn);

void                adcli_conn_set_computer_password (adcli_conn *conn,
                                                      const char *password);

const char *        adcli_conn_get_user_name         (adcli_conn *conn);

void                adcli_conn_set_user_name         (adcli_conn *conn,
                                                      const char *value);

const char *        adcli_conn_get_user_password     (adcli_conn *conn);

void                adcli_conn_set_user_password     (adcli_conn *conn,
                                                      const char *value);

adcli_login_type    adcli_conn_get_login_type        (adcli_conn *conn);

adcli_login_type    adcli_conn_get_allowed_login_types  (adcli_conn *conn);

void                adcli_conn_set_allowed_login_types  (adcli_conn *conn,
                                                         adcli_login_type types);

krb5_ccache         adcli_conn_get_login_ccache      (adcli_conn *conn);

const char *        adcli_conn_get_login_ccache_name (adcli_conn *conn);

void                adcli_conn_set_login_ccache_name (adcli_conn *conn,
                                                      const char *ccname);

const char *        adcli_conn_get_default_naming_context (adcli_conn *conn);

const char *        adcli_conn_get_krb5_conf_dir     (adcli_conn *conn);

void                adcli_conn_set_krb5_conf_dir     (adcli_conn *conn,
                                                      const char *value);

#endif /* ADCONN_H_ */
