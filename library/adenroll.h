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

#ifndef ADENROLL_H_
#define ADENROLL_H_

#include "adconn.h"

typedef enum {
	ADCLI_ENROLL_NO_KEYTAB = 1 << 1,
} adcli_enroll_flags;

typedef struct _adcli_enroll adcli_enroll;

adcli_result       adcli_enroll_join                    (adcli_enroll *enroll,
                                                         adcli_enroll_flags join_flags);

adcli_enroll *     adcli_enroll_new                     (adcli_conn *conn);

adcli_enroll *     adcli_enroll_ref                     (adcli_enroll *enroll);

void               adcli_enroll_unref                   (adcli_enroll *enroll);

const char *       adcli_enroll_get_host_fqdn           (adcli_enroll *enroll);

void               adcli_enroll_set_host_fqdn           (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_host_netbios        (adcli_enroll *enroll);

void               adcli_enroll_set_host_netbios        (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_host_password       (adcli_enroll *enroll,
                                                         size_t *length);

void               adcli_enroll_set_host_password       (adcli_enroll *enroll,
                                                         const char *host_password,
                                                         ssize_t host_password_len);

char *             adcli_enroll_generate_host_password  (adcli_enroll *enroll,
                                                         size_t length,
                                                         int alpha_numeric);

void               adcli_enroll_free_host_password      (char *password,
                                                         size_t length);

const char *       adcli_enroll_get_preferred_ou        (adcli_enroll *enroll);

void               adcli_enroll_set_preferred_ou        (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_computer_container  (adcli_enroll *enroll);

void               adcli_enroll_set_computer_container  (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_computer_account    (adcli_enroll *enroll);

void               adcli_enroll_set_computer_account    (adcli_enroll *enroll,
                                                         const char *value);

const char **      adcli_enroll_get_service_names       (adcli_enroll *enroll);

void               adcli_enroll_set_service_names       (adcli_enroll *enroll,
                                                         const char **value);

void               adcli_enroll_add_service_name        (adcli_enroll *enroll,
                                                         const char *value);

const char **      adcli_enroll_get_service_principals  (adcli_enroll *enroll);

void               adcli_enroll_set_service_principals  (adcli_enroll *enroll,
                                                         const char **value);

krb5_kvno          adcli_enroll_get_kvno                (adcli_enroll *enroll);

void               adcli_enroll_set_kvno                (adcli_enroll *enroll,
                                                         krb5_kvno value);

krb5_keytab        adcli_enroll_get_keytab              (adcli_enroll *enroll);

const char *       adcli_enroll_get_keytab_name         (adcli_enroll *enroll);

void               adcli_enroll_set_keytab_name         (adcli_enroll *enroll,
                                                         const char *value);

krb5_enctype *     adcli_enroll_get_keytab_enctypes     (adcli_enroll *enroll);

void               adcli_enroll_set_keytab_enctypes     (adcli_enroll *enroll,
                                                         krb5_enctype *enctypes);

#endif /* ADENROLL_H_ */
