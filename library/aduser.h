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

#ifndef ADUSER_H_
#define ADUSER_H_

#include "adconn.h"
#include "adattrs.h"

typedef struct _adcli_user adcli_user;

adcli_user *       adcli_user_new                       (adcli_conn *conn,
                                                         const char *sam_name);

adcli_user *       adcli_user_ref                       (adcli_user *user);

void               adcli_user_unref                     (adcli_user *user);

adcli_result       adcli_user_create                    (adcli_user *user,
                                                         adcli_attrs *attrs);

adcli_result       adcli_user_delete                    (adcli_user *user);

const char *       adcli_user_get_ou                    (adcli_user *user);

void               adcli_user_set_ou                    (adcli_user *user,
                                                         const char *ou);

const char *       adcli_user_get_sam_name              (adcli_user *user);

#endif /* ADUSER_H_ */
