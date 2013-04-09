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

#ifndef ADENTRY_H_
#define ADENTRY_H_

#include "adconn.h"
#include "adattrs.h"

typedef struct _adcli_entry adcli_entry;

adcli_entry *      adcli_entry_new_user                 (adcli_conn *conn,
                                                         const char *sam_name);

adcli_entry *      adcli_entry_new_group                (adcli_conn *conn,
                                                         const char *sam_name);

adcli_entry *      adcli_entry_ref                      (adcli_entry *entry);

void               adcli_entry_unref                    (adcli_entry *entry);

adcli_result       adcli_entry_load                     (adcli_entry *entry);

adcli_result       adcli_entry_create                   (adcli_entry *entry,
                                                         adcli_attrs *attrs);

adcli_result       adcli_entry_modify                   (adcli_entry *entry,
                                                         adcli_attrs *attrs);

adcli_result       adcli_entry_delete                   (adcli_entry *entry);

const char *       adcli_entry_get_domain_ou            (adcli_entry *entry);

void               adcli_entry_set_domain_ou            (adcli_entry *entry,
                                                         const char *ou);

const char *       adcli_entry_get_sam_name             (adcli_entry *entry);

const char *       adcli_entry_get_dn                   (adcli_entry *entry);

#endif /* ADENTRY_H_ */
