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

#ifndef ADATTR_H_
#define ADATTR_H_

typedef struct _adcli_attrs adcli_attrs;

#ifndef GNUC_NULL_TERMINATED
#if __GNUC__ >= 4
#define GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#else
#define GNUC_NULL_TERMINATED
#endif
#endif

adcli_attrs *      adcli_attrs_new                    (void);

void               adcli_attrs_add1                   (adcli_attrs *attrs,
                                                       const char *name,
                                                       const char *value);

void               adcli_attrs_add                    (adcli_attrs *attrs,
                                                       const char *name,
                                                       const char *value,
                                                       ...) GNUC_NULL_TERMINATED;

void               adcli_attrs_replace                (adcli_attrs *attrs,
                                                       const char *name,
                                                       const char *value,
                                                       ...) GNUC_NULL_TERMINATED;

void               adcli_attrs_delete1                (adcli_attrs *attrs,
                                                       const char *name,
                                                       const char *value);

void               adcli_attrs_delete                 (adcli_attrs *attrs,
                                                       const char *name,
                                                       const char *value,
                                                       ...) GNUC_NULL_TERMINATED;

int                adcli_attrs_have                   (adcli_attrs *attrs,
                                                       const char *name);

void               adcli_attrs_free                   (adcli_attrs *attrs);

#endif /* ADATTR_H_ */
