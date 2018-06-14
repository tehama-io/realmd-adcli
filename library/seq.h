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

#ifndef SEQ_H_
#define SEQ_H_

#ifdef __GNUC__
#define WARN_UNUSED __attribute__((warn_unused_result))
#else
#define WARN_UNUSED
#endif

/*
 * It's expected that callers will pass in their own arrays of
 * pointer values such as char ** in place of seq_voidp.
 * We use a typedef'd void* to avoid silly casts everywhere.
 */
typedef void *     seq_voidp;

typedef int        (* seq_compar)             (void *match,
                                               void *value);

typedef void *     (* seq_copy)               (void *value);

typedef void       (* seq_destroy)            (void *value);

typedef int        (* seq_search)             (void **seq,
                                               int low,
                                               int high,
                                               void *match,
                                               seq_compar compar);

seq_voidp          seq_push                   (seq_voidp seq,
                                               int *length,
                                               void *value) WARN_UNUSED;

#define            seq_at(seq, i)             (((void **)(seq))[(i)])

seq_voidp          seq_insert                 (seq_voidp seq,
                                               int *length,
                                               void *value,
                                               seq_compar compar,
                                               seq_destroy destroy);

void               seq_remove                 (seq_voidp seq,
                                               int *length,
                                               void *match,
                                               seq_compar compar,
                                               seq_destroy destroy);

void               seq_remove_unsorted        (seq_voidp seq,
                                               int *length,
                                               void *match,
                                               seq_compar compar,
                                               seq_destroy destroy);

seq_voidp          seq_lookup                 (seq_voidp seq,
                                               int *length,
                                               void *match,
                                               seq_compar compar);

void               seq_filter                 (seq_voidp seq,
                                               int *length,
                                               void *match,
                                               seq_compar compar,
                                               seq_destroy destroy);

int                seq_count                  (seq_voidp seq);

seq_voidp          seq_dup                    (seq_voidp seq,
                                               int *length,
                                               seq_copy copy);

void               seq_free                   (seq_voidp seq,
                                               seq_destroy destroy);

#endif /* SEQ_H_ */
