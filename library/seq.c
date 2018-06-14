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

#include "seq.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* For detecting clang features */
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#ifndef CLANG_ANALYZER_NORETURN
#if __has_feature(attribute_analyzer_noreturn)
#define CLANG_ANALYZER_NORETURN __attribute__((analyzer_noreturn))
#else
#define CLANG_ANALYZER_NORETURN
#endif
#endif

/* to make coverage simple */
#define bail_on_null(v) do { if ((v) == NULL) return bail_null (); } while (0)

static void *
bail_null (void)
CLANG_ANALYZER_NORETURN;

static void *
bail_null (void)
{
	return NULL;
}

static int
alloc_size (int num)
{
	int n = num ? 1 : 0;
	while (n < num && n > 0)
		n <<= 1;
	return n;
}

int
seq_count (seq_voidp sequence)
{
	void **seq = sequence;
	int count;
	for (count = 0; seq && seq[count]; count++);
	return count;
}

static void **
guarantee_one_more (void **seq,
                    int len)
{
	int alloc;

	alloc = alloc_size (len + 1);
	assert (alloc != 0);

	if (len + 2 > alloc) {
		assert (alloc != 0);
		seq = realloc (seq, alloc * 2 * sizeof (void *));
	}

	return seq;
}

void *
seq_push (seq_voidp sequence,
          int *length,
          void *value)
{
	void **seq = sequence;
	int len;

	assert (length != NULL);
	assert (value != NULL);

	len = *length;
	seq = guarantee_one_more (seq, len);
	if (seq) {
		seq[len++] = value;
		seq[len] = NULL;
		*length = len;
	}
	return seq;
}

static int
linear_search (void **seq,
               int low,
               int high,
               void *match,
               seq_compar compar)
{
	int at;

	for (at = low; at < high; at++) {
		if (compar (match, seq[at]) == 0) {
			break;
		}
	}

	return at;
}

static int
binary_search (void **seq,
               int low,
               int high,
               void *match,
               seq_compar compar)
{
	int res;
	int mid;

	if (low == high)
		return low;

	mid = low + ((high - low) / 2);
	res = compar (match, seq[mid]);
	if (res > 0)
		return binary_search (seq, mid + 1, high, match, compar);
	else if (res < 0)
		return binary_search (seq, low, mid, match, compar);

	return mid;
}

void *
seq_insert (seq_voidp sequence,
            int *length,
            void *value,
            seq_compar compar,
            seq_destroy destroy)
{
	void **seq = sequence;
	int at;
	int len;

	assert (length != NULL);
	assert (compar != NULL);
	assert (value != NULL);

	len = *length;
	at = binary_search (seq, 0, len, value, compar);

	/* We already have a matching value */
	if (at < len && compar (value, seq[at]) == 0) {
		if (destroy != NULL)
			destroy (seq[at]);

	/* Need to insert a value */
	} else {
		seq = guarantee_one_more (seq, len);
		bail_on_null (seq);
		memmove (seq + at + 1, seq + at, (len - at) * sizeof (void *));
		len++;
		seq[len] = NULL;
	}

	seq[at] = value;
	*length = len;
	return seq;
}

static void
seq_remove_int (seq_voidp sequence,
                int *length,
                void *match,
                seq_search search,
                seq_compar compar,
                seq_destroy destroy)
{
	void **seq = sequence;
	int at;
	int len;

	assert (length != NULL);
	assert (compar != NULL);
	assert (match != NULL);

	len = *length;
	at = search (seq, 0, len, match, compar);

	/* We have a matching value */
	if (at < len && compar (match, seq[at]) == 0) {
		if (destroy != NULL)
			destroy (seq[at]);
		memmove (seq + at, seq + at + 1, (len - at) * sizeof (void *));
		len--;
		seq[len] = NULL;
	}

	*length = len;
}

void
seq_remove (seq_voidp sequence,
            int *length,
            void *match,
            seq_compar compar,
            seq_destroy destroy)
{
	return seq_remove_int (sequence, length, match, binary_search, compar, destroy);
}

void
seq_remove_unsorted (seq_voidp sequence,
                     int *length,
                     void *match,
                     seq_compar compar,
                     seq_destroy destroy)
{
	return seq_remove_int (sequence, length, match, linear_search, compar, destroy);
}

void
seq_filter (seq_voidp sequence,
            int *length,
            void *match,
            seq_compar compar,
            seq_destroy destroy)
{
	void **seq = sequence;
	int len;
	int in, out;

	assert (length != NULL);
	assert (compar != NULL);

	if (!sequence)
		return;

	len = *length;

	for (in = 0, out = 0; in < len; in++) {
		if (compar (match, seq[in]) == 0) {
			seq[out++] = seq[in];
		} else {
			if (destroy)
				destroy (seq[in]);
		}
	}

	seq[out] = NULL;
	*length = out;
}

void *
seq_lookup (seq_voidp sequence,
            int *length,
            void *match,
            seq_compar compar)
{
	void **seq = sequence;
	int at;
	int len;

	assert (length != NULL);
	assert (compar != NULL);
	assert (match != NULL);

	len = *length;
	at = binary_search (seq, 0, len, match, compar);

	/* We have a matching value */
	if (at < len && compar (match, seq[at]) == 0)
		return seq[at];

	return NULL;
}

void *
seq_dup (seq_voidp sequence,
         int *length,
         seq_copy copy)
{
	void **seq = sequence;
	void **copied;
	int alloc;
	int len;
	int at;

	assert (length != NULL);

	len = *length;
	alloc = alloc_size (len + 1);
	assert (alloc != 0);

	copied = calloc (alloc, sizeof (void *));
	bail_on_null (copied);

	for (at = 0; at < len; at++) {
		if (copy == NULL) {
			copied[at] = seq[at];
		} else {
			copied[at] = copy (seq[at]);
			bail_on_null (copied[at]);
		}
	}

	copied[len] = NULL;
	return copied;
}

void
seq_free (seq_voidp sequence,
          seq_destroy destroy)
{
	void **seq = sequence;
	int at;

	for (at = 0; destroy && seq && seq[at] != NULL; at++)
		(destroy) (seq[at]);

	free (seq);
}

#ifdef SEQ_TESTS

#include "test.h"

static void
test_push (void)
{
	void **seq = NULL;
	int len = 0;

	seq = seq_push (seq, &len, "5");
	seq = seq_push (seq, &len, "4");
	seq = seq_push (seq, &len, "3");
	seq = seq_push (seq, &len, "2");
	seq = seq_push (seq, &len, "1");

	assert (seq != NULL);
	assert_str_eq (seq[0], "5");
	assert_str_eq (seq[1], "4");
	assert_str_eq (seq[2], "3");
	assert_str_eq (seq[3], "2");
	assert_str_eq (seq[4], "1");
	assert (seq[5] == NULL);
	assert_num_eq (len, 5);

	seq_free (seq, NULL);
}

static void
test_insert (void)
{
	void **seq = NULL;
	int len = 0;

	/* Note that we have a duplicate ... */
	seq = seq_insert (seq, &len, "3", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "5", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "1", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "4", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "3", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "2", (seq_compar)strcmp, NULL);

	/* ... which doesn't show up here */
	assert_str_eq (seq[0], "1");
	assert_str_eq (seq[1], "2");
	assert_str_eq (seq[2], "3");
	assert_str_eq (seq[3], "4");
	assert_str_eq (seq[4], "5");
	assert (seq[5] == NULL);
	assert_num_eq (len, 5);

	seq_free (seq, NULL);
}

static void **destroyed = NULL;

static void
steal_destroyed (void *value)
{
	int len = seq_count (destroyed);
	destroyed = seq_push (destroyed, &len, value);
}

static void
test_insert_destroys (void)
{
	void **seq = NULL;
	int len = 0;

	destroyed = NULL;

	seq = seq_insert (seq, &len, "3", (seq_compar)strcmp, steal_destroyed);
	seq = seq_insert (seq, &len, "5", (seq_compar)strcmp, steal_destroyed);
	seq = seq_insert (seq, &len, "3", (seq_compar)strcmp, steal_destroyed);
	seq = seq_insert (seq, &len, "4", (seq_compar)strcmp, steal_destroyed);
	seq = seq_insert (seq, &len, "3", (seq_compar)strcmp, steal_destroyed);
	seq = seq_insert (seq, &len, "4", (seq_compar)strcmp, steal_destroyed);

	assert_str_eq (seq[0], "3");
	assert_str_eq (seq[1], "4");
	assert_str_eq (seq[2], "5");
	assert (seq[3] == NULL);

	assert (destroyed != NULL);
	assert_str_eq (destroyed[0], "3");
	assert_str_eq (destroyed[1], "3");
	assert_str_eq (destroyed[2], "4");
	assert (destroyed[3] == NULL);

	seq_free (seq, NULL);

	seq_free (destroyed, NULL);
	destroyed = NULL;
}

static void
test_remove (void)
{
	void **seq = NULL;
	int len = 0;

	seq = seq_insert (seq, &len, "3", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "5", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "1", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "4", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "2", (seq_compar)strcmp, NULL);

	assert_str_eq (seq[0], "1");
	assert_str_eq (seq[1], "2");
	assert_str_eq (seq[2], "3");
	assert_str_eq (seq[3], "4");
	assert_str_eq (seq[4], "5");
	assert (seq[5] == NULL);
	assert_num_eq (len, 5);

	seq_remove (seq, &len, "3", (seq_compar)strcmp, NULL);
	seq_remove (seq, &len, "2", (seq_compar)strcmp, NULL);

	assert_str_eq (seq[0], "1");
	assert_str_eq (seq[1], "4");
	assert_str_eq (seq[2], "5");
	assert (seq[3] == NULL);
	assert_num_eq (len, 3);

	seq_free (seq, NULL);
}

static void
test_remove_unsorted (void)
{
	void **seq = NULL;
	int len = 0;

	seq = seq_push (seq, &len, "3");
	seq = seq_push (seq, &len, "5");
	seq = seq_push (seq, &len, "1");
	seq = seq_push (seq, &len, "4");
	seq = seq_push (seq, &len, "2");

	assert_str_eq (seq[0], "3");
	assert_str_eq (seq[1], "5");
	assert_str_eq (seq[2], "1");
	assert_str_eq (seq[3], "4");
	assert_str_eq (seq[4], "2");
	assert (seq[5] == NULL);
	assert_num_eq (len, 5);

	seq_remove_unsorted (seq, &len, "3", (seq_compar)strcmp, NULL);
	seq_remove_unsorted (seq, &len, "2", (seq_compar)strcmp, NULL);

	assert_str_eq (seq[0], "5");
	assert_str_eq (seq[1], "1");
	assert_str_eq (seq[2], "4");
	assert (seq[3] == NULL);
	assert_num_eq (len, 3);

	seq_free (seq, NULL);
}

static void
test_remove_first (void)
{
	void **seq = NULL;
	int len = 0;

	seq = seq_insert (seq, &len, "3", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "5", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "1", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "4", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "2", (seq_compar)strcmp, NULL);

	assert_str_eq (seq[0], "1");
	assert_str_eq (seq[1], "2");
	assert_str_eq (seq[2], "3");
	assert_str_eq (seq[3], "4");
	assert_str_eq (seq[4], "5");
	assert (seq[5] == NULL);
	assert_num_eq (len, 5);

	seq_remove (seq, &len, "1", (seq_compar)strcmp, NULL);

	assert_str_eq (seq[0], "2");
	assert_str_eq (seq[1], "3");
	assert_str_eq (seq[2], "4");
	assert_str_eq (seq[3], "5");
	assert (seq[4] == NULL);
	assert_num_eq (len, 4);

	seq_free (seq, NULL);
}

static void
test_remove_last (void)
{
	void **seq = NULL;
	int len = 0;

	seq = seq_insert (seq, &len, "3", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "1", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "4", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "2", (seq_compar)strcmp, NULL);

	assert_str_eq (seq[0], "1");
	assert_str_eq (seq[1], "2");
	assert_str_eq (seq[2], "3");
	assert_str_eq (seq[3], "4");
	assert (seq[4] == NULL);
	assert_num_eq (len, 4);

	seq_remove (seq, &len, "4", (seq_compar)strcmp, NULL);

	assert_str_eq (seq[0], "1");
	assert_str_eq (seq[1], "2");
	assert_str_eq (seq[2], "3");
	assert (seq[3] == NULL);
	assert_num_eq (len, 3);

	seq_free (seq, NULL);
}

static int
compar_even (void *match,
             void *value)
{
	int val;

	assert_str_eq (match, "even");

	val = atoi (value);
	if (val % 2 == 0)
		return 0;
	return -1;
}

static void
test_filter (void)
{
	void **seq = NULL;
	int len = 0;

	seq = seq_push (seq, &len, "1");
	seq = seq_push (seq, &len, "2");
	seq = seq_push (seq, &len, "3");
	seq = seq_push (seq, &len, "4");
	seq = seq_push (seq, &len, "5");
	seq = seq_push (seq, &len, "6");
	seq = seq_push (seq, &len, "7");
	seq = seq_push (seq, &len, "8");
	assert (len == 8);

	destroyed = NULL;
	seq_filter (seq, &len, "even", compar_even, steal_destroyed);

	assert_str_eq (seq[0], "2");
	assert_str_eq (seq[1], "4");
	assert_str_eq (seq[2], "6");
	assert_str_eq (seq[3], "8");
	assert (seq[4] == NULL);
	assert_num_eq (len, 4);

	assert (destroyed != NULL);
	assert_str_eq (destroyed[0], "1");
	assert_str_eq (destroyed[1], "3");
	assert_str_eq (destroyed[2], "5");
	assert_str_eq (destroyed[3], "7");
	assert (seq[4] == NULL);
	assert_num_eq (len, 4);

	seq_free (destroyed, NULL);
	seq_free (seq, NULL);
}

static void
test_filter_null (void)
{
	int len = 0;
	seq_filter (NULL, &len, "even", compar_even, NULL);
}

static void
test_remove_destroys (void)
{
	void **seq = NULL;
	int len = 0;

	destroyed = NULL;

	seq = seq_insert (seq, &len, "5", (seq_compar)strcmp, steal_destroyed);
	seq = seq_insert (seq, &len, "4", (seq_compar)strcmp, steal_destroyed);
	seq = seq_insert (seq, &len, "3", (seq_compar)strcmp, steal_destroyed);

	assert (destroyed == NULL);

	seq_remove (seq, &len, "5", (seq_compar)strcmp, steal_destroyed);
	seq_remove (seq, &len, "4", (seq_compar)strcmp, steal_destroyed);
	seq_remove (seq, &len, "3", (seq_compar)strcmp, steal_destroyed);

	assert (seq[0] == NULL);

	assert (destroyed != NULL);
	assert_str_eq (destroyed[0], "5");
	assert_str_eq (destroyed[1], "4");
	assert_str_eq (destroyed[2], "3");
	assert (destroyed[3] == NULL);

	seq_free (seq, NULL);

	seq_free (destroyed, NULL);
	destroyed = NULL;
}

static void
test_lookup (void)
{
	void **seq = NULL;
	int len = 0;

	char *one = "1";
	char *two = "2";
	char *three = "3";
	char *four = "4";
	char *five = "5";
	char lookup[2] = { 0, 0 };
	char *check;

	seq = seq_insert (seq, &len, five, (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, two, (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, four, (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, three, (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, one, (seq_compar)strcmp, NULL);

	assert (len == 5);

	/* Make sure not searching for same pointer */
	lookup[0] = '1';
	check = seq_lookup (seq, &len, lookup, (seq_compar)strcmp);
	assert (check == one);

	lookup[0] = '3';
	check = seq_lookup (seq, &len, lookup, (seq_compar)strcmp);
	assert (check == three);

	check = seq_lookup (seq, &len, three, (seq_compar)strcmp);
	assert (check == three);

	lookup[0] = '8';
	check = seq_lookup (seq, &len, lookup, (seq_compar)strcmp);
	assert (check == NULL);

	seq_free (seq, NULL);
}

static void
test_dup (void)
{
	void **seq = NULL;
	void **dup;
	int len = 0;

	seq = seq_insert (seq, &len, "5", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "2", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "4", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "3", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "1", (seq_compar)strcmp, NULL);

	dup = seq_dup (seq, &len, NULL);
	assert (dup != NULL);

	assert_str_eq (dup[0], "1");
	assert_str_eq (dup[1], "2");
	assert_str_eq (dup[2], "3");
	assert_str_eq (dup[3], "4");
	assert_str_eq (dup[4], "5");
	assert (dup[5] == NULL);

	seq_free (seq, NULL);
	seq_free (dup, NULL);
}

static void
test_dup_deep (void)
{
	void **seq = NULL;
	int len = 0;
	void **dup;

	seq = seq_insert (seq, &len, "5", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "2", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "4", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "3", (seq_compar)strcmp, NULL);
	seq = seq_insert (seq, &len, "1", (seq_compar)strcmp, NULL);

	dup = seq_dup (seq, &len, (seq_copy)strdup);
	assert (dup != NULL);

	assert_str_eq (dup[0], "1");
	assert_str_eq (dup[1], "2");
	assert_str_eq (dup[2], "3");
	assert_str_eq (dup[3], "4");
	assert_str_eq (dup[4], "5");
	assert (dup[5] == NULL);

	seq_free (seq, NULL);
	seq_free (dup, free);
}

static void
test_free_null (void)
{
	seq_free (NULL, NULL);
	seq_free (NULL, free);
}

int
main (int argc,
      char *argv[])
{
	test_func (test_push, "/seq/push");
	test_func (test_insert, "/seq/insert");
	test_func (test_insert_destroys, "/seq/insert_destroys");
	test_func (test_remove, "/seq/remove");
	test_func (test_remove_unsorted, "/seq/remove_unsorted");
	test_func (test_remove_first, "/seq/remove_first");
	test_func (test_remove_last, "/seq/remove_last");
	test_func (test_remove_destroys, "/seq/remove_destroys");
	test_func (test_filter, "/seq/filter");
	test_func (test_filter_null, "/seq/filter_null");
	test_func (test_lookup, "/seq/lookup");
	test_func (test_dup, "/seq/dup");
	test_func (test_dup_deep, "/seq/dup_deep");
	test_func (test_free_null, "/seq/free_null");
	return test_run (argc, argv);
}

#endif /* SEQ_TESTS */
