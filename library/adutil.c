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

#include "config.h"

#include "adcli.h"
#include "adprivate.h"
#include "seq.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/wait.h>

static adcli_message_func message_func = NULL;
static char last_error[2048] = { 0, };

void
_adcli_precond_failed (const char *message,
                       ...)
{
	va_list va;
	const char *env;

	va_start (va, message);
	vfprintf (stderr, message, va);
	va_end (va);

	env = getenv ("ADCLI_STRICT");
	if (env != NULL && env[0] != '\0')
		abort ();

	/* Let coverity know we're not supposed to return from here */
#ifdef __COVERITY__
	abort();
#endif
}

const char *
adcli_result_to_string (adcli_result res)
{
	switch (res) {
	case ADCLI_SUCCESS:
		return "Success";
	case ADCLI_ERR_UNEXPECTED:
		return "Unexpected or internal system error";
	case ADCLI_ERR_DIRECTORY:
		return "Problem with the Active Directory or connecting to it";
	case ADCLI_ERR_CREDENTIALS:
		return "The administrative credentials are invalid or access is denied";
	case ADCLI_ERR_CONFIG:
		return "The local system has an invalid configuration";
	case ADCLI_ERR_FAIL:
		return "Generic failure";
	}

	return_val_if_reached ("Unknown error");
}

static void
messagev (adcli_message_type type,
          const char *format,
          va_list va)
{
	char buffer[sizeof (last_error)];
	char *where = buffer;
	int ret;

	if (type == ADCLI_MESSAGE_ERROR)
		where = last_error;
	else if (message_func == NULL)
		return;

	ret = vsnprintf (where, sizeof (buffer), format, va);
	return_if_fail (ret >= 0);

	if (message_func != NULL)
		(message_func) (type, where);
}

void
_adcli_err (const char *format,
            ...)
{
	va_list va;
	va_start (va, format);
	messagev (ADCLI_MESSAGE_ERROR, format, va);
	va_end (va);
}

void
_adcli_warn (const char *format,
             ...)
{
	va_list va;
	va_start (va, format);
	messagev (ADCLI_MESSAGE_ERROR, format, va);
	va_end (va);
}

void
_adcli_info (const char *format,
             ...)
{
	va_list va;
	va_start (va, format);
	messagev (ADCLI_MESSAGE_INFO, format, va);
	va_end (va);
}

void
adcli_set_message_func (adcli_message_func func)
{
	message_func = func;
}

const char *
adcli_get_last_error (void)
{
	return last_error[0] ? last_error : NULL;
}

void
adcli_clear_last_error (void)
{
	last_error[0] = '\0';
}

void
_adcli_strv_free (char **strv)
{
	seq_free (strv, free);
}

char **
_adcli_strv_dup (char **strv)
{
	int count;

	if (!strv)
		return NULL;

	count = seq_count (strv);
	return seq_dup (strv, &count, (seq_copy)strdup);
}

char *
_adcli_strv_join (char **strv,
                  const char *delim)
{
	char *result = NULL;
	int at = 0;
	int dlen;
	int slen;
	int i;

	dlen = strlen (delim);
	for (i = 0; strv && strv[i] != NULL; i++) {
		slen = strlen (strv[i]);
		result = realloc (result, at + dlen + slen + 1);
		return_val_if_fail (result != NULL, NULL);
		if (at != 0) {
			memcpy (result + at, delim, dlen);
			at += dlen;
		}

		memcpy (result + at, strv[i], slen);
		at += slen;
		result[at] = '\0';
	}

	return result;
}

int
_adcli_strv_len (char **strv)
{
	return seq_count (strv);
}

char **
_adcli_strv_add (char **strv,
                 char *string,
                 int *length)
{
	int len;

	return_val_if_fail (string != NULL, strv);

	if (!length) {
		len = seq_count (strv);
		length = &len;
	}

	return seq_push (strv, length, string);
}

static int
_adcli_strv_has_ex (char **strv,
                    const char *str,
                    int (* compare) (const char *match, const char*value))
{
	int i;

	for (i = 0; strv && strv[i] != NULL; i++) {
		if (compare (strv[i], str) == 0)
			return 1;
	}

	return 0;
}

char **
_adcli_strv_add_unique (char **strv,
                        char *string,
                        int *length,
                        bool case_sensitive)
{
	if (_adcli_strv_has_ex (strv, string, case_sensitive ? strcmp : strcasecmp) == 1) {
		return strv;
	}

	return _adcli_strv_add (strv, string, length);
}

#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))

void
_adcli_strv_remove_unsorted (char **strv,
                             const char *string,
                             int *length)
{
	int len;

	return_if_fail (string != NULL);

	if (!length) {
		len = seq_count (strv);
		length = &len;
	}

	return seq_remove_unsorted (strv, length, discard_const (string),
	                            (seq_compar)strcasecmp, free);
}

int
_adcli_strv_has (char **strv,
                 const char *str)
{
	return _adcli_strv_has_ex (strv, str, strcmp);
}

void
_adcli_str_up (char *str)
{
	while (*str != '\0') {
		*str = toupper (*str);
		str++;
	}
}

int
_adcli_str_is_up (const char *str)
{
	while (*str != '\0') {
		if (*str != toupper (*str))
			return 0;
		str++;
	}
	return 1;
}

void
_adcli_str_down (char *str)
{
	while (*str != '\0') {
		*str = tolower (*str);
		str++;
	}
}

void
_adcli_str_set (char **field,
                const char *value)
{
	char *newval = NULL;

	if (value) {
		newval = strdup (value);
		return_if_fail (newval != NULL);
	}

	free (*field);
	*field = newval;
}

void
_adcli_strv_set (char ***field,
                 const char **value)
{
	char **newval = NULL;

	if (value) {
		newval = _adcli_strv_dup ((char **)value);
		return_if_fail (newval != NULL);
	}

	_adcli_strv_free (*field);
	*field = newval;
}

char *
_adcli_bin_sid_to_str (const uint8_t *data,
                       size_t len)
{
	uint8_t sid_rev_num;
	int8_t num_auths;
	uint8_t id_auth[6];
	uint32_t id_auth_val;
	uint32_t sub_auths[15];
	uint32_t val;
	size_t p = 0;
	size_t c;
	int nc;
	char *sid_buf;
	size_t sid_buf_len;

	if (data == NULL || len < 8) {
		return NULL;
	}

	sid_rev_num = (uint8_t) data [p];
	p++;

	num_auths = (int8_t) data[p];
	p++;

	if (num_auths > 15 || len < 8 + (num_auths * sizeof (uint32_t))) {
		return NULL;
	}

	for (c = 0; c < 6; c++) {
		id_auth[c] = (uint8_t) data[p];
		p++;
	}

	/* Only 32bits are used for the string representation */
	id_auth_val = (id_auth[2] << 24) +
	              (id_auth[3] << 16) +
	              (id_auth[4] << 8) +
	              (id_auth[5]);

	for (c = 0; c < num_auths; c++) {
		memcpy (&val, data + p, sizeof (uint32_t));
		sub_auths[c] = le32toh (val);

		p += sizeof (uint32_t);
	}

	sid_buf_len = 17 + (num_auths * 11);
	sid_buf = calloc (1, sid_buf_len);
	if (sid_buf == NULL) {
		return NULL;
	}

	nc = snprintf (sid_buf, sid_buf_len, "S-%u-%lu", sid_rev_num,
	              (unsigned long) id_auth_val);
	if (nc < 0 || nc >= sid_buf_len) {
		free (sid_buf);
		return NULL;
	}

	p = 0;
	for (c = 0; c < num_auths; c++) {
		p += nc;
		sid_buf_len -= nc;

		nc = snprintf (sid_buf + p, sid_buf_len, "-%lu",
		               (unsigned long) sub_auths[c]);
		if (nc < 0 || nc >= sid_buf_len) {
			free (sid_buf);
			return NULL;
		}
	}

	return sid_buf;
}

char *
_adcli_str_dupn (void *data,
                 size_t len)
{
	char *result;

	result = malloc (len + 1);
	return_val_if_fail (result, NULL);

	memcpy (result, data, len);
	result[len] = '\0';
	return result;
}

int
_adcli_str_has_prefix (const char *str,
                       const char *prefix)
{
	size_t len = strlen (str);
	size_t lp = strlen (prefix);
	return (len >= lp && strncmp (str, prefix, lp) == 0);
}

int
_adcli_str_has_suffix (const char *str,
                       const char *suffix)
{
	size_t len = strlen (str);
	size_t ls = strlen (suffix);
	return (len >= ls && strncmp (str + (len - ls), suffix, ls) == 0);
}

int
_adcli_password_free (char *password)
{
	int ret;

	if (password == NULL)
		return 0;

	ret = adcli_mem_clear (password, strlen (password));
	free (password);
	return ret;
}

int
adcli_mem_clear (void *data,
                 size_t length)
{
	volatile char *vp;
	int ret = 0;

	if (data == NULL)
		return 0;

	/*
	 * Cracktastic stuff here to help compilers not
	 * optimize this away
	 */

	vp = (volatile char*)data;
	while (length) {
		*vp = 0xAA;
		ret += *vp;
		vp++;
		length--;
	}

	return ret;
}

int
_adcli_write_all (int fd,
                  const char *buf,
                  int len)
{
	int res;

	if (len == -1)
		len = strlen (buf);

	while (len > 0) {
		res = write (fd, buf, len);
		if (res <= 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return -errno;
		} else  {
			len -= res;
			buf += res;
		}
	}

	return 0;
}

#define AD_TO_UNIX_TIME_CONST 11644473600LL

bool
_adcli_check_nt_time_string_lifetime (const char *nt_time_string,
                                      unsigned int lifetime)
{
	uint64_t nt_now;
	unsigned long long int pwd_last_set;
	char *endptr;
	time_t now;

	if (nt_time_string == NULL) {
		_adcli_err ("Missing NT time string, assuming it is expired");
		return false;
	}

	if (lifetime == 0) {
		_adcli_info ("Password lifetime is 0, forcing renewal");
		return false;
	}

	now = time (NULL);
	/* NT timestamps start at 1601-01-01 and use a 100ns base */
	nt_now = (now + AD_TO_UNIX_TIME_CONST) * 1000 * 1000 * 10;
	errno = 0;
	pwd_last_set = strtoull (nt_time_string, &endptr, 10);
	if (errno != 0 || *endptr != '\0' || endptr == nt_time_string) {
		_adcli_err ("Failed to convert NT time string, assuming it is expired");
		return false;
	}

	if (pwd_last_set + (lifetime * 24ULL * 60 * 60 \
				* 1000 * 1000 * 10) > nt_now) {
		_adcli_info ("Password not too old, no change needed");
		return true;
	}

	return false;
}

adcli_result
_adcli_call_external_program (const char *binary, char * const *argv,
                              const char *stdin_data,
                              uint8_t **stdout_data, size_t *stdout_data_len)
{
	int ret;
	int pipefd_to_child[2] = { -1, -1};
	int pipefd_from_child[2] = { -1, -1};
	pid_t child_pid = 0;
	int err;
	size_t len;
	ssize_t rlen;
	pid_t wret;
	int status;
	uint8_t read_buf[4096];
	uint8_t *out;

	errno = 0;
	ret = access (binary, X_OK);
	if (ret != 0) {
		err = errno;
		_adcli_err ("Cannot run [%s]: [%d][%s].", binary, err,
		                                          strerror (err));
		ret = ADCLI_ERR_FAIL;
		goto done;
	}

	ret = pipe (pipefd_from_child);
	if (ret == -1) {
		err = errno;
		_adcli_err ("pipe failed [%d][%s].", err, strerror (err));
		ret = ADCLI_ERR_FAIL;
		goto done;
	}

	ret = pipe (pipefd_to_child);
	if (ret == -1) {
		err = errno;
		_adcli_err ("pipe failed [%d][%s].", err, strerror (err));
		ret = ADCLI_ERR_FAIL;
		goto done;
	}

	child_pid = fork ();

	if (child_pid == 0) { /* child */
		close (pipefd_to_child[1]);
		ret = dup2 (pipefd_to_child[0], STDIN_FILENO);
		if (ret == -1) {
			err = errno;
			_adcli_err ("dup2 failed [%d][%s].", err,
			                                     strerror (err));
			exit (EXIT_FAILURE);
		}

		close (pipefd_from_child[0]);
		ret = dup2 (pipefd_from_child[1], STDOUT_FILENO);
		if (ret == -1) {
			err = errno;
			_adcli_err ("dup2 failed [%d][%s].", err,
			                                     strerror (err));
			exit (EXIT_FAILURE);
		}

		execv (binary, argv);
		_adcli_err ("Failed to run %s.", binary);
		ret = ADCLI_ERR_FAIL;
		goto done;
	} else if (child_pid > 0) { /* parent */

		if (stdin_data != NULL) {
			len = strlen (stdin_data);
			ret = write (pipefd_to_child[1], stdin_data, len);
			if (ret != len) {
				_adcli_err ("Failed to send computer account password "
				            "to net command.");
				ret = ADCLI_ERR_FAIL;
				goto done;
			}
		}

		close (pipefd_to_child[0]);
		pipefd_to_child[0] = -1;
		close (pipefd_to_child[1]);
		pipefd_to_child[0] = -1;

		if (stdout_data != NULL || stdout_data_len != NULL) {
			rlen = read (pipefd_from_child[0], read_buf, sizeof (read_buf));
			if (rlen < 0) {
				ret = errno;
				_adcli_err ("Failed to read from child [%d][%s].\n",
				            ret, strerror (ret));
				ret = ADCLI_ERR_FAIL;
				goto done;
			}

			out = malloc (sizeof(uint8_t) * rlen);
			if (out == NULL) {
				_adcli_err ("Failed to allocate memory "
				            "for child output.");
				ret = ADCLI_ERR_FAIL;
				goto done;
			} else {
				memcpy (out, read_buf, rlen);
			}

			if (stdout_data != NULL) {
				*stdout_data = out;
			} else {
				free (out);
			}

			if (stdout_data_len != NULL) {
				*stdout_data_len = rlen;
			}
		}

	} else {
		_adcli_err ("Cannot run net command.");
		ret = ADCLI_ERR_FAIL;
		goto done;
	}

	ret = ADCLI_SUCCESS;

done:
	if (pipefd_from_child[0] != -1) {
		close (pipefd_from_child[0]);
	}
	if (pipefd_from_child[1] != -1) {
		close (pipefd_from_child[1]);
	}
	if (pipefd_to_child[0] != -1) {
		close (pipefd_to_child[0]);
	}
	if (pipefd_to_child[1] != -1) {
		close (pipefd_to_child[1]);
	}

	if (child_pid > 0) {
		wret = waitpid (child_pid, &status, 0);
		if (wret == -1) {
			_adcli_err ("No sure what happend to net command.");
		} else {
			if (WIFEXITED (status) && WEXITSTATUS (status) != 0) {
				_adcli_err ("net command failed with %d.",
				            WEXITSTATUS (status));
			}
		}
	}

	return ret;
}


#ifdef UTIL_TESTS

#include "test.h"

static void
test_strv_add_free (void)
{
	char **strv = NULL;

	strv = _adcli_strv_add (strv, strdup ("one"), NULL);
	strv = _adcli_strv_add (strv, strdup ("two"), NULL);
	strv = _adcli_strv_add (strv, strdup ("three"), NULL);

	assert_str_eq (strv[0], "one");
	assert_str_eq (strv[1], "two");
	assert_str_eq (strv[2], "three");
	assert (strv[3] == NULL);

	_adcli_strv_free (strv);
}

static void
test_strv_add_unique_free (void)
{
	char **strv = NULL;

	strv = _adcli_strv_add_unique (strv, strdup ("one"), NULL, false);
	strv = _adcli_strv_add_unique (strv, strdup ("one"), NULL, false);
	strv = _adcli_strv_add_unique (strv, strdup ("two"), NULL, false);
	strv = _adcli_strv_add_unique (strv, strdup ("two"), NULL, false);
	strv = _adcli_strv_add_unique (strv, strdup ("tWo"), NULL, false);
	strv = _adcli_strv_add_unique (strv, strdup ("three"), NULL, false);
	strv = _adcli_strv_add_unique (strv, strdup ("three"), NULL, false);
	strv = _adcli_strv_add_unique (strv, strdup ("TWO"), NULL, true);

	assert_num_eq (_adcli_strv_len (strv), 4);

	assert_str_eq (strv[0], "one");
	assert_str_eq (strv[1], "two");
	assert_str_eq (strv[2], "three");
	assert_str_eq (strv[3], "TWO");
	assert (strv[4] == NULL);

	_adcli_strv_free (strv);
}


static void
test_strv_dup (void)
{
	char *values[] = { "one", "two", "three", NULL };
	char **strv;

	strv = _adcli_strv_dup (values);

	assert_str_eq (strv[0], "one");
	assert_str_eq (strv[1], "two");
	assert_str_eq (strv[2], "three");
	assert (strv[3] == NULL);

	_adcli_strv_free (strv);
}

static void
test_strv_count (void)
{
	char *values[] = { "one", "two", "three", NULL };
	int len;

	len = _adcli_strv_len (values);
	assert_num_eq (len, 3);
}

static void
test_check_nt_time_string_lifetime (void)
{
	char *time_str;

	/* Missing or invalid value */
	assert (!_adcli_check_nt_time_string_lifetime (NULL, 0));
	assert (!_adcli_check_nt_time_string_lifetime ("", 0));
	assert (!_adcli_check_nt_time_string_lifetime ("a", 0));
	assert (!_adcli_check_nt_time_string_lifetime ("1a", 0));

	/* Certainly expired*/
	assert (!_adcli_check_nt_time_string_lifetime ("0", 0));

	/* 1969-01-01T00:00:00: 116129340000000000 */
	/* Calculated with PowerShell:
	 * (Get-Date -Date "1969-01-01T00:00:00").ToFileTime() */

	assert (!_adcli_check_nt_time_string_lifetime ("130645404000000000", 1));

	/* Make sure lifetime==0 will retrun false even if pwdLastSet is in the future */
	assert (asprintf (&time_str, "%llu",
			  (time (NULL) + 10 + AD_TO_UNIX_TIME_CONST) * 1000 * 1000 *10)
		!= -1);
	assert (!_adcli_check_nt_time_string_lifetime (time_str, 0));
	free (time_str);

	/* This test will fail some time after 2200AD as a reminder to reflect
	 * why adcli is still needed. */
	assert (_adcli_check_nt_time_string_lifetime ("130645404000000000", 100000));
}

static void
test_bin_sid_to_str (void)
{
	uint8_t sid1[] = { 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	                   0x15, 0x00, 0x00, 0x00, 0xF8, 0x12, 0x13, 0xDC,
	                   0x47, 0xF3, 0x1C, 0x76, 0x47, 0x2F, 0x2E, 0xD7,
	                   0x51, 0x04, 0x00, 0x00 };

	uint8_t sid2[] = { 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	                   0x15, 0x00, 0x00, 0x00, 0xF8, 0x12, 0x13, 0xDC,
	                   0x47, 0xF3, 0x1C, 0x76, 0x47, 0x2F, 0x2E, 0xD7};

	uint8_t sid3[] = { 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	                   0x15, 0x00, 0x00, 0x00, 0x29, 0xC9, 0x4F, 0xD9,
	                   0xC2, 0x3C, 0xC3, 0x78, 0x36, 0x55, 0x87, 0xF8};


	char *str;

	str = _adcli_bin_sid_to_str (sid1, sizeof (sid1));
	assert (str != NULL);
	assert (strcmp (str, "S-1-5-21-3692237560-1981608775-3610128199-1105") == 0);
	free (str);

	str = _adcli_bin_sid_to_str (sid2, sizeof (sid2));
	assert (str != NULL);
	assert (strcmp (str, "S-1-5-21-3692237560-1981608775-3610128199") == 0);
	free (str);

	str = _adcli_bin_sid_to_str (sid3, sizeof (sid2));
	assert (str != NULL);
	assert (strcmp (str, "S-1-5-21-3645884713-2026060994-4169618742") == 0);
	free (str);
}

static void
test_call_external_program (void)
{
	adcli_result res;
	char *argv[] = { NULL, NULL, NULL };
	uint8_t *stdout_data;
	size_t stdout_data_len;

	argv[0] = "/does/not/exists";
	res = _adcli_call_external_program (argv[0], argv, NULL, NULL, NULL);
	assert (res == ADCLI_ERR_FAIL);

#ifdef BIN_CAT
	argv[0] = BIN_CAT;
	res = _adcli_call_external_program (argv[0], argv, "Hello",
	                                    &stdout_data, &stdout_data_len);
	assert (res == ADCLI_SUCCESS);
	assert (strncmp ("Hello", (char *) stdout_data, stdout_data_len) == 0);
	free (stdout_data);

	res = _adcli_call_external_program (argv[0], argv, "Hello",
	                                    NULL, NULL);
	assert (res == ADCLI_SUCCESS);
#endif

#ifdef BIN_REV
	argv[0] = BIN_REV;
	res = _adcli_call_external_program (argv[0], argv, "Hello\n",
	                                    &stdout_data, &stdout_data_len);
	assert (res == ADCLI_SUCCESS);
	assert (strncmp ("olleH\n", (char *) stdout_data, stdout_data_len) == 0);
	free (stdout_data);
#endif

#ifdef BIN_TAC
	argv[0] = BIN_TAC;
	res = _adcli_call_external_program (argv[0], argv, "Hello\nWorld\n",
	                                    &stdout_data, &stdout_data_len);
	assert (res == ADCLI_SUCCESS);
	assert (strncmp ("World\nHello\n", (char *) stdout_data, stdout_data_len) == 0);
	free (stdout_data);
#endif

#ifdef BIN_ECHO
	argv[0] = BIN_ECHO;
	argv[1] = "Hello";
	res = _adcli_call_external_program (argv[0], argv, NULL,
	                                    &stdout_data, &stdout_data_len);
	assert (res == ADCLI_SUCCESS);
	assert (strncmp ("Hello\n", (char *) stdout_data, stdout_data_len) == 0);
	free (stdout_data);
#endif
}

int
main (int argc,
      char *argv[])
{
	test_func (test_strv_add_free, "/util/strv_add_free");
	test_func (test_strv_add_unique_free, "/util/strv_add_unique_free");
	test_func (test_strv_dup, "/util/strv_dup");
	test_func (test_strv_count, "/util/strv_count");
	test_func (test_check_nt_time_string_lifetime, "/util/check_nt_time_string_lifetime");
	test_func (test_bin_sid_to_str, "/util/bin_sid_to_str");
	test_func (test_call_external_program, "/util/call_external_program");
	return test_run (argc, argv);
}

#endif /* UTIL_TESTS */
