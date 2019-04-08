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

#include <gssapi/gssapi_krb5.h>
#include <krb5/krb5.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>

krb5_error_code
_adcli_krb5_build_principal (krb5_context k5,
                             const char *user,
                             const char *realm,
                             krb5_principal *principal)
{
	krb5_error_code code;
	char *name = NULL;

	/* Use user if user contains a @-character and add @realm otherwise */
	if (strchr (user, '@') == NULL) {
		if (asprintf (&name, "%s@%s", user, realm) < 0) {
			return_val_if_reached (ENOMEM);
		}
	}

	code = krb5_parse_name (k5, name != NULL ? name : user, principal);
	return_val_if_fail (code == 0, code);

	free (name);
	return 0;
}

krb5_error_code
_adcli_krb5_keytab_clear (krb5_context k5,
                          krb5_keytab keytab,
                          krb5_boolean (* match_func) (krb5_context,
                                                       krb5_keytab_entry *,
                                                       void *),
                          void *match_data)
{
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	krb5_error_code code;

	code = krb5_kt_start_seq_get (k5, keytab, &cursor);
	if (code == KRB5_KT_END || code == ENOENT)
		return 0;
	else if (code != 0)
		return code;

	for (;;) {
		code = krb5_kt_next_entry (k5, keytab, &entry, &cursor);
		if (code != 0)
			break;

		/* See if we should remove this entry */
		if (!match_func (k5, &entry, match_data)) {
			krb5_free_keytab_entry_contents (k5, &entry);
			continue;
		}

		/*
		 * Here we close the cursor, remove the entry and then
		 * start all over again from the beginning. Dumb but works.
		 */

		code = krb5_kt_end_seq_get (k5, keytab, &cursor);
		return_val_if_fail (code == 0, code);

		code = krb5_kt_remove_entry (k5, keytab, &entry);
		krb5_free_keytab_entry_contents (k5, &entry);

		if (code != 0)
			return code;

		code = krb5_kt_start_seq_get (k5, keytab, &cursor);
		return_val_if_fail (code == 0, code);
	}

	if (code == KRB5_KT_END)
		code = 0;

	krb5_kt_end_seq_get (k5, keytab, &cursor);
	return code;
}

static krb5_boolean
match_all_entries (krb5_context k5,
                   krb5_keytab_entry *entry,
                   void *data)
{
	return TRUE;
}

krb5_error_code
_adcli_krb5_keytab_clear_all (krb5_context k5,
                              krb5_keytab keytab)
{
	return _adcli_krb5_keytab_clear (k5, keytab,
	                                 match_all_entries,
	                                 NULL);
}

krb5_error_code
_adcli_krb5_keytab_enumerate (krb5_context k5,
		              krb5_keytab keytab,
                              krb5_boolean (* match_func) (krb5_context,
                                                           krb5_keytab_entry *,
                                                           void *),
                              void *match_data)
{
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	krb5_error_code code;

	code = krb5_kt_start_seq_get (k5, keytab, &cursor);
	if (code == KRB5_KT_END || code == ENOENT)
		return 0;
	else if (code != 0)
		return code;

	for (;;) {
		code = krb5_kt_next_entry (k5, keytab, &entry, &cursor);
		if (code != 0)
			break;

		/* See if we should continue */
		if (!match_func (k5, &entry, match_data))
			break;
	}

	if (code == KRB5_KT_END)
		code = 0;

	krb5_kt_end_seq_get (k5, keytab, &cursor);
	return code;
}

adcli_result
_adcli_krb5_init_context (krb5_context *k5)
{
	krb5_error_code code;

	code = krb5_init_context (k5);
	if (code == ENOMEM) {
		return_unexpected_if_reached ();

	} else if (code != 0) {
		_adcli_err ("Failed to create kerberos context: %s",
		            krb5_get_error_message (NULL, code));
		return ADCLI_ERR_UNEXPECTED;
	}

	return ADCLI_SUCCESS;
}

adcli_result
_adcli_krb5_open_keytab (krb5_context k5,
                         const char *keytab_name,
		         krb5_keytab *keytab)
{
	krb5_error_code code;

	if (keytab_name && strcmp (keytab_name, "") != 0) {
		code = krb5_kt_resolve (k5, keytab_name, keytab);
		if (code != 0) {
			_adcli_err ("Failed to open keytab: %s: %s",
			            keytab_name, krb5_get_error_message (k5, code));
			return ADCLI_ERR_FAIL;
		}

	} else {
		code = krb5_kt_default (k5, keytab);
		if (code != 0) {
			_adcli_err ("Failed to open default keytab: %s",
			            krb5_get_error_message (k5, code));
			return ADCLI_ERR_FAIL;
		}
	}

	return ADCLI_SUCCESS;
}

typedef struct {
	krb5_kvno kvno;
	krb5_enctype enctype;
	int matched;
} match_enctype_kvno;

static krb5_boolean
match_enctype_and_kvno (krb5_context k5,
                        krb5_keytab_entry *entry,
                        void *data)
{
	krb5_boolean similar = FALSE;
	match_enctype_kvno *closure = data;
	krb5_error_code code;

	assert (closure->enctype);

	code = krb5_c_enctype_compare (k5, closure->enctype, entry->key.enctype,
	                               &similar);

	if (code == 0 && entry->vno == closure->kvno && similar) {
		closure->matched = 1;
		return 1;
	}

	return 0;
}

static krb5_error_code
_adcli_krb5_get_keyblock (krb5_context k5,
                          krb5_keytab keytab,
                          krb5_keyblock *keyblock,
                          krb5_boolean (* match_func) (krb5_context,
                                                       krb5_keytab_entry *,
                                                       void *),
                          void *match_data)
{
	krb5_kt_cursor cursor;
	krb5_keytab_entry entry;
	krb5_error_code code;

	code = krb5_kt_start_seq_get (k5, keytab, &cursor);
	if (code == KRB5_KT_END || code == ENOENT)
		return 0;
	else if (code != 0)
		return code;

	for (;;) {
		code = krb5_kt_next_entry (k5, keytab, &entry, &cursor);
		if (code != 0)
			break;

		/* See if we should remove this entry */
		if (!match_func (k5, &entry, match_data)) {
			krb5_free_keytab_entry_contents (k5, &entry);
			continue;
		}

		code = krb5_copy_keyblock_contents (k5, &entry.key, keyblock);
		krb5_free_keytab_entry_contents (k5, &entry);
		break;


	}

	if (code == KRB5_KT_END)
		code = 0;

	krb5_kt_end_seq_get (k5, keytab, &cursor);
	return code;
}

krb5_error_code
_adcli_krb5_keytab_copy_entries (krb5_context k5,
                                 krb5_keytab keytab,
                                 krb5_principal principal,
                                 krb5_kvno kvno,
                                 krb5_enctype *enctypes)
{
	krb5_keytab_entry entry;
	krb5_error_code code;
	int i;
	match_enctype_kvno closure;

	for (i = 0; enctypes[i] != 0; i++) {

		closure.kvno = kvno;
		closure.enctype = enctypes[i];
		closure.matched = 0;

		memset (&entry, 0, sizeof (entry));

		code = _adcli_krb5_get_keyblock (k5, keytab, &entry.key,
		                                 match_enctype_and_kvno, &closure);
		if (code != 0 || closure.matched == 0) {
			return code != 0 ? code : ENOKEY;
		}

		entry.principal = principal;
		entry.vno = kvno;

		code = krb5_kt_add_entry (k5, keytab, &entry);

		entry.principal = NULL;
		krb5_free_keytab_entry_contents (k5, &entry);

		if (code != 0)
			return code;
	}

	return 0;
}

krb5_error_code
_adcli_krb5_keytab_add_entries (krb5_context k5,
                                krb5_keytab keytab,
                                krb5_principal principal,
                                krb5_kvno kvno,
                                krb5_data *password,
                                krb5_enctype *enctypes,
                                krb5_data *salt)
{
	krb5_keytab_entry entry;
	krb5_error_code code;
	int i;

	for (i = 0; enctypes[i] != 0; i++) {
		memset (&entry, 0, sizeof(entry));

		code = krb5_c_string_to_key (k5, enctypes[i], password, salt, &entry.key);
		if (code != 0)
			return code;

		entry.principal = principal;
		entry.vno = kvno;

		code = krb5_kt_add_entry (k5, keytab, &entry);

		entry.principal = NULL;
		krb5_free_keytab_entry_contents (k5, &entry);

		if (code != 0)
			return code;
	}

	return 0;
}

krb5_error_code
_adcli_krb5_keytab_test_salt (krb5_context k5,
                              krb5_keytab scratch,
                              krb5_principal principal,
                              krb5_kvno kvno,
                              krb5_data *password,
                              krb5_enctype *enctypes,
                              krb5_data *salt)
{
	krb5_error_code code;
	krb5_creds creds;

	code = _adcli_krb5_keytab_clear_all (k5, scratch);
	return_val_if_fail (code == 0, code);

	code = _adcli_krb5_keytab_add_entries (k5, scratch, principal, kvno,
	                                       password, enctypes, salt);
	return_val_if_fail (code == 0, code);

	memset(&creds, 0, sizeof (creds));
	code = krb5_get_init_creds_keytab (k5, &creds, principal, scratch, 0, NULL, NULL);

	krb5_free_cred_contents (k5, &creds);

	return code;
}

krb5_error_code
_adcli_krb5_keytab_discover_salt (krb5_context k5,
                                  krb5_principal principal,
                                  krb5_kvno kvno,
                                  krb5_data *password,
                                  krb5_enctype *enctypes,
                                  krb5_data *salts,
                                  int *discovered)
{
	krb5_keytab scratch;
	krb5_error_code code;
	int i;
	krb5_enctype *salt_enctypes = NULL;
	size_t c;
	size_t s;

	/* TODO: This should be a unique name */

	code = krb5_kt_resolve (k5, "MEMORY:adcli-discover-salt", &scratch);
	return_val_if_fail (code == 0, code);

	for (c = 0; enctypes[c] != 0; c++); /* count enctypes */
	salt_enctypes = calloc (c + 1, sizeof (krb5_enctype));
	return_val_if_fail (salt_enctypes != NULL, ENOMEM);

	/* ENCTYPE_ARCFOUR_HMAC does not use salts, so it cannot be used to
	 * discover the right salt. */
	s = 0;
	for (c = 0; enctypes[c] != 0; c++) {
		if (enctypes[c] == ENCTYPE_ARCFOUR_HMAC) {
			continue;
		}

		salt_enctypes[s++] = enctypes[c];
	}

	for (i = 0; salts[i].data != NULL; i++) {
		code = _adcli_krb5_keytab_test_salt (k5, scratch, principal, kvno,
		                                     password, salt_enctypes, &salts[i]);
		if (code == 0) {
			*discovered = i;
			break;
		} else if (code != KRB5_PREAUTH_FAILED && code != KRB5KDC_ERR_PREAUTH_FAILED) {
			break;
		}
	}

	free (salt_enctypes);
	krb5_kt_close (k5, scratch);
	return code;
}

krb5_error_code
_adcli_krb5_w2k3_salt (krb5_context k5,
                       krb5_principal principal,
                       const char *host_netbios,
                       krb5_data *salt)
{
	krb5_data *realm;
	size_t size = 0;
	size_t host_length = 0;
	size_t at = 0;
	int i;

	/*
	 * The format for the w2k3 computer account salt is:
	 * REALM | "host" | SAM-Account-Name-Without-$ | "." | realm
	 */

	realm = krb5_princ_realm (k5, principal);
	host_length = strlen (host_netbios);

	size += realm->length;
	size += 4; /* "host" */
	size += host_length;
	size += 1; /* "." */
	size += realm->length;

	salt->data = malloc (size);
	return_val_if_fail (salt->data != NULL, ENOMEM);

	/* Upper case realm */
	for (i = 0; i < realm->length; i++)
		salt->data[at + i] = toupper (realm->data[i]);
	at += realm->length;

	/* The string "host" */
	memcpy (salt->data + at, "host", 4);
	at += 4;

	/* The netbios name in lower case */
	for (i = 0; i < host_length; i++)
		salt->data[at + i] = tolower (host_netbios[i]);
	at += host_length;

	/* The dot */
	memcpy (salt->data + at, ".", 1);
	at += 1;

	/* Lower case realm */
	for (i = 0; i < realm->length; i++)
		salt->data[at + i] = tolower (realm->data[i]);
	at += realm->length;

	assert (at == size);
	salt->length = size;
	return 0;
}

/* for msDs-supportedEncryptionTypes  bit defines */
#define MS_KERB_ENCTYPE_DES_CBC_CRC             0x01
#define MS_KERB_ENCTYPE_DES_CBC_MD5             0x02
#define MS_KERB_ENCTYPE_RC4_HMAC_MD5            0x04
#define MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96 0x08
#define MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96 0x10

krb5_enctype *
_adcli_krb5_parse_enctypes (const char *value)
{
	const int max_enctypes = 5;
	char *end = NULL;
	krb5_enctype *enctypes;
	int types;
	int at;

	types = strtoul (value, &end, 10);
	if (end == NULL || *end != '\0')
		return NULL;

	enctypes = calloc (max_enctypes + 1, sizeof (krb5_enctype));
	return_val_if_fail (enctypes != NULL, NULL);

	at = 0;
	if (types & MS_KERB_ENCTYPE_DES_CBC_CRC)
		enctypes[at++] = ENCTYPE_DES_CBC_CRC;
	if (types & MS_KERB_ENCTYPE_DES_CBC_MD5)
		enctypes[at++] = ENCTYPE_DES_CBC_MD5;
	if (types & MS_KERB_ENCTYPE_RC4_HMAC_MD5)
		enctypes[at++] = ENCTYPE_ARCFOUR_HMAC;
	if (types & MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96)
		enctypes[at++] = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
	if (types & MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96)
		enctypes[at++] = ENCTYPE_AES256_CTS_HMAC_SHA1_96;

	assert (at <= max_enctypes);
	enctypes[at] = 0;
	return enctypes;
}

char *
_adcli_krb5_format_enctypes (krb5_enctype *enctypes)
{
	char *value;
	int types;
	int i;

	types = 0;
	for (i = 0; enctypes[i] != 0; i++) {
		switch (enctypes[i]) {
		case ENCTYPE_DES_CBC_CRC:
			types |= MS_KERB_ENCTYPE_DES_CBC_CRC;
			break;
		case ENCTYPE_DES_CBC_MD5:
			types |= MS_KERB_ENCTYPE_DES_CBC_MD5;
			break;
		case ENCTYPE_ARCFOUR_HMAC:
			types |= MS_KERB_ENCTYPE_RC4_HMAC_MD5;
			break;
		case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
			types |= MS_KERB_ENCTYPE_AES128_CTC_HMAC_SHA1_96;
			break;
		case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
			types |= MS_KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96;
			break;
		default:
			break;
		}
	}

	if (types == 0)
		return NULL;

	if (asprintf (&value, "%d", types) < 0)
		return_val_if_reached (NULL);

	return value;
}
