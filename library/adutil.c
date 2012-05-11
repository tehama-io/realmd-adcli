
#include "config.h"

#include "adcli.h"
#include "adprivate.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void
_adcli_precond_failed (const char *message,
                       ...)
{
	va_list va;

	va_start (va, message);
	vfprintf (stderr, message, va);
	va_end (va);

	/* TODO: add logic to make these optionally fatal */
}

void
_adcli_strv_free (char **strv)
{
	int i;

	if (strv == NULL)
		return;

	for (i = 0; strv[i] != NULL; i++)
		free (strv[i]);
	free (strv);
}

char **
_adcli_strv_dup (char **strv)
{
	char **result = NULL;
	int length = 0;
	char *string;
	int i;

	if (strv == NULL)
		return NULL;

	for (i = 0; strv[i] != NULL; i++) {
		string = strdup (strv[i]);
		return_val_if_fail (string != NULL, NULL);
		result = _adcli_strv_add (result, string, &length);
		return_val_if_fail (result != NULL, NULL);
	}

	return result;
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
	for (i = 0; strv[i] != NULL; i++) {
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
	int count = 0;

	if (!strv)
		return 0;

	while (*strv != NULL) {
		strv++;
		count++;
	}

	return count;
}

char **
_adcli_strv_add (char **strv,
                 char *string,
                 int *length)
{
	int len = 0;

	if (length)
		len = *length;
	else
		len = _adcli_strv_len (strv);

	strv = realloc (strv, sizeof (char *) * (len + 2));
	return_val_if_fail (strv != NULL, NULL);

	strv[len] = string;
	strv[len + 1] = 0;
	if (length)
		*length = len + 1;

	return strv;
}

void
_adcli_str_up (char *str)
{
	while (*str != '\0') {
		*str = toupper (*str);
		str++;
	}
}

void
_adcli_str_set (char **field,
                const char *value)
{
	char *newval = NULL;

	if (*field == value)
		return;

	if (value) {
		newval = strdup (value);
		return_if_fail (newval != NULL);
	}

	free (*field);
	*field = newval;
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
