
#include "config.h"

#include "adcli.h"
#include "adprivate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
_adcli_messagev (adcli_message_func func,
                 adcli_message_type type,
                 const char *format,
                 va_list va)
{
	char buffer[2048];
	int ret;

	if (func == NULL)
		return;

	ret = vsnprintf (buffer, sizeof (buffer), format, va);
	if (ret > 0)
		(func) (type, buffer);
}

const char *
adcli_result_to_string (adcli_result res)
{
	switch (res) {
	case ADCLI_SUCCESS:
		return "Success";
	case ADCLI_ERR_MEMORY:
		return "Out of memory";
	case ADCLI_ERR_SYSTEM:
		return "Internal error, see diagnostics";
	case ADCLI_ERR_DNS:
		return "DNS configuration or resolution problem";
	default:
		return "Unknown error";
	}
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
		if (string == NULL)
			break;
		result = _adcli_strv_add (result, string, &length);
		if (result == NULL)
			break;
	}

	/* Early break? */
	if (strv[i] != NULL) {
		_adcli_strv_free (result);
		result = NULL;
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
		result = _adcli_xrealloc (result, at + dlen + slen + 1);
		if (result == NULL)
			break;
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

	strv = _adcli_xrealloc (strv, sizeof (char *) * (len + 2));
	if (strv != NULL) {
		strv[len] = string;
		strv[len + 1] = 0;
		if (length)
			*length = len + 1;
	}

	return strv;
}

void *
_adcli_xrealloc (void *ptr,
                 size_t len)
{
	void *res = realloc (ptr, len);
	if (res == NULL)
		free (ptr);
	return res;
}
