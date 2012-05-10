
#include "config.h"

#include "adcli.h"
#include "adprivate.h"

#include <stdio.h>
#include <stdlib.h>

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
