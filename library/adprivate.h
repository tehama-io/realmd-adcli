
#ifndef ADPRIVATE_H_
#define ADPRIVATE_H_

#include <stdarg.h>
#include <limits.h>
#include <stdlib.h>

#if !defined(__cplusplus) && (__GNUC__ > 2)
#define GNUC_PRINTF(x, y) __attribute__((__format__(__printf__, x, y)))
#else
#define GNUC_PRINTF(x, y)
#endif

void       _adcli_messagev            (adcli_message_func func,
                                       adcli_message_type type,
                                       const char *format,
                                       va_list va);

int        _adcli_strv_len            (char **strv);

char **    _adcli_strv_add            (char **strv,
                                       char *string,
                                       int *length);

void       _adcli_strv_free           (char **strv);

char **    _adcli_strv_dup            (char **strv);

char *     _adcli_strv_join           (char **strv,
                                       const char *delim);

void *     _adcli_xrealloc            (void *ptr,
                                       size_t length);

typedef struct _adcli_srvinfo {
	unsigned short priority;
	unsigned short weight;
	unsigned short port;
	char hostname[HOST_NAME_MAX];
	struct _adcli_srvinfo *next;
} adcli_srvinfo;

int     _adcli_getsrvinfo      (const char *rrname,
                                adcli_srvinfo **res);

void    _adcli_freesrvinfo     (adcli_srvinfo *res);

#endif /* ADPRIVATE_H_ */
