
#ifndef ADPRIVATE_H_
#define ADPRIVATE_H_

#include <stdarg.h>
#include <limits.h>
#include <stdlib.h>

#include "adconn.h"

#if !defined(__cplusplus) && (__GNUC__ > 2)
#define GNUC_PRINTF(x, y) __attribute__((__format__(__printf__, x, y)))
#else
#define GNUC_PRINTF(x, y)
#endif

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

void       _adcli_strup               (char *str);

adcli_result   _adcli_set_str_field   (char **field,
                                       const char *value);

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

void    _adcli_err             (adcli_conn *conn,
                                const char *format,
                                ...) GNUC_PRINTF(2, 3);

void    _adcli_warn            (adcli_conn *conn,
                                const char *format,
                                ...) GNUC_PRINTF(2, 3);

void    _adcli_info            (adcli_conn *conn,
                                const char *format,
                                ...) GNUC_PRINTF(2, 3);

#endif /* ADPRIVATE_H_ */
