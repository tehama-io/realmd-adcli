
#ifndef ADPRIVATE_H_
#define ADPRIVATE_H_

#include "adconn.h"

#include <stdarg.h>
#include <limits.h>
#include <stdlib.h>

#include <ldap.h>

/* Utilities */

#if !defined(__cplusplus) && (__GNUC__ > 2)
#define GNUC_PRINTF(x, y) __attribute__((__format__(__printf__, x, y)))
#else
#define GNUC_PRINTF(x, y)
#endif

#define return_val_if_fail(x, v) \
	do { if (!(x)) { \
	     _adcli_precond_failed ("adcli: '%s' not true at %s\n", #x, __func__); \
	     return v; \
	} } while (0)

#define return_unexpected_if_fail(x) \
	return_val_if_fail ((x), ADCLI_ERR_UNEXPECTED)

#define return_if_fail(x) \
	do { if (!(x)) { \
	     _adcli_precond_failed ("adcli: '%s' not true at %s\n", #x, __func__); \
	     return; \
	} } while (0)

#define return_if_reached() \
	do { \
	     _adcli_precond_failed ("adcli: shouldn't be reached at %s\n", __func__); \
	     return; \
	} while (0)

#define return_val_if_reached(v) \
	do { \
	     _adcli_precond_failed ("adcli: shouldn't be reached at %s\n", __func__); \
	     return v; \
	} while (0)

#define return_unexpected_if_reached() \
	return_val_if_reached (ADCLI_ERR_UNEXPECTED)

void           _adcli_precond_failed         (const char *message,
                                              ...) GNUC_PRINTF (1, 2);

int            _adcli_strv_len               (char **strv);

char **        _adcli_strv_add               (char **strv,
                                              char *string,
                                              int *length);

void           _adcli_strv_free              (char **strv);

char **        _adcli_strv_dup               (char **strv);

char *         _adcli_strv_join              (char **strv,
                                              const char *delim);

void           _adcli_str_up                 (char *str);

char *         _adcli_str_dupn               (void *data,
                                              size_t len);

void           _adcli_str_set                (char **location,
                                              const char *value);

int            _adcli_mem_clear              (void *data,
                                              size_t length);

/* DNS service helpers */

typedef struct _adcli_srvinfo {
	unsigned short priority;
	unsigned short weight;
	unsigned short port;
	char hostname[HOST_NAME_MAX];
	struct _adcli_srvinfo *next;
} adcli_srvinfo;

int           _adcli_getsrvinfo              (const char *rrname,
                                              adcli_srvinfo **res);

void          _adcli_freesrvinfo             (adcli_srvinfo *res);

/* Connection helpers */

void          _adcli_err                     (adcli_conn *conn,
                                              const char *format,
                                              ...) GNUC_PRINTF(2, 3);

void          _adcli_warn                    (adcli_conn *conn,
                                              const char *format,
                                              ...) GNUC_PRINTF(2, 3);

void          _adcli_info                    (adcli_conn *conn,
                                              const char *format,
                                              ...) GNUC_PRINTF(2, 3);

/* LDAP helpers */

adcli_result  _adcli_ldap_handle_failure     (adcli_conn *conn,
                                              LDAP *ldap,
                                              const char *desc,
                                              const char *arg,
                                              adcli_result defres);

char *        _adcli_ldap_parse_value        (LDAP *ldap,
                                              LDAPMessage *results,
                                              const char *attr_name);

char **       _adcli_ldap_parse_values       (LDAP *ldap,
                                              LDAPMessage *results,
                                              const char *attr_name);

char *        _adcli_ldap_parse_dn           (LDAP *ldap,
                                              LDAPMessage *results);

#endif /* ADPRIVATE_H_ */
