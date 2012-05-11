
#ifndef ADCONN_H_
#define ADCONN_H_

#include "adutil.h"

#include <krb5/krb5.h>

typedef void        (* adcli_message_func)           (adcli_message_type type,
                                                      const char *message,
                                                      void *data);

typedef char *      (* adcli_password_func)          (const char *prompt,
                                                      void *data);

typedef void        (* adcli_destroy_func)           (void *data);

typedef struct _adcli_conn_ctx adcli_conn;

adcli_result        adcli_conn_connect               (adcli_conn *conn);

adcli_conn *        adcli_conn_new                   (const char *domain);

adcli_conn *        adcli_conn_ref                   (adcli_conn *conn);

void                adcli_conn_unref                 (adcli_conn *conn);

adcli_result        adcli_conn_set_message_func      (adcli_conn *conn,
                                                      adcli_message_func message_func,
                                                      void *data,
                                                      adcli_destroy_func destroy_func);

adcli_result        adcli_conn_set_password_func     (adcli_conn *conn,
                                                      adcli_password_func password_func,
                                                      void *data,
                                                      adcli_destroy_func destroy_data);

const char *        adcli_conn_get_host_fqdn         (adcli_conn *conn);

adcli_result        adcli_conn_set_host_fqdn         (adcli_conn *conn,
                                                      const char *value);

const char *        adcli_conn_get_domain_name       (adcli_conn *conn);

adcli_result        adcli_conn_set_domain_name       (adcli_conn *conn,
                                                      const char *value);

const char *        adcli_conn_get_domain_realm      (adcli_conn *conn);

adcli_result        adcli_conn_set_domain_realm      (adcli_conn *conn,
                                                      const char *value);

const char **       adcli_conn_get_ldap_urls         (adcli_conn *conn);

adcli_result        adcli_conn_set_ldap_urls         (adcli_conn *conn,
                                                      const char **value);

adcli_result        adcli_conn_add_ldap_url          (adcli_conn *conn,
                                                      const char *value);

const char *        adcli_conn_get_admin_name        (adcli_conn *conn);

adcli_result        adcli_conn_set_admin_name        (adcli_conn *conn,
                                                      const char *value);

const char *        adcli_conn_get_admin_password    (adcli_conn *conn);

adcli_result        adcli_conn_set_admin_password    (adcli_conn *conn,
                                                      const char *value);

krb5_ccache         adcli_conn_get_admin_ccache      (adcli_conn *conn);

const char *        adcli_conn_get_admin_ccache_name (adcli_conn *conn);

adcli_result        adcli_conn_set_admin_ccache_name (adcli_conn *conn,
                                                      const char *ccname);

#endif /* ADCONN_H_ */
