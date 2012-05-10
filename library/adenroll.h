
#ifndef ADENROLL_H_
#define ADENROLL_H_

#include "adcli.h"

#include <krb5/krb5.h>

typedef struct _adcli_enroll_ctx adcli_enroll_ctx;

adcli_result       adcli_enroll                       (const char *domain,
                                                       adcli_enroll_ctx *enroll);

adcli_enroll_ctx * adcli_enroll_ctx_new               (void);

void               adcli_enroll_ctx_free              (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_message_func      (adcli_enroll_ctx *enroll,
                                                       adcli_message_func message_func,
                                                       void *data,
                                                       adcli_destroy_func destroy_func);

const char *       adcli_enroll_get_domain_name       (adcli_enroll_ctx *enroll);

const char *       adcli_enroll_get_domain_realm      (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_domain_realm      (adcli_enroll_ctx *enroll,
                                                       const char *value);

const char *       adcli_enroll_get_host_fqdn         (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_host_fqdn         (adcli_enroll_ctx *enroll,
                                                       const char *value);

const char *       adcli_enroll_get_host_netbios      (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_host_netbios      (adcli_enroll_ctx *enroll,
                                                       const char *value);

const char **      adcli_enroll_get_ldap_urls         (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_ldap_urls         (adcli_enroll_ctx *enroll,
                                                       const char **value);

adcli_result       adcli_enroll_add_ldap_url          (adcli_enroll_ctx *enroll,
                                                       const char *value);

const char *       adcli_enroll_get_admin_name        (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_admin_name        (adcli_enroll_ctx *enroll,
                                                       const char *value);

const char *       adcli_enroll_get_admin_password    (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_admin_password    (adcli_enroll_ctx *enroll,
                                                       const char *value);

adcli_result       adcli_enroll_set_admin_password_func  (adcli_enroll_ctx *enroll,
                                                          adcli_password_func password_func,
                                                          void *data,
                                                          adcli_destroy_func destroy_data);

krb5_ccache        adcli_enroll_get_admin_ccache      (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_admin_ccache      (adcli_enroll_ctx *enroll,
                                                       krb5_ccache ccache);

const char *       adcli_enroll_get_admin_ccache_name (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_admin_ccache_name (adcli_enroll_ctx *enroll,
                                                       const char *ccname);

#endif /* ADENROLL_H_ */
