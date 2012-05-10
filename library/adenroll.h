
#ifndef ADENROLL_H_
#define ADENROLL_H_

#include "adcli.h"

typedef struct _adcli_enroll_ctx adcli_enroll_ctx;

adcli_enroll_ctx * adcli_enroll_ctx_new            (void);

void               adcli_enroll_ctx_free           (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_message_func   (adcli_enroll_ctx *enroll,
                                                    adcli_message_func message);

const char *       adcli_enroll_get_domain_name    (adcli_enroll_ctx *enroll);

const char *       adcli_enroll_get_domain_realm  (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_domain_realm   (adcli_enroll_ctx *enroll,
                                                    const char *value);

const char *       adcli_enroll_get_host_fqdn      (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_host_fqdn      (adcli_enroll_ctx *enroll,
                                                    const char *value);

const char *       adcli_enroll_get_host_netbios   (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_host_netbios   (adcli_enroll_ctx *enroll,
                                                    const char *value);

const char **      adcli_enroll_get_ldap_urls      (adcli_enroll_ctx *enroll);

adcli_result       adcli_enroll_set_ldap_urls      (adcli_enroll_ctx *enroll,
                                                    const char **value);

adcli_result       adcli_enroll_add_ldap_url       (adcli_enroll_ctx *enroll,
                                                    const char *value);

adcli_result       adcli_enroll                    (const char *domain,
                                                    adcli_enroll_ctx *enroll);

#endif /* ADENROLL_H_ */
