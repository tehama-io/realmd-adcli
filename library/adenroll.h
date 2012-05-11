
#ifndef ADENROLL_H_
#define ADENROLL_H_

#include "adconn.h"

typedef struct _adcli_enroll adcli_enroll;

adcli_result       adcli_enroll_join                    (adcli_enroll *enroll);

adcli_enroll *     adcli_enroll_new                     (adcli_conn *conn);

adcli_enroll *     adcli_enroll_ref                     (adcli_enroll *enroll);

void               adcli_enroll_unref                   (adcli_enroll *enroll);

const char *       adcli_enroll_get_host_fqdn           (adcli_enroll *enroll);

void               adcli_enroll_set_host_fqdn           (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_host_netbios        (adcli_enroll *enroll);

void               adcli_enroll_set_host_netbios        (adcli_enroll *enroll,
                                                         const char *value);

char *             adcli_enroll_get_host_password       (adcli_enroll *enroll,
                                                         size_t *length);

void               adcli_enroll_set_host_password       (adcli_enroll *enroll,
                                                         const char *host_password,
                                                         ssize_t host_password_len);

const char *       adcli_enroll_get_preferred_ou        (adcli_enroll *enroll);

void               adcli_enroll_set_preferred_ou        (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_computer_container  (adcli_enroll *enroll);

void               adcli_enroll_set_computer_container  (adcli_enroll *enroll,
                                                         const char *value);

const char *       adcli_enroll_get_computer_account    (adcli_enroll *enroll);

void               adcli_enroll_set_computer_account    (adcli_enroll *enroll,
                                                         const char *value);

const char **      adcli_enroll_get_service_names       (adcli_enroll *enroll);

void               adcli_enroll_set_service_names       (adcli_enroll *enroll,
                                                         const char **value);

void               adcli_enroll_add_service_name        (adcli_enroll *enroll,
                                                         const char *value);

const char **      adcli_enroll_get_service_principals  (adcli_enroll *enroll);

void               adcli_enroll_set_service_principals  (adcli_enroll *enroll,
                                                         const char **value);

#endif /* ADENROLL_H_ */
