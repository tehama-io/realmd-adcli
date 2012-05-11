
#ifndef ADENROLL_H_
#define ADENROLL_H_

#include "adconn.h"

typedef struct _adcli_enroll adcli_enroll;

adcli_result       adcli_enroll_join                  (adcli_enroll *enroll);

adcli_enroll *     adcli_enroll_new                   (adcli_conn *conn);

adcli_enroll *     adcli_enroll_ref                   (adcli_enroll *enroll);

void               adcli_enroll_unref                 (adcli_enroll *enroll);

const char *       adcli_enroll_get_host_fqdn         (adcli_enroll *enroll);

adcli_result       adcli_enroll_set_host_fqdn         (adcli_enroll *enroll,
                                                       const char *value);

const char *       adcli_enroll_get_host_netbios      (adcli_enroll *enroll);

adcli_result       adcli_enroll_set_host_netbios      (adcli_enroll *enroll,
                                                       const char *value);

const char *       adcli_enroll_get_computer_ou       (adcli_enroll *enroll);

adcli_result       adcli_enroll_set_computer_ou       (adcli_enroll *enroll,
                                                       const char *value);

#endif /* ADENROLL_H_ */
