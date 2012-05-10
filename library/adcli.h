
#ifndef ADCLI_H_
#define ADCLI_H_

typedef enum {
	ADCLI_SUCCESS = 0,
	ADCLI_ERR_MEMORY = -1,
	ADCLI_ERR_SYSTEM = -2,
	ADCLI_ERR_DNS = -3,
	ADCLI_ERR_CREDENTIALS = -4,
} adcli_result;

typedef enum {
	ADCLI_MESSAGE_INFO,
	ADCLI_MESSAGE_WARNING,
	ADCLI_MESSAGE_ERROR
} adcli_message_type;

typedef void      (* adcli_message_func)        (adcli_message_type type,
                                                 const char *message,
                                                 void *data);

typedef char *    (* adcli_password_func)       (const char *prompt,
                                                 void *data);

typedef void      (* adcli_destroy_func)        (void *data);

const char *      adcli_result_to_string        (adcli_result res);

#include "adenroll.h"

#endif /* ADCLI_H_ */
