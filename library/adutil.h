
#ifndef ADUTIL_H_
#define ADUTIL_H_

typedef enum {
	ADCLI_SUCCESS = 0,
	ADCLI_ERR_MEMORY = -1,
	ADCLI_ERR_SYSTEM = -2,
	ADCLI_ERR_DNS = -3,
	ADCLI_ERR_CREDENTIALS = -4,
	ADCLI_ERR_CONNECTION = -5,
} adcli_result;

typedef enum {
	ADCLI_MESSAGE_INFO,
	ADCLI_MESSAGE_WARNING,
	ADCLI_MESSAGE_ERROR
} adcli_message_type;

const char *      adcli_result_to_string        (adcli_result res);

#endif /* ADUTIL_H_ */
