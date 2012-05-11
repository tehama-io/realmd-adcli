
#ifndef ADUTIL_H_
#define ADUTIL_H_

typedef enum {
	/* Successful completion */
	ADCLI_SUCCESS = 0,

	/*
	 * Invalid input or unexpected system behavior.
	 *
	 * This is almost always caused by a bug, or completely broken
	 * system configuration or state. This is returned when memory
	 * allocation fails, but the process will almost certainly have
	 * been killed first.
	 *
	 * This is returned for invalid inputs (such an unexpected
	 * NULL) to adcli.
	 */
	ADCLI_ERR_UNEXPECTED = -2,

	/*
	 * A general failure, that doesn't fit into the other categories.
	 * Not much the caller can do.
	 */
	ADCLI_ERR_FAIL = -3,

	/*
	 * A problem with the active directory or connecting to it.
	 */
	ADCLI_ERR_DIRECTORY = -4,

	/*
	 * A logic problem with the configuration of the local system, or
	 * the settings passed into adcli.
	 */
	ADCLI_ERR_CONFIG = -5,

	/*
	 * Invalid credentials.
	 *
	 * The credentials are invalid, or don't have the necessary
	 * access rights.
	 */
	ADCLI_ERR_CREDENTIALS = -6,
} adcli_result;

typedef enum {
	ADCLI_MESSAGE_INFO,
	ADCLI_MESSAGE_WARNING,
	ADCLI_MESSAGE_ERROR
} adcli_message_type;

const char *      adcli_result_to_string        (adcli_result res);

#endif /* ADUTIL_H_ */
