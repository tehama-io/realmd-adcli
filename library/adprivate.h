
#ifndef ADPRIVATE_H_
#define ADPRIVATE_H_

#include <stdarg.h>

#if !defined(__cplusplus) && (__GNUC__ > 2)
#define GNUC_PRINTF(x, y) __attribute__((__format__(__printf__, x, y)))
#else
#define GNUC_PRINTF(x, y)
#endif

void       _adcli_messagev            (adcli_message_func func,
                                       adcli_message_type type,
                                       const char *format,
                                       va_list va);

#endif /* ADPRIVATE_H_ */
