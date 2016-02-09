#ifndef _COMMON_H_
#define _COMMON_H_

#include "../../parser/msg_parser.h"
#include "../../str.h"


#define INTERCEPT_ID_SIZE 8


typedef enum call_state {
	STARTING,
	RUNNING,
	TERMINATING
} call_state_t;


str *parse_callid(struct sip_msg *const msg);

#endif
