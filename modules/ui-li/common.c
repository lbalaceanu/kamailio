#include "common.h"

str *parse_callid(struct sip_msg *const msg)
{
	if (!msg->callid && (parse_headers(msg, HDR_CALLID_F, 0) == -1 || !msg->callid)) {
		LM_ERR("bad msg or missing Call-ID header\n");
		return NULL;
	}

	return &msg->callid->body;
}

