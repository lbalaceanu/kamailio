#ifndef _NETWORK_H_
#define _NETWORK_H_

#include "dexport.h"


int init_deliver_sock(const char *const host, const int port);
void destroy_deliver_sock(void);
int deliver_message(struct sip_msg *const orig_msg, const str *const processed_msg, dexport_entry_t *const exp_entry);

#endif	/* _NETWORK_H_ */

