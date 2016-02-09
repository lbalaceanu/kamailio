#ifndef _DB_H_
#define _DB_H_




#include "../../sr_module.h"
#include "common.h"




int init_db(const str *url);
int init_db_child(const str *url);
void destroy_db(void);

// rebuild d-tree from entries in database
//   table   : tkuev table name in database
int update_from_db(const str *table);

int init_deliver_sock(char *host, int port);
void destroy_deliver_sock(void);

// deliver message to SSL handler.
// there may be more than one UEM for the given kennung...
//   dir     : 0=downstream, 1=upstream
//   kennung : the number on which the SIP message matched
//   table   : tkuev table name in database
void deliver(struct sip_msg * msg, int dir, number_t kennung, const str *table);




#endif
