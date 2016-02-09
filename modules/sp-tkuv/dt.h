#ifndef _DT_H_
#define _DT_H_




#include "../../sr_module.h"




int dt_init(void);
void dt_destroy(void);
void dt_clear(void);
void dt_insert(const char *number);
int dt_contains(const char *number);




#endif
