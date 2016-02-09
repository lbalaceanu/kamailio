#ifndef _COMMON_H_
#define _COMMON_H_




#include "../../sr_module.h"




#define MAXNUMBERLEN 31




typedef char number_t[MAXNUMBERLEN + 1];




void canonize_number(const str uri, number_t canon_number);




#endif
