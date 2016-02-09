#ifndef _DEXPORT_H_
#define _DEXPORT_H_

#include "../../str.h"

#include "common.h"


typedef struct dexport_entry {
	str callid;
	str supplement;
	call_state_t state;
	unsigned int last_exp_time;
	struct dexport_entry *next;
} dexport_entry_t;

typedef struct dexport_list {
	int num_entries;
	dexport_entry_t *first;
} dexport_list_t;

typedef int (compare_delete_f)(dexport_entry_t *const entry, const void const* comp_arg);


int init_dexport_list(void);
int add_dexport(const str *const callid, const str *const supplement);
int delete_dexport(const str *const callid);
int delete_dexport_terminated(const unsigned int interval);
dexport_entry_t *find_dexport(const str *const callid);
int isempty_dexport(void);
int num_dexports(void);
void destroy_dexport(void);

#endif	/* _DEXPORT_H_ */
