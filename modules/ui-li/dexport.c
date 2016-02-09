#include "../../locking.h"
#include "../../config.h"
#include "../../mem/shm_mem.h"
#include "../../timer.h"

#include "dexport.h"


extern gen_lock_t *exp_list_lock;
static dexport_list_t *dexport_list = NULL;


static int comp_del_callid(dexport_entry_t *const entry, const void const* comp_arg)
{
	str *callid = (str *)comp_arg;

	return (entry->callid.len == callid->len) && (strncmp(entry->callid.s, callid->s, callid->len) == 0) ? 1 : 0;
}


static int comp_del_interval(dexport_entry_t *const entry, const void const* comp_arg)
{
	unsigned int interval = *(unsigned int *)comp_arg;
	unsigned int ticks = get_ticks();

	LM_DBG("time %u: checking call with state %d, last_exp_time %u (interval %u)\n", ticks, entry->state, entry->last_exp_time, interval);
	if ((entry->state == TERMINATING) && (ticks - entry->last_exp_time > interval)) {
		LM_DBG("entry with Call-ID %.*s must be deleted\n", entry->callid.len, entry->callid.s);
		return 1;
	} else {
		return 0;
	}
}


static int comp_del_always(dexport_entry_t *const entry, const void const* comp_arg)
{
	return 1;
}


static void delete_entry_content(dexport_entry_t *const entry)
{
	if (entry->callid.s != NULL) { 
		shm_free(entry->callid.s);
	}
	if (entry->supplement.s != NULL) {
		shm_free(entry->supplement.s);
	}
}


static void delete_dexport_entry(dexport_entry_t *entry)
{
	if (entry != NULL) {
		delete_entry_content(entry);
		shm_free(entry);
		--dexport_list->num_entries;
	}
}


static dexport_entry_t *_find_dexport(const str *const callid)
{
	dexport_entry_t *entry;

	if (dexport_list->first == NULL) {
		return NULL;
	}

	for (entry = dexport_list->first; entry != NULL; entry = entry->next) {
		if ((entry->callid.len == callid->len) && (strncmp(entry->callid.s, callid->s, callid->len) == 0)) {
			break;
		}
	}

	return entry;
}


static int _delete_dexport(compare_delete_f compare_delete, const void const* comp_arg, const int max_delete)
{
	dexport_entry_t *entry, *last_entry, *del_entry;
	entry = dexport_list->first;
	last_entry = NULL;
	int deleted = 0;

	if (dexport_list->first == NULL) {
		return 0;
	}

	while (entry != NULL) {
		del_entry = entry;
		entry = entry->next;

		if (compare_delete(del_entry, comp_arg) == 1) {
			LM_DBG("found entry meeting deletion criteria, belonging to Call-ID %.*s -- deleting.\n", del_entry->callid.len, del_entry->callid.s);

			/* adjust dexport_list */
			if (dexport_list->first == del_entry) {
				/* deleted item was first in list -- set new first item to next in list */
				dexport_list->first = entry;
			} else {
				/* deleted item was in-between or at the end -- have list skip deleted item */
				last_entry->next = entry;
			}

			delete_dexport_entry(del_entry);
			del_entry = NULL;
			++deleted;

			if (deleted == max_delete) {
				break;
			}
		} else {
			last_entry = del_entry;
		}
	}

	return deleted;
}



int init_dexport_list(void) {
	dexport_list = shm_malloc(sizeof(dexport_list_t));
	if (dexport_list == NULL) {
		LM_CRIT("could not allocate %d bytes of memory for dexport list\n", sizeof(dexport_list_t));
		return -1;
	}
	bzero(dexport_list, sizeof(dexport_list_t));

	return 0;
}


int add_dexport(const str *const callid, const str *const supplement)
{
	dexport_entry_t *entry = NULL;
	int is_new_entry = 0;

	if (callid == NULL || supplement == NULL) {
		LM_ERR("either Call-ID or supplementary data not given, cannot add export entry.\n");
		return -1;
	}

	lock_get(exp_list_lock);

	entry = _find_dexport(callid);
	if (entry == NULL) {
		LM_DBG("creating new export\n");

		/* create new entry */
		entry = shm_malloc(sizeof(dexport_entry_t));
		if (entry == NULL) {
			LM_CRIT("could not allocate %d bytes of memory for new dexport entry\n", sizeof(dexport_entry_t));
			goto error;
		}
		is_new_entry = 1;
		memset(entry, 0, sizeof(*entry));

		/* store Call-ID */
		entry->callid.s = shm_malloc(callid->len);
		if (entry->callid.s == NULL) {
			LM_CRIT("could not allocate %d bytes of memory for new entry's Call-ID\n", callid->len);
			goto error;
		}
		memcpy(entry->callid.s, callid->s, callid->len);
		entry->callid.len = callid->len;
		entry->state = STARTING;

		/* hook up new entry in dexport_list */
		if (dexport_list->first == NULL) {
			/* first entry in list */
			dexport_list->first = entry;
			entry->next = NULL;
		} else {
			/* successive entry in list -- put it up front */
			entry->next = dexport_list->first;
			dexport_list->first = entry;
		}
		++dexport_list->num_entries;
	}

	/* store supplementary data to existing or new entry (if none stored yet) */
	if (supplement->s != NULL && supplement->len > 0 && entry->supplement.s == NULL) {
		LM_DBG("adding supplementary data %.*s\n", supplement->len, supplement->s);
		entry->supplement.s = shm_malloc(supplement->len + CRLF_LEN);
		if (entry->supplement.s == NULL) {
			LM_CRIT("could not allocate %d bytes of memory for supplementary data and CRLF\n", supplement->len + CRLF_LEN);
			goto error;
		}
		memcpy(entry->supplement.s, CRLF, CRLF_LEN);
		memcpy(entry->supplement.s+CRLF_LEN, supplement->s, supplement->len);
		entry->supplement.len = supplement->len+CRLF_LEN;
	}

	lock_release(exp_list_lock);
	return is_new_entry;

error:
	if (is_new_entry) {
		delete_dexport_entry(entry);
		entry = NULL;
	}
	lock_release(exp_list_lock);
	return -1;
}


int delete_dexport(const str *const callid)
{
	int success;

	if (callid == NULL) {
		LM_ERR("no Call-ID given, cannot delete export entry\n");
		return -1;
	}

	lock_get(exp_list_lock);

	success = _delete_dexport(comp_del_callid, callid, 1);
	if (success != 1) {
		LM_ERR("no entry found belonging to Call-ID %.*s\n", callid->len, callid->s);
		success = -1;
	}

	lock_release(exp_list_lock);
	return success;
}


int delete_dexport_terminated(const unsigned int interval)
{
	int deleted;

	lock_get(exp_list_lock);

	if (dexport_list->first == NULL) {
		lock_release(exp_list_lock);
		return 0;
	}

	deleted = _delete_dexport(comp_del_interval, &interval, -1);

	lock_release(exp_list_lock);
	return deleted;
}


dexport_entry_t *find_dexport(const str *const callid)
{
	dexport_entry_t *entry = NULL;

	if (callid->s == NULL || callid->len == 0) {
		LM_ERR("Call-ID not given, won't try to find an export entry.");
		return NULL;
	}

	lock_get(exp_list_lock);

	entry = _find_dexport(callid);

	lock_release(exp_list_lock);

	return entry;
}


inline int isempty_dexport(void) 
{
	int ret;

	lock_get(exp_list_lock);
	ret = (dexport_list->first == NULL) ? 1 : 0;
	lock_release(exp_list_lock);

	return ret;
}


inline int num_dexports(void)
{
	int num;

	lock_get(exp_list_lock);

	num = dexport_list->num_entries;

	lock_release(exp_list_lock);
	return num;
}


void destroy_dexport(void)
{
	if (dexport_list == NULL) {
		// initialization must have failed -- bail out immediately
		return;
	}

	lock_get(exp_list_lock);

	_delete_dexport(comp_del_always, NULL, -1);

	lock_release(exp_list_lock);
}
