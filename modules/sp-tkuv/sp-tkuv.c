#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "../../sr_module.h"
#include "../../script_cb.h"
#include "../../locking.h"
#include "../../timer.h"
#include "../../mem/shm_mem.h"
#include "../../modules/tm/t_hooks.h"
#include "../../modules/tm/tm_load.h"

#include "common.h"
#include "dt.h"
#include "db.h"

MODULE_VERSION




#define DT_UPDATE_INTERVAL (60)




static str db_url   = str_init("mysql://localhost/ser"); // DEFAULT_DB_URL;
static str db_table = str_init("tkuev7_cur");
static int ignore_register = 0;
static char* deliver_host = "localhost";
static int deliver_port = 7000;

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);




static cmd_export_t cmds[]={
	{0,0,0,0,0,0}
};




static param_export_t params[] = {
	{"db_url",          STR_PARAM, &db_url.s },
	{"db_table",        STR_PARAM, &db_table.s },
	{"ignore_register", INT_PARAM, &ignore_register },
	{"deliver_host",    STR_PARAM, &deliver_host },
	{"deliver_port",    INT_PARAM, &deliver_port },
	{0, 0, 0 }
};




struct module_exports exports= {
	"sp-tkuv",
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,       /* exported functions */
	params,     /* exported params */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* initialization module */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init  /* per-child init function */
};




static gen_lock_t *lock = NULL;
static unsigned int *last_dt_update = NULL;

struct tm_binds tmb;




static void tkuv_filter(struct sip_msg *original_request, struct sip_msg *deliver_msg)
{
	number_t from_number;
  number_t paid_number;
	number_t to_number;
	number_t diversion_number;
	number_t req_number;

  // could fail, eg if already parsed
  // don't care about result.
	parse_headers(original_request, HDR_FROM_F | HDR_TO_F | HDR_DIVERSION_F, 0);

  if (ignore_register) {
    // ignore register requests and responses
    if (strncmp("REGISTER", original_request->first_line.u.request.method.s, original_request->first_line.u.request.method.len) == 0) {
      return;
		}
	}

  paid_number[0] = 0;
  char *paid_start = strstr(original_request->buf, "P-Asserted-Identity:");
  if (paid_start) {
    char *paid_end = strstr(paid_start, "\r\n");
    char *paid_uri = strstr(paid_start, "sip:");
    if ((paid_end) && (paid_uri) && (paid_uri<paid_end)) {
      str paid_uri_s = { .s = paid_uri, .len = (paid_end - paid_uri) };
      canonize_number(paid_uri_s, paid_number);
    }
  }

  if (original_request->first_line.type == SIP_REQUEST) canonize_number(original_request->first_line.u.request.uri, req_number);
  else req_number[0] = 0;
  
  if (original_request->from == NULL) from_number[0] = 0;
  else canonize_number(original_request->from->body, from_number);
  
  if (original_request->to == NULL) to_number[0] = 0;
  else canonize_number(original_request->to->body, to_number);
  
  if (original_request->diversion == NULL) diversion_number[0] = 0;
  else canonize_number(original_request->diversion->body, diversion_number);
    
  // critical section start:
  //   avoids dirty reads when updating d-tree.
  //   avoids multiple concurrent d-tree updates.
  lock_get(lock);
  // d-tree update needed?
  if ((*last_dt_update) + DT_UPDATE_INTERVAL < get_ticks()) {
    int n = update_from_db(&db_table);
    if (n>=0) LM_INFO("d-tree updated (%d entries).\n", n);
    else LM_ERR("d-tree update failed!\n");
    (*last_dt_update) = get_ticks();
  }
  // check if sip message matches a UEM. deliver it if necessary.
  if (dt_contains(from_number)) {
    deliver(deliver_msg, 1, from_number, &db_table);
  }
  if (strcmp(paid_number, from_number) != 0) {
    if (dt_contains(paid_number)) {
      deliver(deliver_msg, 1, paid_number, &db_table);
    }
  }
  if (dt_contains(to_number)) {
    deliver(deliver_msg, 0, to_number, &db_table);
  }
  if ((strcmp(diversion_number, to_number) != 0) && (strcmp(diversion_number, req_number) != 0)) {
    if (dt_contains(diversion_number)) {
      deliver(deliver_msg, 0, diversion_number, &db_table);
      }
  }
  if ((strcmp(req_number, to_number) != 0) && (strcmp(req_number, to_number) != 0) && (strcmp(req_number, diversion_number) != 0)) {
    if (dt_contains(req_number)) {
      deliver(deliver_msg, 0, req_number, &db_table);
    }
  }
  // critical section end
  lock_release(lock);
}




/*
static void transaction_filter(struct cell* t, int type, struct tmcb_params* p)
{
  struct sip_msg *original_request = NULL;
  struct sip_msg *deliver_msg = NULL;

  if (type&TMCB_REQUEST_IN) {
    if (tmb.register_tmcb(0, t, TMCB_RESPONSE_OUT|TMCB_E2EACK_IN, transaction_filter, 0, 0) != 1) {
      LM_CRIT("cannot register tm callback.\n");
    }

    original_request = p->req;
    deliver_msg = p->req;
  }
  else if (type&TMCB_E2EACK_IN) {
    original_request = t->uas.request;
    deliver_msg = p->req;
  }
  else if (type&TMCB_RESPONSE_OUT) {
    original_request = t->uas.request;
    deliver_msg = p->rpl;
  }
  else {
    LM_ERR("invalid req type!\n");
    return;
  }

  // some sanity checks
  if (!original_request)  {
    LM_ERR("no original request!\n");
    return;
  }
  if (!deliver_msg)  {
    LM_ERR("no message to deliver!\n");
    return;
  }
  if (original_request==FAKED_REPLY) {
    //LM_ERR("faked request!\n");
    return;
  }
  if (deliver_msg==FAKED_REPLY) {
    //LM_ERR("faked reply!\n");
    return;
  }

  tkuv_filter(original_request, deliver_msg);
}
*/




static int pre_script_filter(struct sip_msg *msg, unsigned int flags, void *param)
{
  // could fail, eg if already parsed
  // don't care about result.
	parse_headers(msg, HDR_CSEQ_F, 0);

  if (ignore_register) {
    if (msg->first_line.type == SIP_REQUEST) {
			// ignore register requests
			if (strncmp("REGISTER", msg->first_line.u.request.method.s, msg->first_line.u.request.method.len) == 0) {
				return 1;
			}
		}
		else if (msg->first_line.type == SIP_REPLY) {
			// ignore replies to register requests
			struct cseq_body cseq_b;
			if (msg->cseq!=NULL) {
				char * tmp = msg->cseq->body.s;
				tmp = parse_cseq(tmp, tmp + msg->cseq->body.len + 2, &cseq_b);
				if (cseq_b.error==PARSE_ERROR){
					LM_ERR("bad cseq '%.*s'\n", msg->cseq->body.len, msg->cseq->body.s);
					return 1;
				}

				if (strncmp("REGISTER", cseq_b.method.s, cseq_b.method.len) == 0) {
					return 1;
				}
			}
		}
	}

  tkuv_filter(msg, msg);

	return 1;
}




static int init_shmlock(void)
{
	lock = lock_alloc();
	if (lock == NULL) {
		LM_CRIT("cannot allocate memory for lock.\n");
		return -1;
	}
	if (lock_init(lock) == 0) {
		LM_CRIT("cannot initialize lock.\n");
		return -1;
	}

	return 0;
}




static void destroy_shmlock(void)
{
	if (lock) {
		lock_destroy(lock);
		lock_dealloc((void *)lock);
		lock = NULL;
	}
}




static int mod_init(void)
{
	LM_INFO("initializing");
	db_url.len = strlen(db_url.s);
	db_table.len = strlen(db_table.s);

	/* load the TM API */
	if (load_tm_api(&tmb)!=0) {
		LM_ERR("Cannot load TM API.\n");
		return -1;
	}

	last_dt_update = shm_malloc(sizeof(unsigned int));
	if (last_dt_update == NULL) {
		LM_CRIT("cannot allocate shared memory.\n");
		return -1;
	}

	if (dt_init() != 0) return -1;
	if (init_shmlock() != 0) return -1;
	if (init_db(&db_url) != 0) return -1;
  if (init_deliver_sock(deliver_host, deliver_port) != 0) return -1;
	//update_from_db(db_table);

	if (register_script_cb(pre_script_filter, REQUEST_CB|PRE_SCRIPT_CB, 0) != 0) {
		LM_CRIT("cannot register reply script callback.\n");
		return -1;
	}
	if (register_script_cb(pre_script_filter, ONREPLY_CB|PRE_SCRIPT_CB, 0) != 0) {
		LM_CRIT("cannot register request script callback.\n");
		return -1;
	}

	//if (tmb.register_tmcb(0, 0, TMCB_REQUEST_IN, transaction_filter, 0) != 1 ) {
	//	LM_CRIT("cannot register tm callback (req).\n");
	//	return -1;
	//}

	LM_INFO("initialized.");

	return 0;
}




static int child_init (int rank)
{
	if (init_db_child(&db_url) != 0) return -1;

	return 0;
}




static void destroy(void)
{
	destroy_deliver_sock();
	destroy_db();
	destroy_shmlock();
	dt_destroy();
	if (last_dt_update) {
		shm_free(last_dt_update);
	}
}
