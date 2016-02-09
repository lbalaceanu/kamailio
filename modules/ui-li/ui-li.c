#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"
#include "../../lib/kmi/mi.h"
#include "../../mod_fix.h"
#include "../../timer.h"
#include "../../modules/tm/tm_load.h"
#include "../dialog/dlg_load.h"

#include "common.h"
#include "dexport.h"
#include "callbacks.h"
#include "network.h"

MODULE_VERSION


static struct mi_root *mi_get_active_calls(struct mi_root *cmd, void *param);
static struct mi_root *mi_export_looped_msg(struct mi_root *cmd, void *param);
static struct mi_root *mi_export_looped_msg_status(struct mi_root *cmd, void *param);

static int mod_init(void);
static void destroy(void);
static int init_shmlock(gen_lock_t **lock);
static void destroy_shmlock(gen_lock_t **lock);
static int activate_monitoring(struct sip_msg *const msg, const char *const target_geo, const char *const dummy);
static void cleanup_monitored(unsigned int ticks, void* param);

static char* deliver_host = "localhost";
static int deliver_port = 8000;
static unsigned int cleanup_period = 300;               // in seconds
static unsigned int reaping_time = 180;                 // in seconds

atomic_t* export_looped_msg = NULL;

struct tm_binds tm_api;
struct dlg_binds dlg_api;
gen_lock_t *exp_list_lock;



static cmd_export_t cmds[] = {
	{"activate_monitoring", (cmd_function)activate_monitoring, 1, fixup_spve_null, 0, REQUEST_ROUTE},
	{0,0,0,0,0,0}
};


static param_export_t params[] = {
	{"deliver_host",		STR_PARAM, &deliver_host },
	{"deliver_port",		INT_PARAM, &deliver_port },
	{"cleanup_period",      INT_PARAM, &cleanup_period },
	{"reaping_time",        INT_PARAM, &reaping_time },
	{0, 0, 0 }
};


static mi_export_t mi_cmds[] = {
	{"li_get_active_calls",	mi_get_active_calls, MI_NO_INPUT_FLAG, 0, 0 },
	{"li_export_looped_msg",	mi_export_looped_msg, 0, 0, 0 },
	{"li_export_looped_msg_status",	mi_export_looped_msg_status, MI_NO_INPUT_FLAG, 0, 0 },
	{ 0, 0, 0, 0, 0}
};


struct module_exports exports = {
	"ui-li",
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,       /* exported functions */
	params,     /* exported params */
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* extra processes */
	mod_init,   /* initialization module */
	0,          /* response function */
	destroy,    /* destroy function */
	0,			/* per-child init function */
};



static struct mi_root *mi_get_active_calls(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *node = NULL;

	rpl_tree = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree == NULL) {
		return 0;
	}

	node = addf_mi_node_child(&rpl_tree->node, 0, 0, 0, "number of actively monitored calls: %d\n", num_dexports());
	if (node == NULL) {
		free_mi_tree(rpl_tree);
		return 0;
	}

	return rpl_tree;
}

static struct mi_root *mi_export_looped_msg(struct mi_root *cmd, void *param)
{
	struct mi_node *node = NULL;
	unsigned int val;

	node = cmd->node.kids;
	if ( node == NULL )
		return init_mi_tree( 400, MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);

	if ( !node->value.s|| !node->value.len|| str2int(&node->value, &val) < 0 )
		return init_mi_tree( 400, MI_BAD_PARM_S, MI_BAD_PARM_LEN);

	if ( val > 0 )
		atomic_set(export_looped_msg, 1);
	else
		atomic_set(export_looped_msg, 0);

	return init_mi_tree(200, MI_OK_S, MI_OK_LEN);
}

static struct mi_root *mi_export_looped_msg_status(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *node = NULL;

	rpl_tree = init_mi_tree(200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree == NULL) {
		return 0;
	}

	node = addf_mi_node_child(&rpl_tree->node, 0, 0, 0, "Export looped messages: %s\n",
			atomic_get(export_looped_msg)?"YES":"NO");
	if (node == NULL) {
		free_mi_tree(rpl_tree);
		return 0;
	}

	return rpl_tree;
}


static int mod_init(void)
{
	LM_INFO("initializing\n");

	if (register_mi_mod(exports.name, mi_cmds)!=0) {
		LM_ERR("failed to register MI commands\n");
		return -1;
	}

	if (init_dexport_list() != 0) return -1; 
	if (init_shmlock(&exp_list_lock) != 0) return -1;
	if (init_deliver_sock(deliver_host, deliver_port) != 0) return -1;

	/* load tm module API interface */
	if (load_tm_api(&tm_api) != 0) {
		LM_ERR("cannot load tm API. Is the tm module loaded?\n");
		return -1;
	}

	/* load dialog API interface */
	if (load_dlg_api(&dlg_api) != 0) {
		LM_ERR("cannot load dialog API. Is the dialog module loaded?\n");
		return(-1);
	}

	/* register initial dialog event */
	if (dlg_api.register_dlgcb(NULL, DLGCB_CREATED, consider_exporting, NULL, NULL) != 0) {
		LM_ERR("failed to register consider_exporting() for dialog event DLGCB_CREATED\n");
		return -1;
	}	

	/* register cleanup function */
	if (register_timer(cleanup_monitored, NULL, cleanup_period) < 0) {
		LM_ERR("failed to register cleanup_monitored()\n");
		return -1;
	}
	LM_DBG("registered cleanup process with period %u\n", cleanup_period);

	export_looped_msg = (atomic_t*)shm_malloc(sizeof(atomic_t));
	if (export_looped_msg == NULL) {
		LM_ERR("No more shared memory\n");
		return -1;
	}
	atomic_set(export_looped_msg, 1);

	LM_INFO("initialized\n");

	return 0;
}


static void destroy(void)
{
	destroy_deliver_sock();
	destroy_dexport();
	destroy_shmlock(&exp_list_lock);
	if ( export_looped_msg )
		shm_free(export_looped_msg);
}


static int init_shmlock(gen_lock_t **lock)
{
	*lock = lock_alloc();
	if (lock == NULL) {
		LM_CRIT("cannot allocate memory for lock\n");
		return -1;
	}

	if (lock_init(*lock) == 0) {
		LM_CRIT("cannot initialize lock\n");
		return -1;
	}

	return 0;
}


static void destroy_shmlock(gen_lock_t **lock)
{
	if (*lock) {
		lock_destroy(*lock);
		lock_dealloc((void *)*lock);
		*lock = NULL;
	}
}


static int activate_monitoring(struct sip_msg *const msg, const char *const target_geo, const char *const dummy)
{
	str tgeo, *callid;
	int add_res;

	if (fixup_get_svalue(msg, (gparam_p)target_geo, &tgeo) < 0) {
		LM_ERR("no hidden target geo number available\n");
		return -1;
	}

	callid = parse_callid(msg);
	if (callid == NULL) {
		LM_ERR("could not parse Call-ID header field\n");
		return -1;
	}

	LM_INFO("activating monitor operation for Call-ID %.*s\n", callid->len, callid->s);
	if (tgeo.len > 0) {
		LM_INFO("also adding supplementary data [%.*s]\n", tgeo.len, tgeo.s);
	}

	add_res = add_dexport(callid, &tgeo);
	if (add_res < 0) {
		LM_ERR("failed to activate monitoring of session for Call-ID %.*s\n", callid->len, callid->s);
		return -1;
	} else if (add_res == 0) {
		LM_DBG("session with Call-ID %.*s is already monitored", callid->len, callid->s);
	}
	LM_INFO("activation complete\n");

	return 1;
}


static void cleanup_monitored(unsigned int ticks, void* param)
{
	int reaped;

	reaped = delete_dexport_terminated(reaping_time);
	LM_DBG("reaped %u terminated export contexts\n", reaped);
}
