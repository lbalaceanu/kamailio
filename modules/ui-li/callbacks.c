#include "callbacks.h"
#include "dexport.h"
#include "network.h"

#include "../../modules/tm/tm_load.h"
#include "../dialog/dlg_load.h"
#include "../../timer.h"


static void export_message(struct sip_msg *const orig_msg, char *const processed_msg, const int proc_msg_len, dexport_entry_t *const exp_entry);
static int register_tm_cbs(struct sip_msg *const msg, void *param);
static void handle_reg_dlg_cbs(struct dlg_cell *dlg, int type, struct dlg_cb_params *params);
static void handle_exp_dlg_cbs(struct dlg_cell *dlg, int type, struct dlg_cb_params *params);
static void handle_tm_cbs(struct cell *t, int type, struct tmcb_params *params);

extern struct tm_binds tm_api;
extern struct dlg_binds dlg_api;
extern gen_lock_t *exp_list_lock;
static int spiral_tracked;

static int li_is_maxfwd_present(struct sip_msg* msg , str *foo)
{
	int x, err;

	/* lookup into the message for MAX FORWARDS header*/
	if ( !msg->maxforwards ) {
		if  ( parse_headers( msg , HDR_MAXFORWARDS_F, 0 )==-1 ){
			LM_ERR("parsing MAX_FORWARD header failed!\n");
			return -2;
		}
		if (!msg->maxforwards) {
			LM_DBG("max_forwards header not found!\n");
			return -1;
		}
	} else if (msg->maxforwards->parsed) {
		trim_len( foo->len , foo->s , msg->maxforwards->body );
		return (((int)(long)msg->maxforwards->parsed)-1);
	}

	/* if header is present, trim to get only the string containing numbers */
	trim_len( foo->len , foo->s , msg->maxforwards->body );

	/* convert from string to number */
	x = str2s( foo->s,foo->len,&err);
	if (err){
		LM_ERR("unable to parse the max forwards number\n");
		return -2;
	}
	return x;
}

static int li_set_maxfwd(int x, str* s)
{
	int i;

	/*rewriting the max-fwd value in the message (buf and orig)*/
	for(i = s->len - 1; i >= 0; i--) {
		s->s[i] = (x % 10) + '0';
		x /= 10;
		if (x==0) {
			i = i - 1;
			break;
		}
	}
	while(i >= 0) s->s[i--] = ' ';

	return 0;

}


void consider_exporting(struct dlg_cell* dlg, int type, struct dlg_cb_params *params)
{
	str *callid;
	dexport_entry_t *exp_entry;
	int val;
	str mf_value= {0, 0};

	LM_INFO("considering to export SIP message\n");

	if (*params->param == NULL) {
		LM_INFO("tracking spiraled requests\n");
		if (dlg_api.register_dlgcb(dlg, DLGCB_SPIRALED, consider_exporting, &spiral_tracked, NULL) != 0) {
			LM_ERR("could not register consider_exporting() for dialog event DLGCB_SPIRALED\n");
		}
	}

	callid = parse_callid(params->req);
	if (callid == NULL) {
		LM_ERR("could not parse Call-ID header field\n");
		return;
	}

	LM_INFO("looking up Call-ID %.*s...\n", callid->len, callid->s);
	exp_entry = find_dexport(callid);
	if (exp_entry == NULL) {
		LM_INFO("...not found\n");
		return;
	}
	LM_INFO("...found! Proceeding\n");

	val=li_is_maxfwd_present(params->req, &mf_value);
	if(val < 0) {
		LM_ERR("failed to extract Max- Forwards header value\n");
	}
	else {
		val++;
		li_set_maxfwd(val, &mf_value);
	}

	LM_DBG("in (size: %d): %.*s\n", params->req->len, params->req->len, params->req->buf);

	LM_INFO("getting lock\n");
	lock_get(exp_list_lock);

	/* if source == myself, don't export */
	if (atomic_get(export_looped_msg)==0 && ip_addr_cmp(&params->req->rcv.src_ip, &params->req->rcv.dst_ip) ) {
		LM_NOTICE("Looped message - don't export\n");
	}
	else
		export_message(params->req, params->req->buf, params->req->len, exp_entry);

	/* put it back */

	if (exp_entry->state == STARTING) {
		LM_INFO("initializing cbs\n");

		LM_INFO("setting up handle_reg_dlg_cbs\n");
		if (dlg_api.register_dlgcb(dlg, DLGCB_REQ_WITHIN | DLGCB_CONFIRMED | DLGCB_TERMINATED | DLGCB_FAILED, handle_reg_dlg_cbs, exp_entry, NULL) != 0) {
			LM_ERR("could not register handle_reg_dlg_cbs() for various dialog events (Call-ID: %.*s)\n", callid->len, callid->s);
		}

		LM_INFO("setting up handle_exp_dlg_cbs\n");
		if (dlg_api.register_dlgcb(dlg, DLGCB_EXPIRED, handle_exp_dlg_cbs, (void *)exp_entry, NULL) != 0) {
			LM_ERR("could not register handle_exp_dlg_cbs() for dialog event DLGCB_EXPIRED (Call-ID: %.*s)\n", callid->len, callid->s);
		}

		exp_entry->state = RUNNING;
	}

	LM_INFO("setting up tm callbacks\n");
	if (register_tm_cbs(params->req, exp_entry) <= 0) {
		LM_ERR("could not register tm-specific callbacks (Call-ID: %.*s)\n", callid->len, callid->s);
	}

	LM_INFO("releasing lock\n");
	lock_release(exp_list_lock);

	/* restore max-forwards */
	if(val > 0) {
		val--;
		li_set_maxfwd(val, &mf_value);
	}

}


static void export_message(struct sip_msg *const orig_msg, char *const processed_msg, const int proc_msg_len, dexport_entry_t *const exp_entry)
{
	str proc_msg = { processed_msg, proc_msg_len };

	if (exp_entry != NULL) {
		LM_INFO("delivering message...\n");
		if (deliver_message(orig_msg, &proc_msg, exp_entry) < 0) {
			LM_ERR("could not deliver message (Call-ID: %.*s)\n", exp_entry->callid.len, exp_entry->callid.s);
		} else {
			LM_INFO("delivered successfully\n");
		}

		LM_DBG("updating export time\n");
		exp_entry->last_exp_time = get_ticks();
	}
}


static int register_tm_cbs(struct sip_msg *const msg, void *param)
{
	dexport_entry_t *exp_entry;

	if (tm_api.register_tmcb(msg, 0, TMCB_REQUEST_OUT | TMCB_ACK_NEG_IN | TMCB_REQUEST_PENDING | TMCB_RESPONSE_IN | TMCB_RESPONSE_READY, handle_tm_cbs, param, 0) <= 0) {
		exp_entry = (dexport_entry_t *)param;
		LM_ERR("could not register handle_tm_cbs() for various tm events (Call-ID: %.*s)\n", exp_entry->callid.len, exp_entry->callid.s);
		return -1;
	}

	return 1;
}


static void handle_reg_dlg_cbs(struct dlg_cell *dlg, int type, struct dlg_cb_params *params)
{
	dexport_entry_t *exp_entry = (dexport_entry_t *)*params->param;
	struct sip_msg *msg;

	LM_INFO("getting lock\n");
	lock_get(exp_list_lock);

	LM_INFO("handling regular dlg (Call-ID: %.*s)\n", exp_entry->callid.len, exp_entry->callid.s);

	if (type & DLGCB_REQ_WITHIN) {
		LM_INFO("sequential request was received\n");
		msg = params->req;
	} else if (type & DLGCB_CONFIRMED) {
		LM_INFO("ACK to INVITE's 200 OK was received\n");
		msg = params->req;
	} else if (type & DLGCB_TERMINATED) {
		exp_entry->state = TERMINATING;
		msg = params->req;
		LM_INFO("dialog is terminating\n");
	} else if (type & DLGCB_FAILED) {
		exp_entry->state = TERMINATING;
		msg = params->rpl;
		LM_INFO("dialog failed\n");
	} else {
		LM_ERR("received unexpected dlg callback type %d (Call-ID: %.*s)\n", type, exp_entry->callid.len, exp_entry->callid.s);
		lock_release(exp_list_lock);
		return;
	}

	if (msg == NULL || msg == FAKED_REPLY || msg->buf == NULL || msg->len == 0) {
		LM_INFO("dialog callback does not provide parsed message, dropping out\n");
		goto done;
	}

	if (register_tm_cbs(msg, (void *)exp_entry) <= 0) {
		LM_ERR("could not register tm-specific callbacks (Call-ID: %.*s)\n", exp_entry->callid.len, exp_entry->callid.s);
	}

	LM_DBG("in (size: %d): %.*s\n", msg->len, msg->len, msg->buf);

	export_message(msg, msg->buf, msg->len, exp_entry);

done:
	LM_INFO("releasing lock\n");
	lock_release(exp_list_lock);
}



static void handle_exp_dlg_cbs(struct dlg_cell *dlg, int type, struct dlg_cb_params *params)
{
	dexport_entry_t *exp_entry = (dexport_entry_t *)*params->param;

	LM_INFO("handling expired dlg (Call-ID: %.*s)\n", exp_entry->callid.len, exp_entry->callid.s);

	if (!(type & DLGCB_EXPIRED)) {
		LM_ERR("received unexpected dlg callback type %d (Call-ID: %.*s)\n", type, exp_entry->callid.len, exp_entry->callid.s);
		return;
	}

	LM_INFO("deleting export context due to expiration (Call-ID: %.*s)\n", exp_entry->callid.len, exp_entry->callid.s);
	if (delete_dexport(&exp_entry->callid) < 0) {
		LM_ERR("could not delete export context (Call-ID: %.*s)\n", exp_entry->callid.len, exp_entry->callid.s);
	}
}



static void handle_tm_cbs(struct cell *t, int type, struct tmcb_params *params)
{
	struct sip_msg *orig_msg;
	str processed_msg;
	dexport_entry_t *exp_entry = (dexport_entry_t *)*params->param;

	LM_INFO("getting lock\n");
	lock_get(exp_list_lock);

	LM_INFO("handling tm (Call-ID: %.*s)\n", exp_entry->callid.len, exp_entry->callid.s);

	if (type & TMCB_REQUEST_OUT) {
		LM_INFO("request was sent\n");

		if (params->send_buf.s == NULL || params->send_buf.len == 0) {
			LM_INFO("tm callback does not provide parsed message, dropping out\n");
			goto done;
		}

		LM_DBG("out (size: %d): %.*s\n", params->send_buf.len, params->send_buf.len, params->send_buf.s);

		orig_msg = params->req;
		processed_msg = params->send_buf;

		export_message(orig_msg, processed_msg.s, processed_msg.len, exp_entry);
	} else if (type & TMCB_ACK_NEG_IN) {
		LM_NOTICE("ACK to negative response was sent\n");

		if (params->send_buf.s == NULL || params->send_buf.len == 0) {
			LM_INFO("tm callback does not provide parsed message, dropping out\n");
			goto done;
		}

		orig_msg = params->rpl;
		processed_msg = params->send_buf;

		LM_NOTICE("out (size: %d): %.*s\n", params->send_buf.len, params->send_buf.len, params->send_buf.s);

		export_message(orig_msg, processed_msg.s, processed_msg.len, exp_entry);
	} else if (type & TMCB_REQUEST_PENDING) {
		LM_INFO("request-pending about to be returned\n");

		if (params->send_buf.s == NULL || params->send_buf.len == 0) {
			LM_INFO("tm callback does not provide parsed message, dropping out\n");
			goto done;
		}

		LM_DBG("out (size: %d): %.*s\n", params->send_buf.len, params->send_buf.len, params->send_buf.s);

		orig_msg = params->req;
		processed_msg = params->send_buf;

		export_message(orig_msg, processed_msg.s, processed_msg.len, exp_entry);
	} else if (type & TMCB_RESPONSE_IN) {
		LM_INFO("response was received\n");

		if (params->rpl == NULL || params->rpl == FAKED_REPLY || params->rpl->buf == NULL || params->rpl->len == 0) {
			LM_INFO("tm callback does not provide parsed message, dropping out\n");
			goto done;
		}

		LM_DBG("in (size: %d): %.*s\n", params->rpl->len, params->rpl->len, params->rpl->buf);

		orig_msg = params->rpl;
		processed_msg.s = params->rpl->buf;
		processed_msg.len = params->rpl->len;

		/* if source == myself, don't export */
		if (atomic_get(export_looped_msg)==0 && orig_msg->first_line.u.reply.statuscode!=100
				&& ip_addr_cmp(&orig_msg->rcv.src_ip, &orig_msg->rcv.dst_ip) ) {
			LM_NOTICE("Looped message - don't export\n");
		}
		else
			export_message(orig_msg, processed_msg.s, processed_msg.len, exp_entry);
	} else if (type & TMCB_RESPONSE_READY) {
		LM_INFO("response about to be sent\n");

		if (params->send_buf.s == NULL || params->send_buf.len == 0) {
			LM_INFO("tm callback does not provide parsed message, dropping out\n");
			goto done;
		}

		LM_DBG("out (size: %d): %.*s\n", params->send_buf.len, params->send_buf.len, params->send_buf.s);

		orig_msg = (params->rpl != NULL && params->rpl != FAKED_REPLY) ? params->rpl : params->req;
		processed_msg = params->send_buf;

		export_message(orig_msg, processed_msg.s, processed_msg.len, exp_entry);
	} else {
		LM_ERR("received unexpected tm callback type %d (Call-ID: %.*s)\n", type, exp_entry->callid.len, exp_entry->callid.s);
		lock_release(exp_list_lock);
		return;
	}

done:
	LM_INFO("releasing lock\n");
	lock_release(exp_list_lock);
}
