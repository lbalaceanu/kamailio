#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>

#include "../../locking.h"
#include "../../parser/msg_parser.h"
#include "../../mem/mem.h"
#include "../../globals.h"
#include "../../crc.h"

#include "common.h"
#include "network.h"

#define DBL_CRLF "\r\n\r\n"
#define DBL_CRLF_LEN (sizeof(DBL_CRLF)-1)
#define MAX_TIMESTAMP 100


static struct sockaddr_in deliver_addr;
static int deliver_sockfd = 0;


static int get_sip_hdr_len(const struct sip_msg *const msg, const str *const proc_msg)
{
	char *idx;

	if (msg->buf == proc_msg->s) {
		// assume message is already completely parsed
		return msg->eoh - msg->buf - CRLF_LEN;
	} else {
		idx = proc_msg->s;

		while (idx <= proc_msg->s + proc_msg->len - DBL_CRLF_LEN) {
			if (strncmp(DBL_CRLF, idx, DBL_CRLF_LEN) == 0) {
				return idx - proc_msg->s;
			}

			++idx;
		}

		idx += DBL_CRLF_LEN-CRLF_LEN;
		if (*idx == '\n' || *idx == '\r') {
			return idx - proc_msg->s;
		}

		return -1;
	}
}



int init_deliver_sock(const char *const host, const int port)
{
	deliver_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (deliver_sockfd < 0) {
		LM_CRIT("could not create UDP socket to host %s and port %d\n", host, port);
		return -1;
	}

	memset(&deliver_addr, 0, sizeof(deliver_addr));
	deliver_addr.sin_family = AF_INET;
	deliver_addr.sin_port = htons(port);
	inet_pton(AF_INET, host, &deliver_addr.sin_addr);

	return 0;
}



void destroy_deliver_sock(void)
{
	if (deliver_sockfd > 0) {
		LM_DBG("closing socket %d\n", deliver_sockfd);
		close(deliver_sockfd);
	}
}



// builds the envelope for given SIP message and actually sends the packet
int deliver_message(struct sip_msg *const orig_msg, const str *const processed_msg, dexport_entry_t *const exp_entry)
{
	str li_packet = {NULL, processed_msg->len};
	double now;
	struct timeval tv;
	char timestamp[MAX_TIMESTAMP];
	int timestamp_len;
	str *supplement = NULL;
	int sip_hdr_len = -1;
	int send_result;

	/* parse SIP message completely */
	if (!orig_msg || !processed_msg || orig_msg->buf != processed_msg->s && parse_headers(orig_msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("could not parse SIP message (Call-ID: %.*s)\n", exp_entry->callid.len, exp_entry->callid.s);
		return -1;
	}

	if (gettimeofday(&tv, NULL) != 0) {
		LM_ERR("could not get current time of day\n");
		return -1;
	}

	now = (double)tv.tv_sec + (double)tv.tv_usec/(1000*1000);

	if (snprintf(timestamp, MAX_TIMESTAMP, "timestamp: %f\r\n", now) >= MAX_TIMESTAMP) {
		LM_ERR("could not store timestamp in buffer\n");
	}	
	timestamp_len = strlen(timestamp);
	li_packet.len += timestamp_len;

	/* if given, append supplementary data to SIP header */
	if (exp_entry->state == STARTING && exp_entry->supplement.len > 0) {
		supplement = &exp_entry->supplement;

		sip_hdr_len = get_sip_hdr_len(orig_msg, processed_msg);

		if (sip_hdr_len <= 0) {
			LM_ERR("could not compute SIP header length\n");
			return -1;
		}

		li_packet.len += supplement->len;
	}

	li_packet.s = pkg_malloc(li_packet.len);
	if (li_packet.s == NULL) {
		LM_CRIT("could not allocate %d bytes of memory for LI packet\n", li_packet.len);
		return -1;
	}

	memcpy(li_packet.s, timestamp, timestamp_len);

	if (supplement != NULL) {
		memcpy(li_packet.s+timestamp_len, processed_msg->s, sip_hdr_len);
		memcpy(li_packet.s+timestamp_len+sip_hdr_len, supplement->s, supplement->len);
		memcpy(li_packet.s+timestamp_len+sip_hdr_len+supplement->len, processed_msg->s+sip_hdr_len, processed_msg->len-sip_hdr_len);
	} else {
		memcpy(li_packet.s+timestamp_len, processed_msg->s, processed_msg->len);
	}

	/* exported message transmission */
	LM_INFO("transmitting LI packet\n");
	send_result = (sendto(deliver_sockfd, li_packet.s, li_packet.len, 0, (struct sockaddr *)&deliver_addr, sizeof(deliver_addr)) == li_packet.len);

	if (!send_result) {
		LM_ERR("could not send LI packet over socket (Call-ID: %.*s, exported message: %.*s)\n", exp_entry->callid.len, exp_entry->callid.s, li_packet.len, li_packet.s);
	}

	pkg_free(li_packet.s);

	return (send_result) ? 0 : -1;
}
