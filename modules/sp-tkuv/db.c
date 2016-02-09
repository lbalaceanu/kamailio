#include "db.h"
#include "dt.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#include "../../lib/srdb1/db.h"
#include "../../mem/mem.h"




#define MAXLIIDLEN 25




static db1_con_t *dbc;
static db_func_t dbf;

static int deliver_sockfd = 0;
static struct sockaddr_in deliver_addr;

static str referenznummer_str = str_init("referenznummer");
static str kennung_str = str_init("kennung");
static str comp_name_str = str_init("target_type");
static str comp_val_str = str_init("ftp");



struct CC_header_Versiont_t {
	u_int16_t id;
	u_int16_t len;
	u_int16_t value;
} __attribute__((packed));

struct CC_header_PayloadType_t {
	u_int16_t id;
	u_int16_t len;
	u_int8_t value;
} __attribute__((packed));

struct CC_header_PayloadTimeStamp_t {
	u_int16_t id;
	u_int16_t len;
	u_int32_t value;
} __attribute__((packed));

struct CC_header_PayloadDirection_t {
	u_int16_t id;
	u_int16_t len;
	u_int8_t value;
} __attribute__((packed));

struct CC_header_CorrelationNumber_t {
	u_int16_t id;
	u_int16_t len;
	char value[8];
} __attribute__((packed));

struct CC_header_LIID_t {
	u_int16_t id;
	u_int16_t len;
	char value[MAXLIIDLEN];
} __attribute__((packed));

struct CC_header_value_t {
	struct CC_header_Versiont_t Version;
	struct CC_header_PayloadType_t PayloadType;
	struct CC_header_PayloadTimeStamp_t PayloadTimeStamp;
	struct CC_header_PayloadDirection_t PayloadDirection;
	struct CC_header_CorrelationNumber_t CorrelationNumber;
	struct CC_header_LIID_t LIID;  // has to be the last element in struct
} __attribute__((packed));

struct CC_header_t {
	u_int16_t id;
	u_int16_t len;
	struct CC_header_value_t value;  // has to be the last element in struct
} __attribute__((packed));

struct CC_payload_t {
	u_int16_t id;
	u_int16_t len;
	char value[];
} __attribute__((packed));

struct CC_t {
	struct CC_header_t header;
	struct CC_payload_t payload;
} __attribute__((packed));

struct CCIE_t {
	u_int16_t id;
	u_int16_t len;
	struct CC_t value;
} __attribute__((packed));




void init_CCIE(struct CCIE_t *ccie, const struct sip_msg *msg, int dir, const char *liid)
{
	int msglen = msg->len;
  int liidlen = strlen(liid);

	ccie->id = 0x00fb;
	ccie->len = sizeof(struct CC_t) + msglen + liidlen - MAXLIIDLEN;  // take only the actual number of characters in liid

	ccie->value.header.id = 0x00fc;
	ccie->value.header.len = sizeof(struct CC_header_value_t) + liidlen - MAXLIIDLEN;  // take only the actual number of characters in liid

	ccie->value.header.value.Version.id = 0x0082;
	ccie->value.header.value.Version.len = 2;
	ccie->value.header.value.Version.value = 0x0002;

	ccie->value.header.value.PayloadType.id = 0x0085;
	ccie->value.header.value.PayloadType.len = 1;
	ccie->value.header.value.PayloadType.value = 255;

	ccie->value.header.value.PayloadTimeStamp.id = 0x0086;
	ccie->value.header.value.PayloadTimeStamp.len = 4;
	ccie->value.header.value.PayloadTimeStamp.value = time(NULL);

	ccie->value.header.value.PayloadDirection.id = 0x0089;
	ccie->value.header.value.PayloadDirection.len = 1;
	ccie->value.header.value.PayloadDirection.value = dir;

	ccie->value.header.value.CorrelationNumber.id = 0x0090;
	ccie->value.header.value.CorrelationNumber.len = 8;
	memset(ccie->value.header.value.CorrelationNumber.value, 0, sizeof(ccie->value.header.value.CorrelationNumber.value));
	ccie->value.header.value.CorrelationNumber.value[0] = 1;

	ccie->value.header.value.LIID.id = 0x00fe;
	ccie->value.header.value.LIID.len = liidlen;
	strncpy(ccie->value.header.value.LIID.value, liid, MAXLIIDLEN);  // take only the actual number of characters in liid

	ccie->value.payload.id = 0x00fd;
	ccie->value.payload.len = msglen;
}




int init_deliver_sock(char *host, int port)
{
	deliver_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (deliver_sockfd < 0) {
		LM_CRIT("Can't get socket.\n");
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
  	if (deliver_sockfd) {
		close(deliver_sockfd);
	}
}




// builds the envelope for given SIP message and actually sends the packet
void deliver_refnr(struct sip_msg *msg, int dir, const char *refnr)
{
	struct CCIE_t ccie;
	init_CCIE(&ccie, msg, dir, refnr);  // FIXME: is refnr == liid ???

  int ccielen = sizeof(ccie) + ccie.value.header.value.LIID.len - MAXLIIDLEN;
  int ccielen_part1 = ccielen - sizeof(ccie.value.payload);
  int ccielen_part2 = sizeof(ccie.value.payload);

	char header[300];
	snprintf(header, 300, "Content-Length: %d\r\n\r\nType: VoIP-Binary\r\nRefNr: %s\r\n", ccielen + msg->len, refnr);  // take only the actual number of characters in liid
	header[299] = 0;
	int hlen = strlen(header);

	int len = hlen + ccielen + msg->len;  // take only the actual number of characters in liid
	char *buf = pkg_malloc(len);
	if (buf == NULL) {
		LM_ERR("Can't alloc %d bytes.\n", len);
		return;
	}

	memcpy(buf, header, hlen);
	memcpy(&(buf[hlen]), &ccie, ccielen_part1);  // take only the actual number of characters in liid
	memcpy(&(buf[hlen+ccielen_part1]), &(ccie.value.payload), ccielen_part2); // take the rest of the structure
	memcpy(&(buf[hlen+ccielen]), msg->buf, msg->len);  // the payload

  if (sendto(deliver_sockfd, buf, len, 0, (struct sockaddr *) &deliver_addr, sizeof(deliver_addr)) != len) {
		LM_ERR("Can't send udp packet.\n");
	}

	pkg_free(buf);
}




void deliver(struct sip_msg *msg, int dir, number_t kennung, const str *table) {
	db_key_t columns[1];
	db_key_t keys[1];
	db_op_t opts[1];
	db_val_t values[1];
	db1_res_t *res;
	int i;
	
	columns[0] = &referenznummer_str;

	keys[0] = &kennung_str;

	opts[0] = OP_EQ;

	values[0].type = DB1_STRING;
	values[0].nul = 0;
	values[0].val.string_val = kennung;

	if (dbf.use_table(dbc, table)	< 0) {
		LM_ERR("cannot use table '%.*s'.\n", table->len, table->s);
		return;
	}

	if (dbf.query(dbc, keys, opts, values, columns, 1, 1, NULL, &res)	< 0) {
		LM_ERR("Error while querying.\n");
		return;
	}

	// deliver message for each matching database entry using the corresponding 'referenznummer'
	for(i=0; i<RES_ROW_N(res); i++) {
		if ((RES_COL_N(res) > 0) &&
				(RES_ROWS(res)[i].values[0].nul == 0)) {
			if (RES_ROWS(res)[i].values[0].type == DB1_STRING) {
				deliver_refnr(msg, dir, RES_ROWS(res)[i].values[0].val.string_val);
			}
			else {
				LM_ERR("invalid result type.\n");
			}
		}
	}
	
	dbf.free_result(dbc, res);
}




int init_db(const str *url)
{
	if (db_bind_mod(url, &dbf) < 0) {
		LM_ERR("Can't bind to database module.\n");
		return -1;
	}

	return 0;
}




int init_db_child(const str *url)
{
	dbc = dbf.init(url);
	if (dbc == NULL) {
		LM_ERR("Child can't connect to database.\n");
		return -1;
	}

	return 0;
}




void destroy_db(void)
{
	if (dbc != NULL) {
		dbf.close(dbc);
	}
}




// rebuild d-tree using database entries
// returns: <0  on failure
//          >=0 on success, indicating the number of d-tree entries
int update_from_db(const str *table)
{
	db_key_t columns[1];
	db_key_t comp_names[1];
	db_val_t comp_vals[1];
	db1_res_t *res;
	int i;
	int n = 0;
	
	columns[0] = &kennung_str;
	comp_names[0] = &comp_name_str;
	if (db_str2val(DB1_STR, &comp_vals[0], comp_val_str.s, comp_val_str.len, 0) < 0) {
		LM_ERR("failed to set required value for database query\n");
		return -1;
	}
	dbf.use_table(dbc, table);
  // just take every entry in table with 'ftap' target type. this table should contain only valid and currently active UEMs!
	if (dbf.query(dbc, comp_names, NULL, comp_vals, columns, 1, 1, NULL, &res)	< 0) {
		LM_ERR("Error while querying.\n");
		return -1;
	}

	dt_clear();

	for(i=0; i<RES_ROW_N(res); i++) {
		if ((RES_COL_N(res) > 0) &&
				(RES_ROWS(res)[i].values[0].nul == 0)) {
			if (RES_ROWS(res)[i].values[0].type == DB1_STRING) {
				dt_insert(RES_ROWS(res)[i].values[0].val.string_val);
				n++;
			}
			else {
				LM_ERR("invalid result type.\n");
			}
		}
	}
	
	dbf.free_result(dbc, res);

  return n;
}
