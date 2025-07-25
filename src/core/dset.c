/*
 * destination set
 *
 * Copyright (C) 2001-2004 FhG FOKUS
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/** Kamailio core :: destination set / branches support.
 * @file dset.c
 * @ingroup core
 * Module: @ref core
 */

#include <string.h>
#include "dprint.h"
#include "config.h"
#include "parser/parser_f.h"
#include "parser/parse_uri.h"
#include "parser/parse_param.h"
#include "parser/msg_parser.h"
#include "globals.h"
#include "ut.h"
#include "hash_func.h"
#include "error.h"
#include "dset.h"
#include "mem/mem.h"
#include "ip_addr.h"
#include "strutils.h"

#define CONTACT "Contact: "
#define CONTACT_LEN (sizeof(CONTACT) - 1)

#define CONTACT_DELIM ", "
#define CONTACT_DELIM_LEN (sizeof(CONTACT_DELIM) - 1)

#define Q_PARAM ";q="
#define Q_PARAM_LEN (sizeof(Q_PARAM) - 1)

#define ROUTE_PARAM "?Route="
#define ROUTE_PARAM_LEN (sizeof(ROUTE_PARAM) - 1)

#define FLAGS_PARAM ";flags="
#define FLAGS_PARAM_LEN (sizeof(FLAGS_PARAM) - 1)

/*
 * Where we store URIs of additional transaction branches
 * (sr_dst_max_branches - 1 : because of the default branch for r-uri, #0 in tm)
 */
static branch_t *_ksr_branches = NULL;

/* how many of them we have */
unsigned int nr_branches = 0;

/* branch iterator */
static int branch_iterator = 0;

/* used to mark ruris "consumed" when branching (1 new, 0 consumed) */
int ruri_is_new = 0;

/* The q parameter of the Request-URI */
static qvalue_t ruri_q = Q_UNSPECIFIED;

/* Branch flags of the Request-URI */
static flag_t ruri_bflags;

/* alias parameter for contact uri/r-uri with surrounding semicolon or =
 * - used for set_contact_alias()/handle_ruri_alias() */
str _ksr_contact_alias = str_init("alias=");
str _ksr_contact_salias = str_init(";alias=");

/**
 *
 */
int init_dst_set(void)
{
	if(sr_dst_max_branches <= 0 || sr_dst_max_branches >= MAX_BRANCHES_LIMIT) {
		LM_ERR("invalid value for max branches parameter: %u, maximum value: "
			   "%u\n",
				sr_dst_max_branches, MAX_BRANCHES_LIMIT);
		return -1;
	}
	/* sr_dst_max_branches - 1 : because of the default branch for r-uri, #0 in tm */
	_ksr_branches = (branch_t *)pkg_malloc(
			(sr_dst_max_branches - 1) * sizeof(branch_t));
	if(_ksr_branches == NULL) {
		PKG_MEM_ERROR;
		return -1;
	}
	memset(_ksr_branches, 0, (sr_dst_max_branches - 1) * sizeof(branch_t));
	return 0;
}

/**
 *
 */
unsigned int get_nr_branches(void)
{
	return nr_branches;
}

/*! \brief
 * Return pointer to branch[idx] structure
 * @param idx - branch index
 *
 * @return  pointer to branch or NULL if invalid branch
 */
branch_t *get_sip_branch(int idx)
{
	if(nr_branches == 0)
		return NULL;
	if(idx < 0) {
		if((int)nr_branches + idx >= 0)
			return &_ksr_branches[nr_branches + idx];
		return NULL;
	}
	if(idx < nr_branches)
		return &_ksr_branches[idx];
	return 0;
}

/**
 *
 */
int get_all_sip_branches(branch_t **vbranches, unsigned int *nbranches)
{
	if(nr_branches == 0) {
		*vbranches = NULL;
		*nbranches = 0;
		return 0;
	}

	*vbranches = (branch_t *)pkg_malloc(nr_branches * sizeof(branch_t));
	if(*vbranches == NULL) {
		PKG_MEM_ERROR;
		return -1;
	}
	memcpy(*vbranches, _ksr_branches, nr_branches * sizeof(branch_t));
	*nbranches = nr_branches;

	return 0;
}

/**
 *
 */
int set_all_sip_branches(branch_t *vbranches, unsigned int nbranches)
{
	if(nbranches == 0) {
		nr_branches = 0;
		return 0;
	}

	memcpy(_ksr_branches, vbranches, nbranches * sizeof(branch_t));
	nr_branches = nbranches;

	return 0;
}

/*! \brief
 * Drop branch[idx]
 * @param idx - branch index
 *
 * @return  0 on success, -1 on error
 */
int drop_sip_branch(int idx)
{
	if(nr_branches == 0 || idx >= nr_branches)
		return 0;
	if(idx < 0 && (int)nr_branches + idx < 0)
		return 0;
	if(idx < 0)
		idx += nr_branches;
	/* last branch */
	if(idx == nr_branches - 1) {
		nr_branches--;
		return 0;
	}
	/* shift back one position */
	for(; idx < nr_branches - 1; idx++)
		memcpy(&_ksr_branches[idx], &_ksr_branches[idx + 1], sizeof(branch_t));
	nr_branches--;
	return 0;
}

static inline flag_t *get_bflags_ptr(unsigned int branch)
{
	if(branch == 0)
		return &ruri_bflags;
	if(branch - 1 < nr_branches)
		return &_ksr_branches[branch - 1].flags;
	return NULL;
}


int setbflag(unsigned int branch, flag_t flag)
{
	flag_t *flags;

	if((flags = get_bflags_ptr(branch)) == NULL)
		return -1;
	(*flags) |= 1 << flag;
	return 1;
}


int isbflagset(unsigned int branch, flag_t flag)
{
	flag_t *flags;

	if((flags = get_bflags_ptr(branch)) == NULL)
		return -1;
	return ((*flags) & (1 << flag)) ? 1 : -1;
}


int resetbflag(unsigned int branch, flag_t flag)
{
	flag_t *flags;

	if((flags = get_bflags_ptr(branch)) == NULL)
		return -1;
	(*flags) &= ~(1 << flag);
	return 1;
}


int getbflagsval(unsigned int branch, flag_t *res)
{
	flag_t *flags;
	if(res == NULL)
		return -1;
	if((flags = get_bflags_ptr(branch)) == NULL)
		return -1;
	*res = *flags;
	return 1;
}


int setbflagsval(unsigned int branch, flag_t val)
{
	flag_t *flags;
	if((flags = get_bflags_ptr(branch)) == NULL)
		return -1;
	*flags = val;
	return 1;
}


/*
 * Initialize the branch iterator, the next
 * call to next_branch will return the first
 * contact from the dset array
 */
void init_branch_iterator(void)
{
	branch_iterator = 0;
}

/**
 * return the value of current branch iterator
 */
int get_branch_iterator(void)
{
	return branch_iterator;
}

/**
 * set the value of current branch interator
 */
void set_branch_iterator(int n)
{
	branch_iterator = n;
}


/** \brief Get a branch from the destination set
 * \return Return the 'i' branch from the dset
 * array, 0 is returned if there are no
 * more branches
 */
char *get_branch(unsigned int i, int *len, qvalue_t *q, str *dst_uri, str *path,
		unsigned int *flags, struct socket_info **force_socket, str *ruid,
		str *instance, str *location_ua)
{
	if(i < nr_branches) {
		*len = _ksr_branches[i].len;
		*q = _ksr_branches[i].q;
		if(dst_uri) {
			dst_uri->len = _ksr_branches[i].dst_uri_len;
			dst_uri->s = (dst_uri->len) ? _ksr_branches[i].dst_uri : 0;
		}
		if(path) {
			path->len = _ksr_branches[i].path_len;
			path->s = (path->len) ? _ksr_branches[i].path : 0;
		}
		if(force_socket)
			*force_socket = _ksr_branches[i].force_send_socket;
		if(flags)
			*flags = _ksr_branches[i].flags;
		if(ruid) {
			ruid->len = _ksr_branches[i].ruid_len;
			ruid->s = (ruid->len) ? _ksr_branches[i].ruid : 0;
		}
		if(instance) {
			instance->len = _ksr_branches[i].instance_len;
			instance->s = (instance->len) ? _ksr_branches[i].instance : 0;
		}
		if(location_ua) {
			location_ua->len = _ksr_branches[i].location_ua_len;
			location_ua->s =
					(location_ua->len) ? _ksr_branches[i].location_ua : 0;
		}
		return _ksr_branches[i].uri;
	} else {
		*len = 0;
		*q = Q_UNSPECIFIED;
		if(dst_uri) {
			dst_uri->s = 0;
			dst_uri->len = 0;
		}
		if(path) {
			path->s = 0;
			path->len = 0;
		}
		if(force_socket)
			*force_socket = 0;
		if(flags)
			*flags = 0;
		if(ruid) {
			ruid->s = 0;
			ruid->len = 0;
		}
		if(instance) {
			instance->s = 0;
			instance->len = 0;
		}
		if(location_ua) {
			location_ua->s = 0;
			location_ua->len = 0;
		}
		return 0;
	}
}


/** Return the next branch from the dset array.
 * 0 is returned if there are no more branches
 */
char *next_branch(int *len, qvalue_t *q, str *dst_uri, str *path,
		unsigned int *flags, struct socket_info **force_socket, str *ruid,
		str *instance, str *location_ua)
{
	char *ret;

	ret = get_branch(branch_iterator, len, q, dst_uri, path, flags,
			force_socket, ruid, instance, location_ua);
	if(likely(ret))
		branch_iterator++;
	return ret;
}

/**
 * Link branch attributes in the data structure
 * - return: -1 (<0) on error; 0 - on no valid branch; 1 - on a valid branch
 */
int get_branch_data(unsigned int i, branch_data_t *vbranch)
{
	if(vbranch == NULL) {
		return -1;
	}
	memset(vbranch, 0, sizeof(branch_data_t));

	if(i < nr_branches) {
		vbranch->uri.s = _ksr_branches[i].uri;
		vbranch->uri.len = _ksr_branches[i].len;
		vbranch->q = _ksr_branches[i].q;
		if(_ksr_branches[i].dst_uri_len > 0) {
			vbranch->dst_uri.len = _ksr_branches[i].dst_uri_len;
			vbranch->dst_uri.s = _ksr_branches[i].dst_uri;
		}
		if(_ksr_branches[i].path_len > 0) {
			vbranch->path.len = _ksr_branches[i].path_len;
			vbranch->path.s = _ksr_branches[i].path;
		}
		vbranch->force_socket = _ksr_branches[i].force_send_socket;
		vbranch->flags = _ksr_branches[i].flags;
		if(_ksr_branches[i].ruid_len > 0) {
			vbranch->ruid.len = _ksr_branches[i].ruid_len;
			vbranch->ruid.s = _ksr_branches[i].ruid;
		}
		if(_ksr_branches[i].instance_len > 0) {
			vbranch->instance.len = _ksr_branches[i].instance_len;
			vbranch->instance.s = _ksr_branches[i].instance;
		}
		if(_ksr_branches[i].location_ua_len > 0) {
			vbranch->location_ua.len = _ksr_branches[i].location_ua_len;
			vbranch->location_ua.s = _ksr_branches[i].location_ua;
		}
		vbranch->otcpid = _ksr_branches[i].otcpid;
		return 1;
	} else {
		vbranch->q = Q_UNSPECIFIED;
		return 0;
	}
}

/**
 * Link branch attributes in the data structure and advance the iterator on
 * return of a valid branch
 * - return: -1 (<0) on error; 0 - on no valid branch; 1 - on a valid branch
 */
int next_branch_data(branch_data_t *vbranch)
{
	int ret;
	ret = get_branch_data(branch_iterator, vbranch);
	if(ret <= 0) {
		return ret;
	}
	branch_iterator++;
	return ret;
}

/*
 * Empty the dset array
 */
void clear_branches(void)
{
	nr_branches = 0;
	ruri_q = Q_UNSPECIFIED;
	ruri_bflags = 0;
	ruri_mark_consumed();
}


/**  Add a new branch to the current destination set.
 * @param msg sip message, used for getting the uri if not specified (0).
 * @param uri uri, can be 0 (in which case the uri is taken from msg)
 * @param dst_uri destination uri, can be 0.
 * @param path path vector (passed in a string), can be 0.
 * @param q  q value.
 * @param flags per branch flags.
 * @param force_socket socket that should be used when sending.
 * @param instance sip instance contact header param value
 * @param reg_id reg-id contact header param value
 * @param ruid ruid value from usrloc
 * @param location_ua location user agent
 *
 * @return  <0 (-1) on failure, 1 on success (script convention).
 */
int append_branch(struct sip_msg *msg, str *uri, str *dst_uri, str *path,
		qvalue_t q, unsigned int flags, struct socket_info *force_socket,
		str *instance, unsigned int reg_id, str *ruid, str *location_ua)
{
	str luri;

	/* if we have already set up the maximum number
	 * of branches, don't try new ones
	 */
	if(unlikely(nr_branches == sr_dst_max_branches - 1)) {
		LM_ERR("max nr of branches exceeded\n");
		ser_error = E_TOO_MANY_BRANCHES;
		return -1;
	}

	/* if not parameterized, take current uri */
	if(uri == 0 || uri->len == 0 || uri->s == 0) {
		if(msg == NULL) {
			LM_ERR("no new uri and no msg to take r-uri\n");
			ser_error = E_INVALID_PARAMS;
			return -1;
		}
		if(msg->new_uri.s)
			luri = msg->new_uri;
		else
			luri = msg->first_line.u.request.uri;
	} else {
		luri = *uri;
	}

	if(unlikely(luri.len > MAX_URI_SIZE - 1)) {
		LM_ERR("too long uri: %.*s\n", luri.len, luri.s);
		return -1;
	}

	/* copy the dst_uri */
	if(dst_uri && dst_uri->len && dst_uri->s) {
		if(unlikely(dst_uri->len > MAX_URI_SIZE - 1)) {
			LM_ERR("too long dst_uri: %.*s\n", dst_uri->len, dst_uri->s);
			return -1;
		}
		memcpy(_ksr_branches[nr_branches].dst_uri, dst_uri->s, dst_uri->len);
		_ksr_branches[nr_branches].dst_uri[dst_uri->len] = 0;
		_ksr_branches[nr_branches].dst_uri_len = dst_uri->len;
	} else {
		_ksr_branches[nr_branches].dst_uri[0] = '\0';
		_ksr_branches[nr_branches].dst_uri_len = 0;
	}

	/* copy the path string */
	if(unlikely(path && path->len && path->s)) {
		if(unlikely(path->len > MAX_PATH_SIZE - 1)) {
			LM_ERR("too long path: %.*s\n", path->len, path->s);
			return -1;
		}
		memcpy(_ksr_branches[nr_branches].path, path->s, path->len);
		_ksr_branches[nr_branches].path[path->len] = 0;
		_ksr_branches[nr_branches].path_len = path->len;
	} else {
		_ksr_branches[nr_branches].path[0] = '\0';
		_ksr_branches[nr_branches].path_len = 0;
	}

	/* copy the ruri */
	memcpy(_ksr_branches[nr_branches].uri, luri.s, luri.len);
	_ksr_branches[nr_branches].uri[luri.len] = 0;
	_ksr_branches[nr_branches].len = luri.len;
	_ksr_branches[nr_branches].q = q;

	_ksr_branches[nr_branches].force_send_socket = force_socket;
	_ksr_branches[nr_branches].flags = flags;

	/* copy instance string */
	if(unlikely(instance && instance->len && instance->s)) {
		if(unlikely(instance->len > MAX_INSTANCE_SIZE - 1)) {
			LM_ERR("too long instance: %.*s\n", instance->len, instance->s);
			return -1;
		}
		memcpy(_ksr_branches[nr_branches].instance, instance->s, instance->len);
		_ksr_branches[nr_branches].instance[instance->len] = 0;
		_ksr_branches[nr_branches].instance_len = instance->len;
	} else {
		_ksr_branches[nr_branches].instance[0] = '\0';
		_ksr_branches[nr_branches].instance_len = 0;
	}

	/* copy reg_id */
	_ksr_branches[nr_branches].reg_id = reg_id;

	/* copy ruid string */
	if(unlikely(ruid && ruid->len && ruid->s)) {
		if(unlikely(ruid->len > MAX_RUID_SIZE - 1)) {
			LM_ERR("too long ruid: %.*s\n", ruid->len, ruid->s);
			return -1;
		}
		memcpy(_ksr_branches[nr_branches].ruid, ruid->s, ruid->len);
		_ksr_branches[nr_branches].ruid[ruid->len] = 0;
		_ksr_branches[nr_branches].ruid_len = ruid->len;
	} else {
		_ksr_branches[nr_branches].ruid[0] = '\0';
		_ksr_branches[nr_branches].ruid_len = 0;
	}

	if(unlikely(location_ua && location_ua->len && location_ua->s)) {
		if(unlikely(location_ua->len > MAX_UA_SIZE)) {
			LM_ERR("too long location_ua: %.*s\n", location_ua->len,
					location_ua->s);
			return -1;
		}
		memcpy(_ksr_branches[nr_branches].location_ua, location_ua->s,
				location_ua->len);
		_ksr_branches[nr_branches].location_ua[location_ua->len] = 0;
		_ksr_branches[nr_branches].location_ua_len = location_ua->len;
	} else {
		_ksr_branches[nr_branches].location_ua[0] = '\0';
		_ksr_branches[nr_branches].location_ua_len = 0;
	}

	nr_branches++;
	return 1;
}


/**  Push a new branch to the current destination set.
 * @param msg sip message, used for getting the uri if not specified (0).
 * @param uri uri, can be 0 (in which case the uri is taken from msg)
 * @param dst_uri destination uri, can be 0.
 * @param path path vector (passed in a string), can be 0.
 * @param q  q value.
 * @param flags per branch flags.
 * @param force_socket socket that should be used when sending.
 * @param instance sip instance contact header param value
 * @param reg_id reg-id contact header param value
 * @param ruid ruid value from usrloc
 * @param location_ua location user agent
 *
 * @return NULL on failure, new branch pointer on success.
 */
branch_t *ksr_push_branch(struct sip_msg *msg, str *uri, str *dst_uri,
		str *path, qvalue_t q, unsigned int flags,
		struct socket_info *force_socket, str *instance, unsigned int reg_id,
		str *ruid, str *location_ua)
{
	if(append_branch(msg, uri, dst_uri, path, q, flags, force_socket, instance,
			   reg_id, ruid, location_ua)
			< 0) {
		return NULL;
	}
	return &_ksr_branches[nr_branches - 1];
}

/*! \brief
 * Combines the given elements into a Contact header field
 * dest = target buffer, will be updated to new position after the printed contact
 * uri, q = contact elements
 * end = end of target buffer
 * Returns 0 on success or -1 on error (buffer is too short)
 */
static int print_contact_str(char **dest, str *uri, qvalue_t q, str *path,
		unsigned int flags, char *end, int options)
{
	char *p = *dest;
	str buf;

	/* uri */
	if(p + uri->len + 2 > end) {
		return -1;
	}
	*p++ = '<';
	memcpy(p, uri->s, uri->len);
	p += uri->len;

	/* uri parameters */
	/* path vector as route header parameter */
	if((options & DS_PATH) && path->len > 0) {
		if(p + ROUTE_PARAM_LEN + path->len > end) {
			return -1;
		}
		memcpy(p, ROUTE_PARAM, ROUTE_PARAM_LEN);
		p += ROUTE_PARAM_LEN;
		/* copy escaped path into dest */
		buf.s = p;
		buf.len = end - p;
		if(escape_param(path, &buf) < 0) {
			return -1;
		}
		p += buf.len;
	}

	/* end of uri parameters */
	*p++ = '>';

	/* header parameters */
	/* q value */
	if(q != Q_UNSPECIFIED) {
		buf.s = q2str(q, (unsigned int *)&buf.len);
		if(p + Q_PARAM_LEN + buf.len > end) {
			return -1;
		}
		memcpy(p, Q_PARAM, Q_PARAM_LEN);
		p += Q_PARAM_LEN;
		memcpy(p, buf.s, buf.len);
		p += buf.len;
	}

	/* branch flags (not SIP standard conformant) */
	if(options & DS_FLAGS) {
		buf.s = int2str(flags, &buf.len);
		if(p + FLAGS_PARAM_LEN + buf.len > end) {
			return -1;
		}
		memcpy(p, FLAGS_PARAM, FLAGS_PARAM_LEN);
		p += FLAGS_PARAM_LEN;
		memcpy(p, buf.s, buf.len);
		p += buf.len;
	}

	*dest = p;
	return 0;
}


/*
 * Create a Contact header field from the dset
 * array
 */
char *print_dset(struct sip_msg *msg, int *len, int options)
{
	int cnt = 0;
	qvalue_t q;
	str uri, path;
	unsigned int flags;
	char *p;
	int crt_branch;
	static char dset[MAX_REDIRECTION_LEN];
	char *end = dset + MAX_REDIRECTION_LEN;

	/* backup current branch index to restore it later */
	crt_branch = get_branch_iterator();

	/* contact header name */
	if(CONTACT_LEN + CRLF_LEN + 1 > MAX_REDIRECTION_LEN) {
		goto memfail;
	}
	memcpy(dset, CONTACT, CONTACT_LEN);
	p = dset + CONTACT_LEN;

	/* current uri */
	if(msg->new_uri.s) {
		if(print_contact_str(&p, &msg->new_uri, ruri_q, &msg->path_vec,
				   ruri_bflags, end, options)
				< 0) {
			goto memfail;
		}
		cnt++;
	}

	/* branches */
	init_branch_iterator();
	while((uri.s = next_branch(&uri.len, &q, 0, &path, &flags, 0, 0, 0, 0))) {
		if(cnt > 0) {
			if(p + CONTACT_DELIM_LEN > end) {
				goto memfail;
			}
			memcpy(p, CONTACT_DELIM, CONTACT_DELIM_LEN);
			p += CONTACT_DELIM_LEN;
		}

		if(print_contact_str(&p, &uri, q, &path, flags, end, options) < 0) {
			goto memfail;
		}

		cnt++;
	}

	if(cnt == 0) {
		LM_INFO("no new r-uri or branches\n");
		goto notfound;
	}

	if(p + CRLF_LEN + 1 > end) {
		goto memfail;
	}
	memcpy(p, CRLF " ", CRLF_LEN + 1);
	*len = p - dset + CRLF_LEN;
	set_branch_iterator(crt_branch);
	return dset;

memfail:
	LM_ERR("redirection buffer length exceed\n");
notfound:
	*len = 0;
	set_branch_iterator(crt_branch);
	return 0;
}


/*
 * Sets the q parameter of the Request-URI
 */
void set_ruri_q(qvalue_t q)
{
	ruri_q = q;
}


/*
 * Return the q value of the Request-URI
 */
qvalue_t get_ruri_q(void)
{
	return ruri_q;
}


/*
 * Rewrite Request-URI
 */
int rewrite_uri(struct sip_msg *_m, str *_s)
{
	char *buf = NULL;

	if(_m->new_uri.s == NULL || _m->new_uri.len < _s->len) {
		buf = (char *)pkg_malloc(_s->len + 1);
		if(!buf) {
			PKG_MEM_ERROR;
			return -1;
		}
	}
	if(buf != NULL) {
		if(_m->new_uri.s)
			pkg_free(_m->new_uri.s);
	} else {
		buf = _m->new_uri.s;
	}

	memcpy(buf, _s->s, _s->len);
	buf[_s->len] = '\0';

	_m->parsed_uri_ok = 0;

	_m->new_uri.s = buf;
	_m->new_uri.len = _s->len;
	/* mark ruri as new and available for forking */
	ruri_mark_new();

	return 1;
}

/*
 * Reset Request-URI
 */
void reset_uri(sip_msg_t *msg)
{
	if(msg->new_uri.s == NULL) {
		return;
	}
	pkg_free(msg->new_uri.s);
	msg->new_uri.len = 0;
	msg->new_uri.s = 0;
	msg->parsed_uri_ok = 0;
	ruri_mark_new();
	return;
}

/**
 * return src ip, port and proto as a SIP uri or proxy address
 * - value stored in a static buffer
 * - mode=0 return uri, mode=1 return proxy address
 */
int msg_get_src_addr(sip_msg_t *msg, str *uri, int mode)
{
	static char buf[80];
	char *p;
	str ip, port;
	int len;
	str proto;

	if(msg == NULL || uri == NULL) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	ip.s = ip_addr2a(&msg->rcv.src_ip);
	ip.len = strlen(ip.s);

	port.s = int2str(msg->rcv.src_port, &port.len);

	switch(msg->rcv.proto) {
		case PROTO_NONE:
		case PROTO_UDP:
			if(mode == 0) {
				proto.s =
						0; /* Do not add transport parameter, UDP is default */
				proto.len = 0;
			} else {
				proto.s = "udp";
				proto.len = 3;
			}
			break;

		case PROTO_TCP:
			proto.s = "tcp";
			proto.len = 3;
			break;

		case PROTO_TLS:
			proto.s = "tls";
			proto.len = 3;
			break;

		case PROTO_SCTP:
			proto.s = "sctp";
			proto.len = 4;
			break;

		case PROTO_WS:
		case PROTO_WSS:
			proto.s = "ws";
			proto.len = 2;
			break;

		default:
			LM_ERR("unknown transport protocol\n");
			return -1;
	}

	len = ip.len + 2 * (msg->rcv.src_ip.af == AF_INET6) + 1 + port.len;
	if(mode == 0) {
		len += 4;
		if(proto.s) {
			len += TRANSPORT_PARAM_LEN;
			len += proto.len;
		}
	} else {
		len += proto.len + 1;
	}

	if(len > 79) {
		LM_ERR("buffer too small\n");
		return -1;
	}

	p = buf;
	if(mode == 0) {
		memcpy(p, "sip:", 4);
		p += 4;
	} else {
		memcpy(p, proto.s, proto.len);
		p += proto.len;
		*p++ = ':';
	}

	if(msg->rcv.src_ip.af == AF_INET6)
		*p++ = '[';
	memcpy(p, ip.s, ip.len);
	p += ip.len;
	if(msg->rcv.src_ip.af == AF_INET6)
		*p++ = ']';

	*p++ = ':';

	memcpy(p, port.s, port.len);
	p += port.len;

	if(mode == 0 && proto.s) {
		memcpy(p, TRANSPORT_PARAM, TRANSPORT_PARAM_LEN);
		p += TRANSPORT_PARAM_LEN;

		memcpy(p, proto.s, proto.len);
	}

	uri->s = buf;
	uri->len = len;
	uri->s[uri->len] = '\0';

	return 0;
}


/**
 * set name of alias parameter used for contact/r-uri src/rcv address encoding
 */
int ksr_contact_alias_set_name(str *aname)
{
	_ksr_contact_salias.s = (char *)pkg_malloc(aname->len + 3);
	if(_ksr_contact_salias.s == NULL) {
		PKG_MEM_ERROR;
		return -1;
	}
	_ksr_contact_salias.s[0] = ';';
	memcpy(_ksr_contact_salias.s + 1, aname->s, aname->len);
	_ksr_contact_salias.s[aname->len + 1] = '=';
	_ksr_contact_salias.s[aname->len + 2] = '\0';
	_ksr_contact_salias.len = aname->len + 2;
	_ksr_contact_alias.s = _ksr_contact_salias.s + 1;
	_ksr_contact_alias.len = _ksr_contact_salias.len - 1;
	LM_DBG("new contact alias parameter expression [%.*s]\n",
			_ksr_contact_salias.len, _ksr_contact_salias.s);

	return 0;
}

/**
 * add alias parameter with encoding of source address
 * - nuri->s must point to a buffer of nuri->len size
 */
int uri_add_rcv_alias(sip_msg_t *msg, str *uri, str *nuri)
{
	char *p;
	str ip, port;
	int len;

	if(msg == NULL || uri == NULL || nuri == NULL) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	ip.s = ip_addr2a(&msg->rcv.src_ip);
	ip.len = strlen(ip.s);

	port.s = int2str(msg->rcv.src_port, &port.len);

	/*uri;alias=[ip]~port~proto*/
	len = uri->len + _ksr_contact_salias.len + ip.len + port.len + 6;
	if(len >= nuri->len) {
		LM_ERR("not enough space - new uri len: %d (buf size: %d)\n", len,
				nuri->len);
		return -1;
	}
	p = nuri->s;
	memcpy(p, uri->s, uri->len);
	p += uri->len;
	memcpy(p, _ksr_contact_salias.s, _ksr_contact_salias.len);
	p += _ksr_contact_salias.len;
	if(msg->rcv.src_ip.af == AF_INET6)
		*p++ = '[';
	memcpy(p, ip.s, ip.len);
	p += ip.len;
	if(msg->rcv.src_ip.af == AF_INET6)
		*p++ = ']';
	*p++ = '~';
	memcpy(p, port.s, port.len);
	p += port.len;
	*p++ = '~';
	*p++ = msg->rcv.proto + '0';
	nuri->len = p - nuri->s;
	nuri->s[nuri->len] = '\0';

	LM_DBG("encoded <%.*s> => [%.*s]\n", uri->len, uri->s, nuri->len, nuri->s);
	return 0;
}

/**
 * restore from alias parameter with encoding of source address
 * - nuri->s must point to a buffer of nuri->len size
 * - suri->s must point to a buffer of suri->len size
 */
int uri_restore_rcv_alias(str *uri, str *nuri, str *suri)
{
	char *p;
	str skip;
	str ip, port, sproto;
	int proto;

	if(uri == NULL || nuri == NULL || suri == NULL) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	/* sip:x;alias=1.1.1.1~0~0 */
	if(uri->len < _ksr_contact_salias.len + 16) {
		/* no alias possible */
		return -2;
	}
	p = uri->s + uri->len - _ksr_contact_salias.len - 11;
	skip.s = 0;
	while(p > uri->s + 5) {
		if(strncmp(p, _ksr_contact_salias.s, _ksr_contact_salias.len) == 0) {
			skip.s = p;
			break;
		}
		p--;
	}
	if(skip.s == 0) {
		/* alias parameter not found */
		return -2;
	}
	p += _ksr_contact_salias.len;
	ip.s = p;
	p = (char *)memchr(ip.s, '~', (size_t)(uri->s + uri->len - ip.s));
	if(p == NULL) {
		/* proper alias parameter not found */
		return -2;
	}
	ip.len = p - ip.s;
	p++;
	if(p >= uri->s + uri->len) {
		/* proper alias parameter not found */
		return -2;
	}
	port.s = p;
	p = (char *)memchr(port.s, '~', (size_t)(uri->s + uri->len - port.s));
	if(p == NULL) {
		/* proper alias parameter not found */
		return -2;
	}
	port.len = p - port.s;
	p++;
	if(p >= uri->s + uri->len) {
		/* proper alias parameter not found */
		return -2;
	}
	proto = (int)(*p - '0');
	p++;

	if(p != uri->s + uri->len && *p != ';') {
		/* proper alias parameter not found */
		return -2;
	}
	skip.len = (int)(p - skip.s);

	if(suri->len <= 4 + ip.len + 1 + port.len + 11 /*;transport=*/ + 4) {
		LM_ERR("address buffer too small\n");
		return -1;
	}
	if(nuri->len <= uri->len - skip.len) {
		LM_ERR("uri buffer too small\n");
		return -1;
	}

	p = nuri->s;
	memcpy(p, uri->s, (size_t)(skip.s - uri->s));
	p += skip.s - uri->s;
	memcpy(p, skip.s + skip.len,
			(size_t)(uri->s + uri->len - skip.s - skip.len));
	p += uri->s + uri->len - skip.s - skip.len;
	nuri->len = p - nuri->s;

	p = suri->s;
	memcpy(p, "sip:", 4);
	p += 4;
	memcpy(p, ip.s, ip.len);
	p += ip.len;
	*p++ = ':';
	memcpy(p, port.s, port.len);
	p += port.len;
	proto_type_to_str((unsigned short)proto, &sproto);
	if(sproto.len > 0 && proto != PROTO_UDP) {
		memcpy(p, ";transport=", 11);
		p += 11;
		memcpy(p, sproto.s, sproto.len);
		p += sproto.len;
	}
	suri->len = p - suri->s;

	LM_DBG("decoded <%.*s> => [%.*s] [%.*s]\n", uri->len, uri->s, nuri->len,
			nuri->s, suri->len, suri->s);

	return 0;
}


/**
 * trim alias parameter from uri
 * - nuri->s must point to a buffer of nuri->len size
 */
int uri_trim_rcv_alias(str *uri, str *nuri)
{
	char *p;
	str skip;
	str ip, port;

	if(uri == NULL || nuri == NULL) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	/* sip:x;alias=1.1.1.1~0~0 */
	if(uri->len < _ksr_contact_salias.len + 16) {
		/* no alias possible */
		return 0;
	}
	p = uri->s + uri->len - _ksr_contact_salias.len - 11;
	skip.s = 0;
	while(p > uri->s + 5) {
		if(strncmp(p, _ksr_contact_salias.s, _ksr_contact_salias.len) == 0) {
			skip.s = p;
			break;
		}
		p--;
	}
	if(skip.s == 0) {
		/* alias parameter not found */
		return 0;
	}
	p += _ksr_contact_salias.len;
	ip.s = p;
	p = (char *)memchr(ip.s, '~', (size_t)(uri->s + uri->len - ip.s));
	if(p == NULL) {
		/* proper alias parameter not found */
		return 0;
	}
	ip.len = p - ip.s;
	p++;
	if(p >= uri->s + uri->len) {
		/* proper alias parameter not found */
		return 0;
	}
	port.s = p;
	p = (char *)memchr(port.s, '~', (size_t)(uri->s + uri->len - port.s));
	if(p == NULL) {
		/* proper alias parameter not found */
		return 0;
	}
	port.len = p - port.s;
	p++;
	if(p >= uri->s + uri->len) {
		/* proper alias parameter not found */
		return 0;
	}
	/* jump over proto */
	p++;

	if(p != uri->s + uri->len && *p != ';') {
		/* proper alias parameter not found */
		return 0;
	}
	skip.len = (int)(p - skip.s);
	if(nuri->len <= uri->len - skip.len) {
		LM_ERR("uri buffer too small\n");
		return -1;
	}

	p = nuri->s;
	memcpy(p, uri->s, (size_t)(skip.s - uri->s));
	p += skip.s - uri->s;
	memcpy(p, skip.s + skip.len,
			(size_t)(uri->s + uri->len - skip.s - skip.len));
	p += uri->s + uri->len - skip.s - skip.len;
	nuri->len = p - nuri->s;

	LM_DBG("decoded <%.*s> => [%.*s]\n", uri->len, uri->s, nuri->len, nuri->s);
	return 1;
}

/**
 * encode sip uri to uri alias parameter format
 * - param: iuri - input sip uri
 * - param: ualias - output uri alias value in format: address~port~proto
 *   * ualias->s must point to a buffer of size ualias->len, at least iuri->len
 *   * ualias->len is adjusted to the output value length
 * - return 0 on success, negative on error
 */
int ksr_uri_alias_encode(str *iuri, str *ualias)
{
	sip_uri_t puri;
	char *p;

	if(parse_uri(iuri->s, iuri->len, &puri) < 0) {
		LM_ERR("failed to parse uri [%.*s]\n", iuri->len, iuri->s);
		return -1;
	}

	/*host~port~proto*/
	if(puri.host.len + 16 >= ualias->len) {
		LM_ERR("not enough space to build uri alias - buf size: %d\n",
				ualias->len);
		return -1;
	}
	p = ualias->s;
	memcpy(p, puri.host.s, puri.host.len);
	p += puri.host.len;
	*p++ = '~';
	if(puri.port.len > 0) {
		memcpy(p, puri.port.s, puri.port.len);
		p += puri.port.len;
	} else {
		if(puri.proto == PROTO_TLS || puri.proto == PROTO_WSS) {
			memcpy(p, "5061", 4);
		} else {
			memcpy(p, "5060", 4);
		}
		p += 4;
	}
	*p++ = '~';
	*p++ = ((puri.proto) ? puri.proto : 1) + '0';
	ualias->len = p - ualias->s;
	ualias->s[ualias->len] = '\0';

	LM_DBG("encoded <%.*s> => [%.*s]\n", iuri->len, iuri->s, ualias->len,
			ualias->s);

	return 0;
}

/**
 * decode uri alias parameter to a sip uri
 * - param: ualias - uri alias value in format: address~port~proto
 * - param: ouri - output uri - ouri->s must point to a buffer of size ouri->len
 *   * ouri->len is adjusted to the output value length
 * - return 0 on success, negative on error
 */
int ksr_uri_alias_decode(str *ualias, str *ouri)
{
	int n;
	char *p;
	int nproto;
	str sproto;

	/* 24 => sip:...;transport=sctp */
	if(ualias->len + 24 >= ouri->len) {
		LM_ERR("received uri alias is too long: %d\n", ualias->len);
		return -1;
	}

	/* received=ip~port~proto */
	memcpy(ouri->s, "sip:", 4);
	memcpy(ouri->s + 4, ualias->s, ualias->len);
	ouri->s[4 + ualias->len] = '\0';
	p = ouri->s + 4;
	n = 0;
	while(*p != '\0') {
		if(*p == '~') {
			n++;
			if(n == 1) {
				/* port */
				*p = ':';
			} else if(n == 2) {
				/* proto */
				*p = ';';
				p++;
				if(*p == '\0') {
					LM_ERR("invalid received format\n");
					goto error;
				}
				nproto = *p - '0';
				if(nproto == PROTO_NONE) {
					nproto = PROTO_UDP;
				}
				if(nproto != PROTO_UDP) {
					proto_type_to_str(nproto, &sproto);
					if(sproto.len == 0) {
						LM_ERR("unknown proto in received param\n");
						goto error;
					}
					memcpy(p, "transport=", 10);
					p += 10;
					memcpy(p, sproto.s, sproto.len);
					p += sproto.len;
				} else {
					/* go back one byte to overwrite ';' */
					p--;
				}
				ouri->len = (int)(p - ouri->s);
				ouri->s[ouri->len] = '\0';
				break;
			} else {
				LM_ERR("invalid number of separators (%d)\n", n);
				goto error;
			}
		}
		p++;
	}
	return 0;

error:
	return -1;
}

/**
 * remove param from ouri, storing in nuri
 * - nuri->len has to be set to the size of nuri->s buffer
 */
int ksr_uri_remove_param(str *ouri, str *pname, str *nuri)
{
	str t;
	str pstart;
	sip_uri_t puri;
	param_hooks_t hooks;
	param_t *params, *pit;

	if(nuri->len < ouri->len + 1) {
		LM_ERR("output buffer too small (%d / %d)\n", nuri->len, ouri->len);
		return -1;
	}
	if(parse_uri(ouri->s, ouri->len, &puri) < 0) {
		LM_ERR("failed to parse uri [%.*s]\n", ouri->len, ouri->s);
		return -1;
	}
	if(puri.sip_params.len > 0) {
		t = puri.sip_params;
	} else if(puri.params.len > 0) {
		t = puri.params;
	} else {
		LM_DBG("no uri params [%.*s]\n", ouri->len, ouri->s);
		memcpy(nuri->s, ouri->s, ouri->len);
		nuri->len = ouri->len;
		nuri->s[nuri->len] = 0;
		return 0;
	}

	if(parse_params(&t, CLASS_ANY, &hooks, &params) < 0) {
		LM_ERR("ruri parameter parsing failed\n");
		return -1;
	}

	for(pit = params; pit; pit = pit->next) {
		if((pit->name.len == pname->len)
				&& (strncasecmp(pit->name.s, pname->s, pname->len) == 0)) {
			break;
		}
	}
	if(pit == NULL) {
		LM_DBG("uri param [%.*s] not found\n", pname->len, pname->s);
		free_params(params);
		memcpy(nuri->s, ouri->s, ouri->len);
		nuri->len = ouri->len;
		nuri->s[nuri->len] = 0;
		return 0;
	}

	pstart.s = pit->name.s;
	while(pstart.s > ouri->s && *pstart.s != ';') {
		pstart.s--;
	}
	memcpy(nuri->s, ouri->s, pstart.s - ouri->s);
	nuri->len = pstart.s - ouri->s;

	if(pit->body.len > 0) {
		if(pit->body.s + pit->body.len < ouri->s + ouri->len) {
			memcpy(nuri->s + nuri->len, pit->body.s + pit->body.len,
					ouri->s + ouri->len - pit->body.s - pit->body.len);
			nuri->len += ouri->s + ouri->len - pit->body.s - pit->body.len;
		}
	} else {
		if(pit->name.s + pit->name.len < ouri->s + ouri->len) {
			memcpy(nuri->s + nuri->len, pit->name.s + pit->name.len,
					ouri->s + ouri->len - pit->name.s - pit->name.len);
			nuri->len += ouri->s + ouri->len - pit->name.s - pit->name.len;
		}
	}
	nuri->s[nuri->len] = 0;

	free_params(params);

	return 0;
}

/* address of record (aor) management */

/* address of record considered case sensitive
 * - 0 = no; 1 = yes */
static int aor_case_sensitive = 0;

int set_aor_case_sensitive(int mode)
{
	int r;
	r = aor_case_sensitive;
	aor_case_sensitive = mode;
	return r;
}

int get_aor_case_sensitive(void)
{
	return aor_case_sensitive;
}
