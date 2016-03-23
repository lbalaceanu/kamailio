/*
 * $Id: bind_presence.h 1979 2007-04-06 13:24:12Z anca_vamanu $
 *
 * presence module - presence server implementation
 *
 * Copyright (C) 2007 Voice Sistem S.R.L.
 *
 * This file is part of Kamailio, a free SIP server.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2007-04-17  initial version (Anca Vamanu)
 */
/*! \file
 * \brief SIP-Router Presence :: Kamailio generic presence module
 *
 * \ingroup presence
 */


#ifndef _NDB_REDIS_BIND_H_
#define _NDB_REDIS_BIND_H_

#include "redis_client.h"

typedef int     (*redisc_exec_t)(str *srv, str *res, str *cmd, ...);
typedef void*   (*redisc_exec_argv_t)(redisc_server_t *rsrv, int argc, const char **argv, const size_t *argvlen);
typedef redisc_reply_t* (*redisc_get_reply_t)(str *name);
typedef int     (*redisc_free_reply_t)(str *name);

typedef struct ndb_redis_api {
	redisc_exec_t redisc_exec;
	redisc_exec_argv_t redisc_exec_argv;
	redisc_get_reply_t redisc_get_reply;
	redisc_free_reply_t redisc_free_reply;
} ndb_redis_api_t;

int bind_ndb_redis(ndb_redis_api_t* api);

typedef int (*bind_ndb_redis_t)(ndb_redis_api_t* api);

inline static int ndb_redis_load_api(ndb_redis_api_t *api)
{
	bind_ndb_redis_t bind_ndb_redis_exports;
	if (!(bind_ndb_redis_exports = (bind_ndb_redis_t)find_export("bind_ndb_redis", 1, 0)))
	{
		LM_ERR("Failed to import bind_ndb_redis\n");
		return -1;
	}
	return bind_ndb_redis_exports(api);
}

#endif

