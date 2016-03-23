/*
 * bind_ndb_redis.c created on: Feb 18, 2016    Author: lbalaceanu
 *
 * presence module - presence server implementation
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 * This is the core presence module, used in combination with other modules.
 *
 * \ingroup presence
 */

#include "bind_ndb_redis.h"
#include "redis_client.h"

int bind_ndb_redis(ndb_redis_api_t* api)
{
	if (!api) {
		LM_ERR("Invalid parameter value\n");
		return -1;
	}

	api->redisc_exec = redisc_exec;
	api->redisc_exec_argv= redisc_exec_argv;
	api->redisc_get_reply= redisc_get_reply;
	api->redisc_free_reply= redisc_free_reply;
	return 0;
}
