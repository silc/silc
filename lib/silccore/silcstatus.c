/*

  silcstatus.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include "silcstatus.h"

/* Returns arguments by the status type. */

SilcUInt32 silc_status_get_args(SilcStatus status,
				SilcArgumentPayload args,
				void **ret_arg1, void **ret_arg2)
{
  SilcUInt32 num, len;
  unsigned char *tmp;

  assert(ret_arg1 && ret_arg2);

  num = silc_argument_get_arg_num(args);
  if (num > 3)
    return 0;
  if (num == 0)
    return 0;

  switch (status) {

  case SILC_STATUS_ERR_NO_SUCH_NICK:
  case SILC_STATUS_ERR_NO_SUCH_CHANNEL:
  case SILC_STATUS_ERR_NO_SUCH_SERVER:
  case SILC_STATUS_ERR_NO_SUCH_SERVICE:
  case SILC_STATUS_ERR_UNKNOWN_ALGORITHM:
    tmp = silc_argument_get_arg_type(args, 2, &len);
    if (!tmp)
      return 0;
    *ret_arg1 = silc_memdup(tmp, len);
    if (!(*ret_arg1))
      return 0;
    num = 1;
    break;

  case SILC_STATUS_ERR_NO_SUCH_CLIENT_ID:
  case SILC_STATUS_ERR_BAD_CLIENT_ID:
    {
      SilcID id;
      tmp = silc_argument_get_arg_type(args, 2, &len);
      if (!tmp)
	return 0;
      if (silc_id_payload_parse_id(tmp, len, &id))
	return 0;
      *ret_arg1 = silc_id_dup(&id.u.client_id, SILC_ID_CLIENT);
      if (!(*ret_arg1))
	return 0;
      num = 1;
    }
    break;

  case SILC_STATUS_ERR_NO_SUCH_SERVER_ID:
  case SILC_STATUS_ERR_BAD_SERVER_ID:
    {
      SilcID id;
      tmp = silc_argument_get_arg_type(args, 2, &len);
      if (!tmp)
	return 0;
      if (silc_id_payload_parse_id(tmp, len, &id))
	return 0;
      *ret_arg1 = silc_id_dup(&id.u.server_id, SILC_ID_SERVER);
      if (!(*ret_arg1))
	return 0;
      num = 1;
    }
    break;

  case SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID:
  case SILC_STATUS_ERR_BAD_CHANNEL_ID:
  case SILC_STATUS_ERR_NOT_ON_CHANNEL:
  case SILC_STATUS_ERR_CHANNEL_IS_FULL:
  case SILC_STATUS_ERR_NOT_INVITED:
  case SILC_STATUS_ERR_BANNED_FROM_CHANNEL:
  case SILC_STATUS_ERR_NO_CHANNEL_PRIV:
  case SILC_STATUS_ERR_NO_CHANNEL_FOPRIV:
    {
      SilcID id;
      tmp = silc_argument_get_arg_type(args, 2, &len);
      if (!tmp)
	return 0;
      if (silc_id_payload_parse_id(tmp, len, &id))
	return 0;
      *ret_arg1 = silc_id_dup(&id.u.channel_id, SILC_ID_CHANNEL);
      if (!(*ret_arg1))
	return 0;
      num = 1;
    }
    break;

  case SILC_STATUS_ERR_USER_NOT_ON_CHANNEL:
  case SILC_STATUS_ERR_USER_ON_CHANNEL:
    {
      SilcID id;
      tmp = silc_argument_get_arg_type(args, 2, &len);
      if (!tmp)
	return 0;
      if (silc_id_payload_parse_id(tmp, len, &id))
	return 0;
      *ret_arg1 = silc_id_dup(&id.u.client_id, id.type);
      if (!(*ret_arg1))
	return 0;
      num = 1;
      tmp = silc_argument_get_arg_type(args, 3, &len);
      if (!tmp)
	return num;
      if (silc_id_payload_parse_id(tmp, len, &id))
	return 0;
      *ret_arg2 = silc_id_dup(&id.u.channel_id, id.type);
      if (!(*ret_arg2))
	return num;
      num = 2;
    }
    break;

  default:
    return 0;
    break;
  }

  return num;
}
