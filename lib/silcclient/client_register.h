/*

  client_register.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CLIENT_REGISTER_H
#define CLIENT_REGISTER_H

SILC_FSM_STATE(silc_client_new_id);
SILC_FSM_STATE(silc_client_st_register);
SILC_FSM_STATE(silc_client_st_register_complete);
SILC_FSM_STATE(silc_client_st_register_error);
SILC_FSM_STATE(silc_client_st_resume);
SILC_FSM_STATE(silc_client_st_resume_new_id);
SILC_FSM_STATE(silc_client_st_resume_error);

#endif /* CLIENT_REGISTER_H */
