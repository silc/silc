/*

  silcserver.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcserver/Server Library Interface
 *
 * DESCRIPTION
 *
 *
 ***/

#ifndef SILCSERVER_H
#define SILCSERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "silcserver_params.h"

/****s* silcserver/SilcServerAPI/SilcServer
 *
 * NAME
 *
 *    typedef struct SilcServerStruct *SilcServer;
 *
 * DESCRIPTION
 *
 *    This context is the actual SILC Server context and is allocated
 *    by silc_server_alloc and given as argument to all silc_server_*
 *    functions.  It is freed by the silc_server_free function.
 *
 ***/
typedef struct SilcServerStruct *SilcServer;

/****f* silcserver/SilcServerAPI/SilcServerRunning
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcServerRunning)(SilcServer server, SilcBool running,
 *                                      void *context);
 *
 * DESCRIPTION
 *
 *    Called to indicate that the server is up and running and ready to
 *    accept new connection and create connections to remote router, if
 *    any has been configured.
 *
 ***/
typedef void (*SilcServerRunning)(SilcServer server, void *context);

/****f* silcserver/SilcServerAPI/SilcServerStop
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcServerStop)(SilcServer server, void *context);
 *
 * DESCRIPTION
 *
 *    Called to indicate that the server has stopped and can be freed now.
 *
 ***/
typedef void (*SilcServerStop)(SilcServer server, void *context);

/****f* silcserver/SilcServerAPI/silc_server_alloc
 *
 * SYNOPSIS
 *
 *    SilcServer silc_server_alloc(void *app_context, SilcServerParams params,
 *                                 SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Allocates SILC server context and returns it.  Returns NULL if case
 *    of error.  The `app_context' is application specific context and
 *    can be retrieved from the server by using silc_server_get_context
 *    function.  The `params' context contains the SILC server parameters
 *    that application has gathered most likely from a configuration file
 *    or similar source.  The `params' and everything inside are allocated
 *    by the caller, but the server library will own it and free it.  It
 *    may also modify its content.
 *
 ***/
SilcServer silc_server_alloc(void *app_context, SilcServerParams params,
			     SilcSchedule schedule);

/****f* silcserver/SilcServerAPI/silc_server_free
 *
 * SYNOPSIS
 *
 *    void silc_server_free(SilcServer server);
 *
 * DESCRIPTION
 *
 *    Free the server context and all allocated resources.
 *
 ***/
void silc_server_free(SilcServer server);

/****f* silcserver/SilcServerAPI/silc_server_run
 *
 * SYNOPSIS
 *
 *    void silc_server_run(SilcServer server, SilcServerRunning running,
 *                         void *running_context);
 *
 * DESCRIPTION
 *
 *    Starts the SILC server.  This function returns immediately and the
 *    SilcSchedule must be run after this functions returns or it must be
 *    already running when this function is called.  The `running' callback
 *    will be called once the server is up and running.
 *
 ***/
void silc_server_run(SilcServer server, SilcServerRunning running,
		     void *running_context);

/****f* silcserver/SilcServerAPI/silc_server_run
 *
 * SYNOPSIS
 *
 *    void silc_server_stop(SilcServer server, SilcServerStop stop_callback,
 *                          void *stop_context);
 *
 * DESCRIPTION
 *
 *    Stops the SILC server.  Stopping of the server is asynchronous and
 *    once it has stopped the `stopped' callback will be called with the
 *    `stop_context'.  Application should not exit without calling this
 *    function.
 *
 ***/
void silc_server_stop(SilcServer server, SilcServerStop stopped,
		      void *stop_context);

#include "server_internal.h"

#ifdef __cplusplus
}
#endif

#endif /* SILCSERVER_H */
