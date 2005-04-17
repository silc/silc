#ifndef __SILC_CMDQUEUE_H
#define __SILC_CMDQUEUE_H

/* wrappers for queuing commands:

   basically the same as the correspondening silc_client_* functions 
   with one additional parameter:
   
   bool sync		- command must be executed in sync (i.e. no
   			  other command may be send before completion)
   */

bool silc_queue_command_call(SilcClient client, 
				SilcClientConnection conn,
				const char *command_line, ...);

#define silc_queue_command_pending silc_client_command_pending

/*
   enable and/or disable command queueing. If command queueing is
   disabled, all silc_queue_* calls will immedially call silc_client_*
   functions. If queueing is enabled, all silc_queue_* calls don't have
   any effect until queueing is disabled again.

   queueing is enabled and disabled for each SilcClientConnection
   seperatly.

   If queueing is enabled, silc_queue_flush will send all currently
   queued commands but won't disable queueing.
 */
void silc_queue_enable(SilcClientConnection conn);
void silc_queue_disable(SilcClientConnection conn);
void silc_queue_flush(SilcClientConnection conn);

/* returns true if queueing is enabled */
bool silc_queue_get_state(SilcClientConnection conn);

void silc_queue_init(void);
void silc_queue_deinit(void);

#endif
