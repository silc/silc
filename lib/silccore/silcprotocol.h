/****h* silccore/silcprotocol.h
 *
 * NAME
 *
 * silcprotocol.h
 *
 * COPYRIGHT
 *
 * Author: Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 * Copyright (C) 1997 - 2000 Pekka Riikonen
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * DESCRIPTION
 *
 * Implementation of the protocol handling routines for SILC applications.
 * These routines allow execution of arbitrary protocols in the application.
 * New protocols may be registered by type and allocated later by that
 * type for the execution. The protocols implements a state machine style
 * execution where each state is executed one after the other. The
 * application controls these states and their order of execution.
 * 
 * After the protocol has been executed, an final callback is called
 * which the application may use to do post-protocol work or to start
 * perhaps other protocols. These routines are generic and the actual
 * protocols, their types, callback and final callbacks functions must
 * be implemented in the application.
 *
 ***/

#ifndef SILCPROTOCOL_H
#define SILCPROTOCOL_H

/****d* silccore/SilcProtocolAPI/SilcProtocolType
 *
 * NAME
 * 
 *    typedef unsigned char SilcProtocolType;
 *
 * DESCRIPTION
 *
 *    Protocol type definition. The protocol types are application
 *    specific and this is just a generic type for them.
 *
 ***/
typedef unsigned char SilcProtocolType;

/****d* silccore/SilcProtocolAPI/SilcProtocolState
 *
 * NAME
 * 
 *    typedef unsigned char SilcProtocolState;
 *
 * DESCRIPTION
 *
 *    Protocol state definition and the defined protocol states. These
 *    states are the generic states. However, each protocol actually
 *    implements the states. The state after SILC_PROTOCOL_STATE_START
 *    would be state 2 in the application. These states can be easily
 *    used for example inside switch() statement.
 *
 * EXAMPLE
 *
 *    switch (protocol->state) {
 *    case SILC_PROTOCOL_STATE_START:
 *      protocol_starts_here();
 *    case 2:
 *      ...
 *    case 3:
 *      ...
 *    case SILC_PROTOCOL_STATE_END:
 *      protocol_ends_here();
 *    case SILC_PROTOCOL_STATE_FAILURE:
 *      remote_end_sent_failure();
 *    case SILC_PROTOCOL_STATE_ERROR:
 *      local_error_during_protocol();
 *    }
 *
 * SOURCE
 */
typedef unsigned char SilcProtocolState;

/* Protocol states. Do NOT change the values of these states, especially
   the START state or you break every protocol. */
#define SILC_PROTOCOL_STATE_UNKNOWN 0
#define SILC_PROTOCOL_STATE_START 1
#define SILC_PROTOCOL_STATE_END 252
#define SILC_PROTOCOL_STATE_FAILURE 253	 /* Received failure from remote */
#define SILC_PROTOCOL_STATE_ERROR 254    /* Local error at our end */
/***/

/* Type definition for authentication protocol's auth methods. */
/* XXX strictly speaking this belongs to application */
typedef unsigned char SilcProtocolAuthMeth;

/****f* silccore/SilcProtocolAPI/SilcProtocolCallback
 *
 * SYNOPSIS
 *
 *    typedef SilcTaskCallback SilcProtocolCallback;
 *
 * DESCRIPTION
 *
 *    Protocol callback. This callback is set when registering new
 *    protocol. The callback is called everytime the protocol is executed.
 *    The `context' delivered to this callback function is the SilcProtocol
 *    context and needs to be explicitly type casted to SilcProtocol in
 *    the callback function.
 *
 ***/
typedef SilcTaskCallback SilcProtocolCallback;

/****f* silccore/SilcProtocolAPI/SilcProtocolFinalCallback
 *
 * SYNOPSIS
 *
 *    typedef SilcTaskCallback SilcProtocolFinalCallback;
 *
 * DESCRIPTION
 *
 *    Final protocol callback. This callback is set when allocating
 *    protocol for execution. This is called when the protocol has ended.
 *    The `context' delivered to this callback function is the SilcProtocol
 *    context and needs to be explicitly type casted to SilcProtocol in
 *    the callback function.
 *
 ***/
typedef SilcTaskCallback SilcProtocolFinalCallback;

/****s* silccore/SilcProtocolAPI/SilcProtocolObject
 *
 * NAME
 * 
 *    typedef struct SilcProtocolObjectStruct { ... } SilcProtocolObject;
 *
 * DESCRIPTION
 *
 *    The object for one protocol. This hold the information of one
 *    registered protocol. Application must not allocate this type
 *    directly. It is used by the protocol routines.
 *
 *    Short description of the field following:
 *  
 *    SilcProtocolType type
 *
 *      Protocol type.
 * 
 *    SilcProtocolCallback callback;
 *
 *      Callback function for the protocol. This is SilcTaskCallback function
 *      pointer as the protocols in SILC are executed as timeout tasks.
 *
 *    struct SilcProtocolObjectStruct *next;
 *
 *      Pointer to the next protocol.
 *
 ***/
typedef struct SilcProtocolObjectStruct {
  SilcProtocolType type;
  SilcProtocolCallback callback;
  struct SilcProtocolObjectStruct *next;
} SilcProtocolObject;

/****s* silccore/SilcProtocolAPI/SilcProtocol
 *
 * NAME
 * 
 *    typedef struct SilcProtocolStruct { ... } *SilcProtocol;
 *
 * DESCRIPTION
 *
 *    The actual protocol object. This is allocated by the silc_protocol_alloc
 *    and holds the information about the current protocol. Information
 *    such as the current state, execution callback and final callback.
 *    The context is freed by silc_protocol_free function.
 *
 *    Short description of the field following:
 *
 *    SilcProtocolObject *protocol
 *
 *      This is the pointer to the SilcProtocolObject and holds the
 *      protocol specific information.
 *
 *    SilcProtocolState state
 *
 *      Protocol state. The state of the protocol can be changed in the
 *      callback function.
 *
 *    void *context
 *
 *      Context to be sent for the callback function. This is usually 
 *      object for either SILC client or server. However, this abstraction 
 *      makes it possible that this pointer could be some other object as
 *      well. Note that the context is not delivered in any callback 
 *      function. Application can access it through this context.
 *
 *    SilcProtocolFinalCallback final_callback;
 *
 *      This is a callback function that is called with timeout _after_ the
 *      protocol has finished or error occurs. If this is NULL, naturally 
 *      nothing will be executed. Protocol should call this function only at 
 *      SILC_PROTOCOL_STATE_END and SILC_PROTOCOL_STATE_ERROR states.
 *
 ***/
typedef struct SilcProtocolStruct {
  SilcProtocolObject *protocol;
  SilcProtocolState state;
  void *context;
  SilcProtocolFinalCallback final_callback;
} *SilcProtocol;

/* Prototypes */

/****f* silccore/SilcProtocolAPI/silc_protocol_register
 *
 * SYNOPSIS
 *
 *    void silc_protocol_register(SilcProtocolType type,
 *                                SilcProtocolCallback callback);
 *
 * DESCRIPTION
 *
 *    Dynamically registers new protocol. The protocol is added into protocol
 *    list and can be unregistered with silc_protocol_unregister. The
 *    `type' is the type of the protocol and is used to identify the
 *    protocol when allocating it with silc_protocol_alloc. The `callback'
 *    is the actual protocol function that is called when protocol is
 *    executed (and it performes the actual protocol). The protocol
 *    is unregistered by silc_protocol_unregister function.
 *
 ***/
void silc_protocol_register(SilcProtocolType type,
			    SilcProtocolCallback callback);

/****f* silccore/SilcProtocolAPI/silc_protocol_unregister
 *
 * SYNOPSIS
 *
 *    void silc_protocol_unregister(SilcProtocolType type,
 *                                  SilcProtocolCallback callback);
 *
 * DESCRIPTION
 *
 *    Unregisters protocol. The unregistering is done by both protocol type
 *    and the protocol callback. Every registered protocol must be 
 *    unregistered using this function.
 *
 ***/
void silc_protocol_unregister(SilcProtocolType type,
                              SilcProtocolCallback callback);

/****f* silccore/SilcProtocolAPI/silc_protocol_alloc
 *
 * SYNOPSIS
 *
 *    void silc_protocol_alloc(SilcProtocolType type, 
 *                             SilcProtocol *new_protocol,
 *                             void *context, 
 *                             SilcProtocolFinalCallback callback);
 *
 * DESCRIPTION
 *
 *    Allocates a new protocol. The new allocated and initialized 
 *    protocol is returned to the `new_protocol' argument. The argument
 *    context `context' is the context to be sent as argument for the
 *    protocol callback function. The `callback' argument is the function
 *    to be called after the protocol has finished.
 *
 ***/
void silc_protocol_alloc(SilcProtocolType type, SilcProtocol *new_protocol,
			 void *context, SilcProtocolFinalCallback callback);

/****f* silccore/SilcProtocolAPI/silc_protocol_free
 *
 * SYNOPSIS
 *
 *    void silc_protocol_free(SilcProtocol protocol);
 *
 * DESCRIPTION
 *
 *    Frees the protocol context. This must be called for all allocated
 *    protocols.
 *
 ***/
void silc_protocol_free(SilcProtocol protocol);

/****f* silccore/SilcProtocolAPI/silc_protocol_execute
 *
 * SYNOPSIS
 *
 *    void silc_protocol_execute(SilcProtocol protocol, void *timeout_queue,
 *                               long secs, long usecs);
 *
 * DESCRIPTION
 *
 *    Executes the protocol. This calls the state that has been set.
 *    The state must be set before calling this function. This is then
 *    also used to call always the next state after changing the state
 *    of the protocol. The `timeout_queue' is a timeout task queue from
 *    the application. It is passed to the protocol callback functions.
 *    The `secs' and `usecs' are the timeout before the protocol is
 *    executed. If both zero the protocol is executed immediately.
 *
 ***/
void silc_protocol_execute(SilcProtocol protocol, void *timeout_queue,
			   long secs, long usecs);

/****f* silccore/SilcProtocolAPI/silc_protocol_execute_final
 *
 * SYNOPSIS
 *
 *    void 
 *    silc_protocol_execute_final(SilcProtocol protocol, void *timeout_queue);
 *
 * DESCRIPTION
 *
 *    Executes the final callback for the protocol. The `timeout_queue' is
 *    a timeout task queue from the application. It is passed to the
 *    protocol callback functions. The final callback is executed 
 *    immediately.
 *
 ***/
void silc_protocol_execute_final(SilcProtocol protocol, void *timeout_queue);

/****f* silccore/SilcProtocolAPI/silc_protocol_cancel
 *
 * SYNOPSIS
 *
 *    void silc_protocol_cancel(SilcProtocol protocol, void *timeout_queue);
 *
 * DESCRIPTION
 *
 *    Cancels the execution of the next state of the protocol. This has
 *    effect only if the silc_protocol_execute was called with timeout.
 *    It is guaranteed that if the protocol is cancelled before the timeout
 *    has elapsed the protocol callback won't be called.
 *
 ***/
void silc_protocol_cancel(SilcProtocol protocol, void *timeout_queue);

#endif
