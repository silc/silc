#ifndef SILC_COMMANDS_H
#define SILC_COMMANDS_H

#define command_bind_silc(cmd, section, signal) \
        command_bind_proto(cmd, SILC_PROTOCOL, section, signal)
#define command_bind_silc_first(cmd, section, signal) \
        command_bind_proto_first(cmd, SILC_PROTOCOL, section, signal)
#define command_bind_silc_last(cmd, section, signal) \
        command_bind_proto_last(cmd, SILC_PROTOCOL, section, signal)

/* Simply returns if server isn't for SILC protocol. Prints ERR_NOT_CONNECTED
   error if there's no server or server isn't connected yet */
#define CMD_SILC_SERVER(server) \
	G_STMT_START { \
          if (server != NULL && !IS_SILC_SERVER(server)) \
            return; \
          if (server == NULL || !(server)->connected) \
            cmd_return_error(CMDERR_NOT_CONNECTED); \
	} G_STMT_END

/* Returning from command function with error */
#define cmd_return_error_value(a,v) \
	G_STMT_START { \
	  signal_emit("error command", 1, GINT_TO_POINTER(a)); \
	  signal_stop(); \
	  return (v); \
	} G_STMT_END

#endif
