#ifndef __SILC_CHANNELS_H
#define __SILC_CHANNELS_H

#include "chat-protocols.h"
#include "channels.h"
#include "silc-servers.h"

/* Returns SILC_CHANNEL_REC if it's SILC channel, NULL if it isn't. */
#define SILC_CHANNEL(channel) \
	PROTO_CHECK_CAST(CHANNEL(channel), SILC_CHANNEL_REC, chat_type, "SILC")
#define IS_SILC_CHANNEL(channel) \
	(SILC_CHANNEL(channel) ? TRUE : FALSE)
#define silc_channel_find(server, name) \
	SILC_CHANNEL(channel_find(SERVER(server), name))

#define STRUCT_SERVER_REC SILC_SERVER_REC
typedef struct {
#include "channel-rec.h"
  GSList *banlist;		/* list of bans */
  GSList *ebanlist;		/* list of ban exceptions */
  GSList *invitelist;		/* invite list */
  SilcUInt32 cur_key;
  SilcChannelEntry entry;
} SILC_CHANNEL_REC;

void silc_channels_init(void);
void silc_channels_deinit(void);

/* Create new SILC channel record */
SILC_CHANNEL_REC *silc_channel_create(SILC_SERVER_REC *server,
				      const char *name, int automatic);
SILC_CHANNEL_REC *silc_channel_find_entry(SILC_SERVER_REC *server,
					  SilcChannelEntry entry);

#endif
