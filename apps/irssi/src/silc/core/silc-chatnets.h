#ifndef __SILC_CHATNETS_H
#define __SILC_CHATNETS_H

#include "chat-protocols.h"
#include "chatnets.h"

/* returns SILC_CHATNET_REC if it's SILC network, NULL if it isn't */
#define SILC_CHATNET(chatnet) \
	PROTO_CHECK_CAST(CHATNET(chatnet), SILC_CHATNET_REC, chat_type, "SILC")

#define IS_SILC_CHATNET(chatnet) \
	(SILC_CHATNET(chatnet) ? TRUE : FALSE)

#define IS_SILCNET(silcnet) IS_SILC_CHATNET(silcnet)
#define SILCNET(silcnet) SILC_CHATNET(silcnet)

struct _SILC_CHATNET_REC {
#include "chatnet-rec.h"
};

typedef struct _SILC_CHATNET_REC SILC_CHATNET_REC;

#define silc_chatnet_find(name) \
	SILC_CHATNET(chatnet_find(name))
#define silcnet_find(name) silc_chatnet_find(name)

void silc_chatnets_init(void);
void silc_chatnets_deinit(void);

#endif
