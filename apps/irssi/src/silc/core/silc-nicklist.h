#ifndef __SILC_NICKLIST_H
#define __SILC_NICKLIST_H

#include "nicklist.h"

typedef struct {
#include "nick-rec.h"
	SilcChannelUser silc_user;

	unsigned int founder:1;
} SILC_NICK_REC;

SILC_NICK_REC *silc_nicklist_insert(SILC_CHANNEL_REC *channel,
				    SilcChannelUser user, int send_massjoin);

SILC_NICK_REC *silc_nicklist_find(SILC_CHANNEL_REC *channel,
                                  SilcClientEntry client);

/* Check if `msg' is meant for `nick'. */
int silc_nick_match(const char *nick, const char *msg);

void silc_nicklist_init(void);
void silc_nicklist_deinit(void);

#endif
