#include "../common/module.h"

#include "silc.h"
#include "silcclient.h"
#include "client_ops.h"
#include "silc-core.h"

#include "silc-channels.h"
#include "silc-commands.h"
#include "silc-queries.h"
#include "silc-servers.h"

typedef SILC_SERVER_REC *Irssi__Silc__Server;
typedef SILC_CHANNEL_REC *Irssi__Silc__Channel;
typedef QUERY_REC *Irssi__Silc__Query;
typedef NICK_REC *Irssi__Silc__Nick;
