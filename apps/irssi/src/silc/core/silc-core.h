#ifndef __SILC_CORE_H
#define __SILC_CORE_H

extern SilcClient silc_client;

#define IS_SILC_ITEM(rec) (IS_SILC_CHANNEL(rec) || IS_SILC_QUERY(rec))

#endif
