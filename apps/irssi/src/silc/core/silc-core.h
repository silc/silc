#ifndef __SILC_CORE_H
#define __SILC_CORE_H

#include "clientutil.h"

/* Default client configuration file. This can be overridden at the
   compilation time. Otherwise, use default. This can be overridden on
   command line as well. */
#ifndef SILC_CLIENT_CONFIG_FILE
#define SILC_CLIENT_CONFIG_FILE "/etc/silc/silc.conf"
#endif

/* Default user configuration file. This file is searched from user's
   home directory. This may override global configuration settings. */
#define SILC_CLIENT_HOME_CONFIG_FILE "~/.silc/silc.conf"

/* Default public and private key file names */
#define SILC_CLIENT_PUBLIC_KEY_NAME "public_key.pub"
#define SILC_CLIENT_PRIVATE_KEY_NAME "private_key.prv"

/* Default key expiration time, one year. */
#define SILC_CLIENT_KEY_EXPIRES 365

/* Default settings for creating key pair */
#define SILC_CLIENT_DEF_PKCS "rsa"
#define SILC_CLIENT_DEF_PKCS_LEN 4096

extern SilcClient silc_client;
extern SilcHash sha1hash;
extern SilcPublicKey irssi_pubkey;
extern SilcPrivateKey irssi_privkey;
extern char *opt_nickname;

#define IS_SILC_ITEM(rec) (IS_SILC_CHANNEL(rec) || IS_SILC_QUERY(rec))

#define SILC_MSG_SIGNED_VERIFIED 0
#define SILC_MSG_SIGNED_UNKNOWN 1
#define SILC_MSG_SIGNED_FAILED 2

#endif
