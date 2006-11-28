#include "common.h"

#define MODULE_NAME "silc"

#undef PACKAGE
#undef VERSION
#include "silc.h"
#include "silcclient.h"
#include "client_ops.h"
#include "silc-core.h"

#define SILC_PROTOCOL (chat_protocol_lookup("SILC"))
