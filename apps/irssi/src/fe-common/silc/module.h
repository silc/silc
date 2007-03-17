#include "common.h"

#define MODULE_NAME "fe-common/silc"
#define SILC_PROTOCOL (chat_protocol_lookup("SILC"))

#undef PACKAGE
#undef VERSION
#include "silc.h"
#include "silcclient.h"
#include "silc-core.h"
