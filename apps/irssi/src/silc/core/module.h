#include "common.h"

#define MODULE_NAME "silc"

#undef PACKAGE
#undef VERSION
#include "silcincludes.h"
#include "clientlibincludes.h"
#include "client_ops.h"
#include "silc-core.h"

#define SILC_PROTOCOL (chat_protocol_lookup("SILC"))
