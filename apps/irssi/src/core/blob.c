#include "common.h"
#include "blob.h"
#include "modules.h"

void blob_fill(BLOB_REC *blob)
{
	blob->type = module_get_uniq_id("BLOB", 0);
}
