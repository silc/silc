#ifndef __BLOB_H__
#define __BLOB_H__

#include "modules.h"

struct _BLOB_REC {
	int type;
	void *data;
	guint32 octets;
};

typedef struct _BLOB_REC BLOB_REC;

void blob_fill(BLOB_REC *blob);

#endif
