#ifndef __CLIENTUTIL_H
#define __CLIENTUTIL_H

int silc_client_verify_server_key(SILC_SERVER_REC *server,
				  unsigned char *pk, unsigned int pk_len,
				  SilcSKEPKType pk_type);

#endif
