#include <stdio.h>
#include <stdlib.h>
#include "silcincludes.h"

#include "aes.h"

int main()
{
	int i;
	unsigned char key[256];
	unsigned char plain[256];
	unsigned char plain2[256];
	unsigned char cipher[256];
	unsigned char iv[256];
	void *context;
	int len;

	memset(&key, 0, sizeof(key));
	memset(&plain, 0, sizeof(plain));
	memset(&plain2, 0, sizeof(plain2));
	memset(&cipher, 0, sizeof(cipher));
	memset(&iv, 0, sizeof(iv));

	context = malloc(silc_aes_context_len());

	fprintf(stderr, "\nKey:\n");
#if 0
	len = 32;

	for (i = 0; i < len; i += 2) {
		fprintf(stderr, "%02x%02x ", key[i], key[i+1]);
	}

	fprintf(stderr, "\nSetting key\n");
	silc_aes_set_key(context, key, len * 8);

	fprintf(stderr, "\nPlaintext:\n");
	for (i = 0; i < len; i += 2) {
		plain[i] = i;
		plain[i+1] = i+1;
		fprintf(stderr, "%02x%02x ", plain[i], plain[i+1]);
	}

#else
	len = 16;

	key[0] = 0x2b;
	key[1] = 0x7e;
	key[2] = 0x15;
	key[3] = 0x16;
	key[4] = 0x28;
	key[5] = 0xae;
	key[6] = 0xd2;
	key[7] = 0xa6;
	key[8] = 0xab;
	key[9] = 0xf7;
	key[10] = 0x15;
	key[11] = 0x88;
	key[12] = 0x09;
	key[13] = 0xcf;
	key[14] = 0x4f;
	key[15] = 0x3c;
	for (i = 0; i < len ; i += 2) {
		fprintf(stderr, "%02x%02x ", key[i], key[i+1]);
	}

	fprintf(stderr, "\nSetting key\n");
	silc_aes_set_key(context, key, len * 8);

	plain[0] = 0x32;
	plain[1] = 0x43;
	plain[2] = 0xf6;
	plain[3] = 0xa8;
	plain[4] = 0x88;
	plain[5] = 0x5a;
	plain[6] = 0x30;
	plain[7] = 0x8d;
	plain[8] = 0x31;
	plain[9] = 0x31;
	plain[10] = 0x98;
	plain[11] = 0xa2;
	plain[12] = 0xe0;
	plain[13] = 0x37;
	plain[14] = 0x07;
	plain[15] = 0x34;

	fprintf(stderr, "\nPlaintext:\n");
	for (i = 0; i < len; i += 2) {
		fprintf(stderr, "%02x%02x ", plain[i], plain[i+1]);
	}

#endif

	fprintf(stderr, "\n\nEncrypting\n");
	silc_aes_encrypt_cbc(context, plain, cipher, len, iv);

	fprintf(stderr, "Ciphertext:\n");
	for (i = 0; i < len; i += 2) {
		fprintf(stderr, "%02x", cipher[i]);
		fprintf(stderr, "%02x ", cipher[i+1]);
	}

	memset(&iv, 0, sizeof(iv));

	fprintf(stderr, "\n\nDecrypting\n");
	silc_aes_decrypt_cbc(context, cipher, plain2, len, iv);

	fprintf(stderr, "Decryptedtext:\n");
	for (i = 0; i < len; i += 2) {
		fprintf(stderr, "%02x", plain2[i]);
		fprintf(stderr, "%02x ", plain2[i+1]);
	}
	fprintf(stderr, "\nDone\n");

	return 0;
}
