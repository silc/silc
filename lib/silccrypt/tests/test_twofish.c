#include <stdio.h>
#include <stdlib.h>
#include "silc.h"

#include "twofish.h"

int main()
{
	int i;
	unsigned char key[256];
	unsigned char plain[256];
	unsigned char plain2[256];
	unsigned char cipher[256];
	unsigned char iv[256];
	void *context;

	memset(&key, 0, sizeof(key));
	memset(&plain, 0, sizeof(plain));
	memset(&plain2, 0, sizeof(plain2));
	memset(&cipher, 0, sizeof(cipher));
	memset(&iv, 0, sizeof(iv));

	context = malloc(silc_twofish_context_len());

	fprintf(stderr, "\nKey:\n");
	for (i = 0; i < (sizeof(key) / 2); i += 2) {
		fprintf(stderr, "%02x%02x ", key[i], key[i+1]);
	}

	fprintf(stderr, "\nSetting key\n");
	silc_twofish_set_key(context, key, 256);

	fprintf(stderr, "\nPlaintext:\n");
	for (i = 0; i < (sizeof(plain) / 2); i += 2) {
		plain[i] = i;
		plain[i+1] = i+1;
		fprintf(stderr, "%02x%02x ", plain[i], plain[i+1]);
	}

	fprintf(stderr, "\n\nEncrypting\n");
	silc_twofish_encrypt_cbc(context, plain, cipher, 256, iv);

	fprintf(stderr, "Ciphertext:\n");
	for (i = 0; i < (sizeof(cipher)/2); i += 2) {
		fprintf(stderr, "%02x", cipher[i]);
		fprintf(stderr, "%02x ", cipher[i+1]);
	}

	memset(&iv, 0, sizeof(iv));

	fprintf(stderr, "\n\nDecrypting\n");
	silc_twofish_decrypt_cbc(context, cipher, plain2, 256, iv);

	fprintf(stderr, "Decryptedtext:\n");
	for (i = 0; i < (sizeof(plain2)/2); i += 2) {
		fprintf(stderr, "%02x", plain2[i]);
		fprintf(stderr, "%02x ", plain2[i+1]);
	}
	fprintf(stderr, "\nDone\n");

	return 0;
}
