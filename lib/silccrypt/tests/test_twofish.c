#include <stdio.h>
#include <stdlib.h>

int main()
{
	int i, k, l;
	unsigned char key[256];
	unsigned char plain[256];
	unsigned char plain2[256];
	unsigned char cipher[256];
	memset(&key, 0, sizeof(key));
	memset(&plain, 0, sizeof(plain));
	memset(&plain2, 0, sizeof(plain2));
	memset(&cipher, 0, sizeof(cipher));

	fprintf(stderr, "\nKey:\n");
	for (i = 0; i < (sizeof(plain) / 2); i++) {
		key[i] = i;
		key[i+1] = i+1;
		fprintf(stderr, "%02x%02x ", key[i], key[i+1]);
	}

	fprintf(stderr, "\nSetting key\n");
	set_key(key, 128);

	fprintf(stderr, "\nPlaintext:\n");
	for (i = 0; i < (sizeof(plain) / 2); i++) {
		plain[i] = i;
		plain[i+1] = i+1;
		fprintf(stderr, "%02x%02x ", plain[i], plain[i+1]);
	}

	fprintf(stderr, "\n\nEncrypting\n");
	fprintf(stderr, "Ciphertext:\n");
	l = 0;
	for (k = 0; k < 8; k++) {
		encrypt(&plain[l], &cipher[l]);
		for (i = 0; i < 16; i++) {
			fprintf(stderr, "%02x", cipher[l+i]);
			fprintf(stderr, "%02x ", cipher[l+i+1]);
		}
		l += 16;
	}

	fprintf(stderr, "\n\nDecrypting\n");

	fprintf(stderr, "Decryptedtext:\n");
	l = 0;
	for (k = 0; k < 8; k++) {
		decrypt(&cipher[l], &plain2[l]);
		for (i = 0; i < 16; i++) {
			fprintf(stderr, "%02x", plain2[l+i]);
			fprintf(stderr, "%02x ", plain2[l+i+1]);
		}
		l += 16;
	}
	fprintf(stderr, "\nAll done.\n");

	return 0;
}
