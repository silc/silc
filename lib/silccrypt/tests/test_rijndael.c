#include <stdio.h>
#include <stdlib.h>

main()
{
	int i, k;
	unsigned char key[256];
	unsigned char plain[256];
	unsigned char plain2[256];
	unsigned char cipher[256];
	memset(&key, 0, sizeof(key));
	memset(&plain, 0, sizeof(plain));
	memset(&plain2, 0, sizeof(plain2));
	memset(&cipher, 0, sizeof(cipher));

	fprintf(stderr, "\nKey:\n");
	for (i = 0; i < sizeof(key) / 2; i++) {
		key[i] = i;
		key[i+1] = i+1;
		fprintf(stderr, "%02x%02x ", key[i], key[i+1]);
	}

	fprintf(stderr, "\nSetting key\n");
	set_key(key, 128);

	fprintf(stderr, "\nPlaintext:\n");
	for (i = 0; i < sizeof(plain) / 2; i++) {
		plain[i] = i;
		plain[i+1] = i+1;
		fprintf(stderr, "%02x%02x ", plain[i], plain[i+1]);
	}

	fprintf(stderr, "Encrypting\n");
	encrypt(plain, cipher);

	fprintf(stderr, "\nCiphertext:\n");
	for (i = 0; i < sizeof(cipher); i++) {
		fprintf(stderr, "%02x", cipher[i]);
	}

	fprintf(stderr, "Decrypting\n");
	decrypt(cipher, plain2);

	fprintf(stderr, "\nDecryptedtext:\n");
	for (i = 0; i < sizeof(plain2); i++) {
		fprintf(stderr, "%02x", plain2[i]);
	}

}
