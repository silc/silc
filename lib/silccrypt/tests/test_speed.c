#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
//#include "../ciphers.h"
#include "../serpent.h"

#define timediff(tv2, tv1)  (((tv2)->tv_sec - (tv1)->tv_sec)*1000000 + \
                             ((tv2)->tv_usec - (tv1)->tv_usec))

int main(int argc, char **argv)
{
	int i;
	unsigned char key[256];
	unsigned char plain[512];
	unsigned char plain2[512];
	unsigned char cipher[512];
	unsigned char iv[128];
	struct timeval tv1,tv2;

	memset(&key, 0, sizeof(key));
	memset(&plain, 0, sizeof(plain));
	memset(&plain2, 0, sizeof(plain2));
	memset(&cipher, 0, sizeof(cipher));
	memset(&iv, 0, sizeof(iv));

	gettimeofday(&tv1, NULL);
	silc_serpent_init(NULL, key, 128);
	gettimeofday(&tv2, NULL);

	fprintf(stderr, "\nPlaintext:\n");
	for (i = 0; i < sizeof(plain) / 2; i += 2) {
		plain[i] = i;
		plain[i+1] = i+1;
		fprintf(stderr, "%02x%02x ", plain[i], plain[i+1]);
	}

	fprintf(stderr, "\n\nEncrypting\n");
	gettimeofday(&tv1, NULL);
	silc_serpent_encrypt_cbc(NULL, plain, cipher, sizeof(plain), iv);
	gettimeofday(&tv2, NULL);

	fprintf(stderr, "Encrypt %6.3f Mb/s\n", 
		   1000000.0*8.0/timediff(&tv2,&tv1));

	fprintf(stderr, "Ciphertext:\n");
	for (i = 0; i < (sizeof(cipher)/2); i += 2) {
		fprintf(stderr, "%02x", cipher[i]);
		fprintf(stderr, "%02x ", cipher[i+1]);
	}

	fprintf(stderr, "\n\nDecrypting\n");
	gettimeofday(&tv1, NULL);
	silc_serpent_decrypt_cbc(NULL, cipher, plain2, sizeof(cipher), iv);
	gettimeofday(&tv2, NULL);

	fprintf(stderr, "Decrypt %6.3f Mb/s\n", 
		   1000000.0*8.0/timediff(&tv2,&tv1));

	fprintf(stderr, "Decrypted text:\n");
	for (i = 0; i < (sizeof(plain2)/2); i += 2) {
		fprintf(stderr, "%02x", plain2[i]);
		fprintf(stderr, "%02x ", plain2[i+1]);
	}
	fprintf(stderr, "\nDone\n");

	return 0;
}
