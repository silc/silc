#include <stdio.h>
#include <stdlib.h>

#include "silcincludes.h"
#include "rsa.h"
#include "rsa_internal.h"

void testi(SilcRng rng, void *context)
{
        char *numbuf;
        unsigned int bytes;
        unsigned int i;
        MP_INT tnum;            /* number we'll encrypt */
        MP_INT test;            /* en/decrypted result of tnum */
	RsaKey *key = (RsaKey *)context;
	int bits = 1024;        

        numbuf = (char *)malloc((bits / 3) + 1);
        bytes = bits / 10;
            
        mpz_init(&tnum);
        mpz_init(&test);
        
        fprintf(stderr, "\nTesting encryption and decryption ... ");

        for(i = 0; i < bytes; i++)
            sprintf(numbuf + 2 * i, "%02x", silc_rng_get_byte(rng));
        
        mpz_set_str(&tnum, numbuf, 16);

        /* empty buffer */
        memset(numbuf, 0, bits / 3);
        free(numbuf);

        /* make tnum smaller than n */
        mpz_div_ui(&tnum, &tnum, 10);
        /* encrypt */
        rsa_en_de_crypt(&test, &tnum, &key->e, &key->n);
        /* decrypt */
        rsa_en_de_crypt(&test, &test, &key->d, &key->n);
        /* see if decrypted result is same than the original one is */
        if (mpz_cmp(&test, &tnum) != 0) {
            fprintf(stderr, "Error in encryption and decryption!\n");
            return -1;
        }

        mpz_clear(&tnum);
        mpz_clear(&test);

        fprintf(stderr, "Keys are Ok.\n");
}

int main()
{
	SilcPKCS pkcs;
	SilcRng rng;
	unsigned char *pk, *prv;
	unsigned int pk_len, prv_len;
	unsigned char *src, *dst, *new;
	unsigned int src_len, dst_len, new_len;
	SilcInt tnum, test;

	silc_pkcs_alloc("rsa", &pkcs);

	rng = silc_rng_alloc();
	silc_rng_init(rng);
	silc_math_primegen_init();

	pkcs->pkcs->init(pkcs->context, 1024, rng);
	
	pk = silc_pkcs_get_public_key(pkcs, &pk_len);
	prv = silc_pkcs_get_public_key(pkcs, &prv_len);

	src = "PEKKA RIIKONEN";
	src_len = 5;
	dst = silc_calloc(200, sizeof(unsigned char));
	pkcs->pkcs->encrypt(pkcs->context, src, src_len, dst, &dst_len);

	SILC_LOG_HEXDUMP(("src"), src, src_len);
	SILC_LOG_HEXDUMP(("dst"), dst, dst_len);

	new = silc_calloc(200, sizeof(unsigned char));
	pkcs->pkcs->decrypt(pkcs->context, dst, dst_len, new, &new_len);

	SILC_LOG_HEXDUMP(("new"), new, new_len);

	testi(rng, pkcs->context);

	return 0;
}
