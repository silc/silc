#include "silc.h"
#include "dsa.h"

unsigned char *signature = NULL;
SilcUInt32 signature_len;
SilcBool success = FALSE;

static void sign_cb(SilcBool success, const unsigned char *sig,
		    SilcUInt32 sig_len, void *context)
{
  SILC_LOG_HEXDUMP(("Signature"), sig, sig_len);
  signature = silc_memdup(sig, sig_len);
  signature_len = sig_len;
}

static void verify_cb(SilcBool s, void *context)
{
  SILC_LOG_DEBUG(("Verify %s", s ? "success" : "failed"));
  success = s;
}

int main(int argc, char **argv)
{
  const SilcPKCSAlgorithm *alg;
  SilcRng rng;
  void *public_key, *private_key;
  SilcHash hash;
  unsigned char tmp[20];

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*dsa*,*pkcs*");
  }

  silc_crypto_init(NULL);

  rng = silc_rng_alloc();
  silc_rng_init(rng);
  silc_hash_alloc("sha1", &hash);

  SILC_LOG_DEBUG(("Generate DSA keypair"));
  alg = silc_pkcs_find_algorithm("dsa", "dss");
  if (!silc_dsa_generate_key(alg, 2048, rng, &public_key, &private_key))
    goto err;

  SILC_LOG_DEBUG(("Key length: %d",
		  silc_dsa_public_key_bitlen(alg, public_key)));

  SILC_LOG_DEBUG(("Sign"));
  memset(tmp, 0, sizeof(tmp));
  silc_dsa_sign(alg, private_key, tmp, sizeof(tmp), TRUE, hash, rng,
		sign_cb, NULL);

  SILC_LOG_DEBUG(("Verify"));
  silc_dsa_verify(alg, public_key, signature, signature_len,
		  tmp, sizeof(tmp), hash, rng, verify_cb, NULL);

  silc_rng_free(rng);
  silc_free(signature);

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
