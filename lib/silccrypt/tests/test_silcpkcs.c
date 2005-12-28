/* Tests API in silcpkcs.h */
#include "silc.h"

int key_len = 2048;
const unsigned char p[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
int p_len = 32;

int test()
{
  SilcBool success = FALSE;
  SilcPKCS pkcs;
  unsigned char *pk, *prv;
  char *identifier;
  SilcUInt32 pk_len = 0, prv_len = 0;
  SilcPublicKey pubkey, pubkey2;
  SilcPublicKeyIdentifier ident;
  SilcPrivateKey privkey;
  SilcBuffer buf;
  unsigned char d[4096], d2[4096];
  SilcUInt32 dlen, d2len;
  SilcHash sha1;

  SILC_LOG_DEBUG(("Registering PKCSs"));
  if (!silc_pkcs_register_default()) {
    SILC_LOG_DEBUG(("Registering PKCSs failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Supported PKCS: %s", silc_pkcs_get_supported()));


  SILC_LOG_DEBUG(("Allocate rsa PKCS"));
  if (!silc_pkcs_is_supported("rsa")) {
    SILC_LOG_DEBUG(("rsa PKCS not supported"));
    goto err;
  }
  if (!silc_pkcs_alloc("rsa", &pkcs)) {
    SILC_LOG_DEBUG(("Allocate rsa PKCS failed"));
    goto err;
  }


  SILC_LOG_DEBUG(("Generating new key pair"));
  if (!silc_pkcs_generate_key(pkcs, key_len, NULL)) {
    SILC_LOG_DEBUG(("Generating new key pair failed"));
    goto err;
  }


  SILC_LOG_DEBUG(("Key length: %d", silc_pkcs_get_key_len(pkcs)));
  if (silc_pkcs_get_key_len(pkcs) != key_len) {
    SILC_LOG_DEBUG(("Bad key length: %d != %d",
		    silc_pkcs_get_key_len(pkcs), key_len));
    goto err;
  }
  SILC_LOG_DEBUG(("PKCS name: %s", silc_pkcs_get_name(pkcs)));

  SILC_LOG_DEBUG(("------"));
  SILC_LOG_DEBUG(("------ Testing Public Key Routines"));
  SILC_LOG_DEBUG(("------"));

  SILC_LOG_DEBUG(("Get public key from PKCS"));
  pk = silc_pkcs_get_public_key(pkcs, &pk_len);
  if (!pk || !pk_len) {
    SILC_LOG_DEBUG(("Getting public key failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Making new public key identifier"));
  identifier = silc_pkcs_encode_identifier("foo", "bar", "foo bar",
					   "foo@bar.com", "bar", "BB");
  if (!identifier) {
    SILC_LOG_DEBUG(("Making new public key identifier failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decoding public key identifier"));
  ident = silc_pkcs_decode_identifier(identifier);
  if (!ident) {
    SILC_LOG_DEBUG(("Decoding public key identifier failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Allocating SilcPublicKey"));
  pubkey = silc_pkcs_public_key_alloc("rsa", identifier, pk, pk_len);
  if (!pubkey) {
    SILC_LOG_DEBUG(("Allocating SilcPublicKey failed"));
    goto err;
  }
  silc_free(pk);
  SILC_LOG_DEBUG(("Encode SilcPublicKey data"));
  pk = silc_pkcs_public_key_encode(pubkey, &pk_len);
  if (!pk) {
    SILC_LOG_DEBUG(("Encode SilcPublicKey data failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decode public key to SilcPublicKey"));
  if (!silc_pkcs_public_key_decode(pk, pk_len, &pubkey)) {
    SILC_LOG_DEBUG(("Decode public key to SilcPublicKey failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Save public key to publickey.pub"));
  unlink("publickey.pub");
  if (!silc_pkcs_save_public_key("publickey.pub", pubkey,
				 SILC_PKCS_FILE_PEM)) {
    SILC_LOG_DEBUG(("Save public key to publickey.pub failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Copying public key"));
  pubkey2 = silc_pkcs_public_key_copy(pubkey);
  if (!pubkey2) {
    SILC_LOG_DEBUG(("Copying public key failed"));
    goto err;
  }
  silc_pkcs_public_key_free(pubkey);
  SILC_LOG_DEBUG(("Load public key"));
  if (!silc_pkcs_load_public_key("publickey.pub", &pubkey,
				 SILC_PKCS_FILE_PEM)) {
    SILC_LOG_DEBUG(("Load public key failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Comparing copied and loaded public keys"));
  if (!silc_pkcs_public_key_compare(pubkey, pubkey2)) {
    SILC_LOG_DEBUG(("Comparing copied and loaded public keys failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Match"));
  SILC_LOG_DEBUG(("Set public key to PKCS"));
  if (!silc_pkcs_public_key_set(pkcs, pubkey)) {
    SILC_LOG_DEBUG(("Set public key to PKCS"));
    goto err;
  }
  SILC_LOG_DEBUG(("Encoding public key payload"));
  buf = silc_pkcs_public_key_payload_encode(pubkey);
  if (!buf) {
    SILC_LOG_DEBUG(("Encoding public key payload failed"));
    goto err;
  }
  silc_pkcs_public_key_free(pubkey2);
  SILC_LOG_DEBUG(("Decoding public key payload"));
  if (!silc_pkcs_public_key_payload_decode(buf->data, buf->len, &pubkey2)) {
    SILC_LOG_DEBUG(("Decoding public key payload failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Comparing decoded and original public keys"));
  if (!silc_pkcs_public_key_compare(pubkey2, pubkey)) {
    SILC_LOG_DEBUG(("Comparing decoded and original public keys failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Match"));
  SILC_LOG_DEBUG(("Dumping public key identifier"));
  silc_show_public_key("publickey.pub");
  unlink("publickey.pub");
  silc_free(pk);
  silc_free(identifier);
  silc_pkcs_free_identifier(ident);
  silc_pkcs_public_key_free(pubkey);
  silc_pkcs_public_key_free(pubkey2);


  SILC_LOG_DEBUG(("------"));
  SILC_LOG_DEBUG(("------ Testing Private Key Routines"));
  SILC_LOG_DEBUG(("------"));

  SILC_LOG_DEBUG(("Get private key from PKCS"));
  prv = silc_pkcs_get_private_key(pkcs, &prv_len);
  if (!prv || !prv_len) {
    SILC_LOG_DEBUG(("Getting private key failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Allocating SilcPrivateKey"));
  privkey = silc_pkcs_private_key_alloc("rsa", prv, prv_len);
  if (!privkey) {
    SILC_LOG_DEBUG(("Allocating SilcPrivateKey failed"));
    goto err;
  }
  silc_free(prv);
  SILC_LOG_DEBUG(("Encode SilcPrivateKey data"));
  prv = silc_pkcs_private_key_encode(privkey, &prv_len);
  if (!prv) {
    SILC_LOG_DEBUG(("Encode SilcPrivateKey data failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decode private key to SilcPrivateKey"));
  if (!silc_pkcs_private_key_decode(prv, prv_len, &privkey)) {
    SILC_LOG_DEBUG(("Decode private key to SilcPrivateKey failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Save private key to privkey.prv"));
  unlink("privkey.prv");
  if (!silc_pkcs_save_private_key("privkey.prv", privkey,
				  "foobar", 6,
				  SILC_PKCS_FILE_BIN)) {
    SILC_LOG_DEBUG(("Save private key to priv.pub failed"));
    goto err;
  }
  silc_pkcs_private_key_free(privkey);
  SILC_LOG_DEBUG(("Load private key"));
  if (!silc_pkcs_load_private_key("privkey.prv", &privkey, "foobar", 6,
				  SILC_PKCS_FILE_BIN)) {
    SILC_LOG_DEBUG(("Load private key failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Set private key to PKCS"));
  if (!silc_pkcs_private_key_set(pkcs, privkey)) {
    SILC_LOG_DEBUG(("Set private key to PKCS"));
    goto err;
  }
  unlink("privkey.prv");
  silc_free(prv);
  silc_pkcs_private_key_free(privkey);


  SILC_LOG_DEBUG(("------"));
  SILC_LOG_DEBUG(("------ Testing Public Key Cryptography Operations"));
  SILC_LOG_DEBUG(("------"));

  memset(d, 0, sizeof(d));
  memset(d2, 0, sizeof(d2));

  SILC_LOG_DEBUG(("Encrypting data"));
  if (!silc_pkcs_encrypt(pkcs, (unsigned char *)p, p_len, d, &dlen)) {
    SILC_LOG_DEBUG(("Encrypting data failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decrypting data"));
  if (!silc_pkcs_decrypt(pkcs, d, dlen, d2, &d2len)) {
    SILC_LOG_DEBUG(("Decrypting data failed"));
    goto err;
  }
  SILC_LOG_HEXDUMP(("Plaintext"), p, p_len);
  SILC_LOG_HEXDUMP(("Ciphertext"), d, dlen);
  SILC_LOG_HEXDUMP(("Decrypted"), d2, d2len);
  if (memcmp(p, d2, p_len)) {
    SILC_LOG_DEBUG(("Decryption failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Decryption successful"));
  memset(d, 0, sizeof(d));
  memset(d2, 0, sizeof(d2));

  SILC_LOG_DEBUG(("Signing data"));
  if (!silc_pkcs_sign(pkcs, (unsigned char *)p, p_len, d, &dlen)) {
    SILC_LOG_DEBUG(("Signing data failed"));
    goto err;
  }
  SILC_LOG_HEXDUMP(("Data"), p, p_len);
  SILC_LOG_HEXDUMP(("signature"), d, dlen);
  SILC_LOG_DEBUG(("Verifying data"));
  if (!silc_pkcs_verify(pkcs, d, dlen, (unsigned char *)p, p_len)) {
    SILC_LOG_DEBUG(("Verifying data failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Verification successful"));

  silc_hash_alloc("sha1", &sha1);
  SILC_LOG_DEBUG(("Signing data with hash"));
  if (!silc_pkcs_sign_with_hash(pkcs, sha1, (unsigned char *)p, p_len,
				d, &dlen)) {
    SILC_LOG_DEBUG(("Signing data with hash failed"));
    goto err;
  }
  SILC_LOG_HEXDUMP(("Data"), p, p_len);
  SILC_LOG_HEXDUMP(("signature"), d, dlen);
  SILC_LOG_DEBUG(("Verifying data with hash"));
  if (!silc_pkcs_verify_with_hash(pkcs, sha1, d, dlen,
				  (unsigned char *)p, p_len)) {
    SILC_LOG_DEBUG(("Verifying data with hash failed"));
    goto err;
  }
  SILC_LOG_DEBUG(("Verification with hash successful"));
  silc_hash_free(sha1);

  silc_pkcs_free(pkcs);
  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}

int main(int argc, char **argv)
{
  int success;
  int i;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*crypt*,*pkcs*,*rsa*,*primegen*");
  }
  silc_hash_register_default();
  silc_hmac_register_default();
  silc_cipher_register_default();
  silc_rng_global_init(NULL);

  success = test();

  for (i = 0; i < 100; i++) {
    success = test();
    if (!success)
      break;
  }

  silc_pkcs_unregister_all();
  silc_hash_unregister_all();
  silc_hmac_unregister_all();
  silc_cipher_unregister_all();

  return success;
}
