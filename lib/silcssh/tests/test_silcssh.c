/* SILC SSH2 library tests */

#include "silc.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcRng rng;
  SilcPublicKey public_key;
  SilcPrivateKey private_key;
  SilcSshPublicKey ssh_pubkey;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*ssh*,*pkcs1*,*asn1*,*rsa*,*dsa*");
  }

  silc_crypto_init(NULL);
  rng = silc_rng_alloc();
  silc_rng_init(rng);

  SILC_LOG_DEBUG(("Generate key pair"));
  silc_ssh_generate_key("dsa", 1024, rng, "foo@example.com",
			&public_key, &private_key);

  SILC_LOG_DEBUG(("Set SSH2 public key headers"));
  ssh_pubkey = silc_pkcs_public_key_get_pkcs(SILC_PKCS_SSH2, public_key);
  silc_ssh_public_key_set_type(ssh_pubkey, SILC_SSH_KEY_SSH2);
  silc_ssh_public_key_add_field(ssh_pubkey, "Comment", "My own key");

  SILC_LOG_DEBUG(("Save public and private key"));
  if (!silc_pkcs_save_public_key("pubkey.pub", public_key,
				 SILC_PKCS_FILE_BASE64))
    goto err;
  if (!silc_pkcs_save_private_key("privkey.prv", private_key, "testi", 5,
       	                          SILC_PKCS_FILE_BASE64, rng))
    goto err;

  SILC_LOG_DEBUG(("Load public key"));
  if (!silc_pkcs_load_public_key("pubkey.pub", SILC_PKCS_ANY,  &public_key))
    goto err;
  ssh_pubkey = silc_pkcs_public_key_get_pkcs(SILC_PKCS_SSH2, public_key);
  SILC_LOG_DEBUG(("Subject: '%s'",
		  silc_ssh_public_key_get_field(ssh_pubkey, "Subject")));
  SILC_LOG_DEBUG(("Comment: '%s'",
		  silc_ssh_public_key_get_field(ssh_pubkey, "Comment")));

  SILC_LOG_DEBUG(("Load private key"));
  if (!silc_pkcs_load_private_key("privkey.prv", "testi", 5,
			     	  SILC_PKCS_ANY, &private_key))
    goto err;

  SILC_LOG_DEBUG(("Save as OpenSSH public key"));
  ssh_pubkey = silc_pkcs_public_key_get_pkcs(SILC_PKCS_SSH2, public_key);
  silc_ssh_public_key_set_type(ssh_pubkey, SILC_SSH_KEY_OPENSSH);
  if (!silc_pkcs_save_public_key("pubkey_openssh.pub", public_key,
				 SILC_PKCS_FILE_BASE64))
    goto err;

  SILC_LOG_DEBUG(("Load public key"));
  if (!silc_pkcs_load_public_key("pubkey_openssh.pub", SILC_PKCS_SSH2,
				 &public_key))
    goto err;

  silc_rng_free(rng);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
