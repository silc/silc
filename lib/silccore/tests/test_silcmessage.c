/* SILC Message Payload tests */

#include "silc.h"
#include "silcapputil.h"

SilcPublicKey public_key, pk2;
SilcPrivateKey private_key;
SilcCipher key;
SilcHash hash;
SilcHmac hmac;
SilcRng rng;

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcMessagePayload message;
  SilcBuffer buf;
  const char *msg = "FOOBAR MESSAGE";
  unsigned char *data, tmp[1023], *tmp2;
  SilcUInt32 data_len;
  SilcUInt16 flags;
  int i, n;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*message*");
  }

  silc_cipher_register_default();
  silc_hash_register_default();
  silc_hmac_register_default();
  silc_pkcs_register_default();

  SILC_LOG_DEBUG(("Load keypair"));
  if (!silc_load_key_pair("pubkey.pub", "privkey.prv", "",
			  &public_key, &private_key)) {
    SILC_LOG_DEBUG(("Create keypair"));
    if (!silc_create_key_pair("rsa", 2048, "pubkey.pub", "privkey.prv",
			      NULL, "", &public_key, &private_key, FALSE))
      goto err;
  }

  SILC_LOG_DEBUG(("Alloc RNG"));
  rng = silc_rng_alloc();
  silc_rng_init(rng);

  SILC_LOG_DEBUG(("Alloc AES"));
  if (!silc_cipher_alloc("aes-128-cbc", &key))
    goto err;

  SILC_LOG_DEBUG(("Alloc SHA-256"));
  if (!silc_hash_alloc("sha256", &hash))
    goto err;

  SILC_LOG_DEBUG(("Alloc HMAC"));
  if (!silc_hmac_alloc("hmac-sha256-96", hash, &hmac))
    goto err;

  SILC_LOG_DEBUG(("Set static key: '1234567890123456'"));
  if (!silc_cipher_set_key(key, "1234567890123456", 16 * 8))
    goto err;
  SILC_LOG_DEBUG(("Set HMAC key: '1234567890123456'"));
  silc_hmac_set_key(hmac, "1234567890123456", 16);

  /* Simple private message */
  SILC_LOG_DEBUG(("Encoding private message len %d (static key)",
		  strlen(msg)));
  buf = silc_message_payload_encode(SILC_MESSAGE_FLAG_ACTION |
				    SILC_MESSAGE_FLAG_UTF8 |
				    SILC_MESSAGE_FLAG_ACK,
				    msg, strlen(msg), TRUE, TRUE,
				    key, hmac, rng, NULL, NULL, NULL, NULL);
  if (!buf)
    goto err;
  SILC_LOG_HEXDUMP(("message"), buf->data, silc_buffer_len(buf));
  SILC_LOG_DEBUG(("Parsing private messsage (static key)"));
  message = silc_message_payload_parse(silc_buffer_data(buf),
				       silc_buffer_len(buf), TRUE, TRUE,
				       key, hmac, NULL, FALSE, NULL);
  if (!message)
    goto err;
  flags = silc_message_get_flags(message);
  SILC_LOG_DEBUG(("Flags: %x", flags));
  if (!(flags & SILC_MESSAGE_FLAG_ACTION))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_UTF8))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_ACK))
    goto err;
  data = silc_message_get_data(message, &data_len);
  SILC_LOG_HEXDUMP(("Data"), data, data_len);
  if (data_len != strlen(msg) || memcmp(data, msg, strlen(msg)))
    goto err;
  SILC_LOG_HEXDUMP(("MAC"), silc_message_get_mac(message),
		   silc_hmac_len(hmac));
  silc_message_payload_free(message);

  /* Simple private message */
  n = 10;
  SILC_LOG_DEBUG(("Encoding private message len %d (static key)", n));
  buf = silc_message_payload_encode(SILC_MESSAGE_FLAG_ACTION |
				    SILC_MESSAGE_FLAG_UTF8 |
				    SILC_MESSAGE_FLAG_ACK,
				    msg, n, TRUE, TRUE,
				    key, hmac, rng, NULL, NULL, NULL, buf);
  if (!buf)
    goto err;
  SILC_LOG_HEXDUMP(("message"), buf->data, silc_buffer_len(buf));
  SILC_LOG_DEBUG(("Parsing private messsage (static key)"));
  message = silc_message_payload_parse(silc_buffer_data(buf),
				       silc_buffer_len(buf), TRUE, TRUE,
				       key, hmac, NULL, FALSE, NULL);
  if (!message)
    goto err;
  flags = silc_message_get_flags(message);
  SILC_LOG_DEBUG(("Flags: %x", flags));
  if (!(flags & SILC_MESSAGE_FLAG_ACTION))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_UTF8))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_ACK))
    goto err;
  data = silc_message_get_data(message, &data_len);
  SILC_LOG_HEXDUMP(("Data"), data, data_len);
  if (data_len != n || memcmp(data, msg, n))
    goto err;
  SILC_LOG_HEXDUMP(("MAC"), silc_message_get_mac(message),
		   silc_hmac_len(hmac));
  silc_message_payload_free(message);

  /* Simple private message */
  n = 1;
  SILC_LOG_DEBUG(("Encoding private message len %d (static key)", n));
  buf = silc_message_payload_encode(SILC_MESSAGE_FLAG_ACTION |
				    SILC_MESSAGE_FLAG_UTF8 |
				    SILC_MESSAGE_FLAG_ACK,
				    msg, n, TRUE, TRUE,
				    key, hmac, rng, NULL, NULL, NULL, buf);
  if (!buf)
    goto err;
  SILC_LOG_HEXDUMP(("message"), buf->data, silc_buffer_len(buf));
  SILC_LOG_DEBUG(("Parsing private messsage (static key)"));
  message = silc_message_payload_parse(silc_buffer_data(buf),
				       silc_buffer_len(buf), TRUE, TRUE,
				       key, hmac, NULL, FALSE, NULL);
  if (!message)
    goto err;
  flags = silc_message_get_flags(message);
  SILC_LOG_DEBUG(("Flags: %x", flags));
  if (!(flags & SILC_MESSAGE_FLAG_ACTION))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_UTF8))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_ACK))
    goto err;
  data = silc_message_get_data(message, &data_len);
  SILC_LOG_HEXDUMP(("Data"), data, data_len);
  if (data_len != n || memcmp(data, msg, n))
    goto err;
  SILC_LOG_HEXDUMP(("MAC"), silc_message_get_mac(message),
		   silc_hmac_len(hmac));
  silc_message_payload_free(message);

  /* Simple private message */
  for (i = 0; i < sizeof(tmp); i++)
    tmp[i] = (32 + i) & 127;
  SILC_LOG_DEBUG(("Encoding private message len %d (static key)",
		  sizeof(tmp)));
  buf = silc_message_payload_encode(SILC_MESSAGE_FLAG_ACTION |
				    SILC_MESSAGE_FLAG_UTF8 |
				    SILC_MESSAGE_FLAG_ACK,
				    tmp, sizeof(tmp), TRUE, TRUE,
				    key, hmac, rng, NULL, NULL, NULL, buf);
  if (!buf)
    goto err;
  SILC_LOG_HEXDUMP(("message"), buf->data, silc_buffer_len(buf));
  SILC_LOG_DEBUG(("Parsing private messsage (static key)"));
  message = silc_message_payload_parse(silc_buffer_data(buf),
				       silc_buffer_len(buf), TRUE, TRUE,
				       key, hmac, NULL, FALSE, NULL);
  if (!message)
    goto err;
  flags = silc_message_get_flags(message);
  SILC_LOG_DEBUG(("Flags: %x", flags));
  if (!(flags & SILC_MESSAGE_FLAG_ACTION))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_UTF8))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_ACK))
    goto err;
  data = silc_message_get_data(message, &data_len);
  SILC_LOG_HEXDUMP(("Data"), data, data_len);
  if (data_len != sizeof(tmp) || memcmp(data, tmp, sizeof(tmp)))
    goto err;
  SILC_LOG_HEXDUMP(("MAC"), silc_message_get_mac(message),
		   silc_hmac_len(hmac));
  silc_message_payload_free(message);

  /* Digitally signed private message */
  for (i = 0; i < sizeof(tmp); i++)
    tmp[i] = (32 + i) & 127;
  SILC_LOG_DEBUG(("Encoding private message len %d (static key) SIGNED",
		  sizeof(tmp)));
  buf = silc_message_payload_encode(SILC_MESSAGE_FLAG_ACTION |
				    SILC_MESSAGE_FLAG_UTF8 |
				    SILC_MESSAGE_FLAG_ACK |
				    SILC_MESSAGE_FLAG_SIGNED,
				    tmp, sizeof(tmp), TRUE, TRUE,
				    key, hmac, rng,
				    public_key, private_key, hash, buf);
  if (!buf)
    goto err;
  SILC_LOG_HEXDUMP(("message"), buf->data, silc_buffer_len(buf));
  SILC_LOG_DEBUG(("Parsing private messsage (static key)"));
  message = silc_message_payload_parse(silc_buffer_data(buf),
				       silc_buffer_len(buf), TRUE, TRUE,
				       key, hmac, NULL, FALSE, NULL);
  if (!message)
    goto err;
  flags = silc_message_get_flags(message);
  SILC_LOG_DEBUG(("Flags: %x", flags));
  if (!(flags & SILC_MESSAGE_FLAG_ACTION))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_UTF8))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_ACK))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_SIGNED))
    goto err;
  data = silc_message_get_data(message, &data_len);
  SILC_LOG_HEXDUMP(("Data"), data, data_len);
  if (data_len != sizeof(tmp) || memcmp(data, tmp, sizeof(tmp)))
    goto err;
  SILC_LOG_HEXDUMP(("MAC"), silc_message_get_mac(message),
		   silc_hmac_len(hmac));
  SILC_LOG_DEBUG(("Verifying signature"));
  if (silc_message_signed_verify(message, public_key, hash) !=
      SILC_AUTH_OK)
    goto err;
  SILC_LOG_DEBUG(("Signature Ok"));
  SILC_LOG_DEBUG(("Get public key"));
  pk2 = silc_message_signed_get_public_key(message, NULL, NULL);
  if (!pk2)
    goto err;
  SILC_LOG_DEBUG(("Verify public key"));
  if (!silc_pkcs_public_key_compare(public_key, pk2))
    goto err;
  SILC_LOG_DEBUG(("Public key Ok"));
  silc_pkcs_public_key_free(pk2);
  silc_message_payload_free(message);

  /* Digitally signed channel message */
  for (i = 0; i < sizeof(tmp) / 2; i++)
    tmp[i] = (32 + i) & 127;
  SILC_LOG_DEBUG(("Encoding channel message len %d (static key) SIGNED",
		  sizeof(tmp) / 2));
  buf = silc_message_payload_encode(SILC_MESSAGE_FLAG_ACTION |
				    SILC_MESSAGE_FLAG_UTF8 |
				    SILC_MESSAGE_FLAG_ACK |
				    SILC_MESSAGE_FLAG_SIGNED,
				    tmp, sizeof(tmp) / 2, TRUE, FALSE,
				    key, hmac, rng,
				    public_key, private_key, hash, buf);
  if (!buf)
    goto err;
  SILC_LOG_HEXDUMP(("message"), buf->data, silc_buffer_len(buf));
  SILC_LOG_DEBUG(("Parsing channel messsage (static key)"));
  message = silc_message_payload_parse(silc_buffer_data(buf),
				       silc_buffer_len(buf), FALSE, TRUE,
				       key, hmac, NULL, FALSE, NULL);
  if (!message)
    goto err;
  flags = silc_message_get_flags(message);
  SILC_LOG_DEBUG(("Flags: %x", flags));
  if (!(flags & SILC_MESSAGE_FLAG_ACTION))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_UTF8))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_ACK))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_SIGNED))
    goto err;
  data = silc_message_get_data(message, &data_len);
  SILC_LOG_HEXDUMP(("Data"), data, data_len);
  if (data_len != sizeof(tmp) / 2 || memcmp(data, tmp, sizeof(tmp) / 2))
    goto err;
  SILC_LOG_HEXDUMP(("MAC"), silc_message_get_mac(message),
		   silc_hmac_len(hmac));
  SILC_LOG_DEBUG(("Verifying signature"));
  if (silc_message_signed_verify(message, public_key, hash) !=
      SILC_AUTH_OK)
    goto err;
  SILC_LOG_DEBUG(("Signature Ok"));
  SILC_LOG_DEBUG(("Get public key"));
  pk2 = silc_message_signed_get_public_key(message, NULL, NULL);
  if (!pk2)
    goto err;
  SILC_LOG_DEBUG(("Verify public key"));
  if (!silc_pkcs_public_key_compare(public_key, pk2))
    goto err;
  SILC_LOG_DEBUG(("Public key Ok"));
  silc_pkcs_public_key_free(pk2);
  silc_message_payload_free(message);

  /* Digitally signed private message (no encryption) */
  for (i = 0; i < sizeof(tmp) / 2; i++)
    tmp[i] = (32 + i) & 127;
  SILC_LOG_DEBUG(("Encoding private message len %d SIGNED",
		  sizeof(tmp) / 2));
  buf = silc_message_payload_encode(SILC_MESSAGE_FLAG_ACTION |
				    SILC_MESSAGE_FLAG_UTF8 |
				    SILC_MESSAGE_FLAG_ACK |
				    SILC_MESSAGE_FLAG_SIGNED,
				    tmp, sizeof(tmp) / 2, FALSE, TRUE,
				    NULL, NULL, rng,
				    public_key, private_key, hash, buf);
  if (!buf)
    goto err;
  SILC_LOG_HEXDUMP(("message"), buf->data, silc_buffer_len(buf));
  SILC_LOG_DEBUG(("Parsing private messsage (static key)"));
  message = silc_message_payload_parse(silc_buffer_data(buf),
				       silc_buffer_len(buf), TRUE, FALSE,
				       NULL, NULL, NULL, FALSE, NULL);
  if (!message)
    goto err;
  flags = silc_message_get_flags(message);
  SILC_LOG_DEBUG(("Flags: %x", flags));
  if (!(flags & SILC_MESSAGE_FLAG_ACTION))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_UTF8))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_ACK))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_SIGNED))
    goto err;
  data = silc_message_get_data(message, &data_len);
  SILC_LOG_HEXDUMP(("Data"), data, data_len);
  if (data_len != sizeof(tmp) / 2 || memcmp(data, tmp, sizeof(tmp) / 2))
    goto err;
  SILC_LOG_DEBUG(("Verifying signature"));
  if (silc_message_signed_verify(message, public_key, hash) !=
      SILC_AUTH_OK)
    goto err;
  SILC_LOG_DEBUG(("Signature Ok"));
  SILC_LOG_DEBUG(("Get public key"));
  pk2 = silc_message_signed_get_public_key(message, NULL, NULL);
  if (!pk2)
    goto err;
  SILC_LOG_DEBUG(("Verify public key"));
  if (!silc_pkcs_public_key_compare(public_key, pk2))
    goto err;
  SILC_LOG_DEBUG(("Public key Ok"));
  silc_pkcs_public_key_free(pk2);
  silc_message_payload_free(message);

  /* Digitally signed channel message (LARGE) */
  n = 65550;
  tmp2 = silc_malloc(n);
  if (!tmp2)
    goto err;
  SILC_LOG_DEBUG(("Encoding channel message len %d (static key) SIGNED LARGE",
		  n));
  buf = silc_message_payload_encode(SILC_MESSAGE_FLAG_ACTION |
				    SILC_MESSAGE_FLAG_UTF8 |
				    SILC_MESSAGE_FLAG_ACK |
				    SILC_MESSAGE_FLAG_SIGNED,
				    tmp2, n, TRUE, FALSE,
				    key, hmac, rng,
				    public_key, private_key, hash, buf);
  if (!buf)
    goto err;
  SILC_LOG_DEBUG(("Message length: %d", silc_buffer_len(buf)));
  if (silc_buffer_len(buf) > SILC_PACKET_MAX_LEN)
    goto err;
  SILC_LOG_DEBUG(("Parsing channel messsage (static key)"));
  message = silc_message_payload_parse(silc_buffer_data(buf),
				       silc_buffer_len(buf), FALSE, TRUE,
				       key, hmac, NULL, FALSE, NULL);
  if (!message)
    goto err;
  flags = silc_message_get_flags(message);
  SILC_LOG_DEBUG(("Flags: %x", flags));
  if (!(flags & SILC_MESSAGE_FLAG_ACTION))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_UTF8))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_ACK))
    goto err;
  if (!(flags & SILC_MESSAGE_FLAG_SIGNED))
    goto err;
  data = silc_message_get_data(message, &data_len);
  SILC_LOG_DEBUG(("Data len: %d", data_len));
  if (silc_buffer_len(buf) > SILC_PACKET_MAX_LEN)
    goto err;
  SILC_LOG_HEXDUMP(("MAC"), silc_message_get_mac(message),
		   silc_hmac_len(hmac));
  SILC_LOG_DEBUG(("Verifying signature"));
  if (silc_message_signed_verify(message, public_key, hash) !=
      SILC_AUTH_OK)
    goto err;
  SILC_LOG_DEBUG(("Signature Ok"));
  SILC_LOG_DEBUG(("Get public key"));
  pk2 = silc_message_signed_get_public_key(message, NULL, NULL);
  if (!pk2)
    goto err;
  SILC_LOG_DEBUG(("Verify public key"));
  if (!silc_pkcs_public_key_compare(public_key, pk2))
    goto err;
  SILC_LOG_DEBUG(("Public key Ok"));
  silc_pkcs_public_key_free(pk2);
  silc_message_payload_free(message);
  silc_free(tmp2);


  success = TRUE;
  SILC_LOG_DEBUG(("Cleanup"));
  silc_pkcs_public_key_free(public_key);
  silc_pkcs_private_key_free(private_key);
  silc_cipher_free(key);
  silc_hash_free(hash);
  silc_rng_free(rng);

 err:
  silc_cipher_unregister_all();
  silc_hash_unregister_all();
  silc_hmac_unregister_all();
  silc_pkcs_unregister_all();

  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
