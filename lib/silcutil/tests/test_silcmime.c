/* SilcMime tests */

#include "silc.h"
#include "silcmime.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcMime mime, part, part2;
  SilcMimeAssembler ass;
  int i;
  char tmp[500];
  unsigned char *enc;
  SilcUInt32 enc_len;
  SilcDList frag;
  SilcBuffer buf;
  const char *mtype;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*mime*");
  }

  /* 
   * Simple MIME test
   */
  SILC_LOG_DEBUG(("Allocating MIME message context"));
  mime = silc_mime_alloc();
  if (!mime)
    goto err;
  SILC_LOG_DEBUG(("Adding MIME fields"));
  SILC_LOG_DEBUG(("Adding MIME-Version: 1.0"));
  silc_mime_add_field(mime, "MIME-Version", "1.0");
  SILC_LOG_DEBUG(("Adding Content-Type: foo/bar"));
  silc_mime_add_field(mime, "Content-Type", "foo/bar");
  SILC_LOG_DEBUG(("Adding Content-Transfer-Encoding: binary"));
  silc_mime_add_field(mime, "Content-Transfer-Encoding", "binary");
  SILC_LOG_DEBUG(("Adding FOO: BaR"));
  silc_mime_add_field(mime, "FOO", "BaR");
  SILC_LOG_DEBUG(("Adding MIME data, 100 A's + 1 B"));
  for (i = 0; i < 100; i++)
    tmp[i] = 'A';
  tmp[100] = 'B';
  silc_mime_add_data(mime, tmp, 101);
  SILC_LOG_DEBUG(("Encoding MIME context"));
  enc = silc_mime_encode(mime, &enc_len);
  if (!enc)
    goto err;
  SILC_LOG_DEBUG(("Encoded MIME message: \n%s", enc));
  silc_mime_free(mime);
  SILC_LOG_DEBUG(("Decoding MIME message"));
  mime = silc_mime_decode(NULL, enc, enc_len);
  if (!mime)
    goto err;
  SILC_LOG_DEBUG(("Re-encoding MIME context"));
  silc_free(enc);
  enc = silc_mime_encode(mime, &enc_len);
  if (!enc)
    goto err;
  SILC_LOG_DEBUG(("Re-encoded MIME message: \n%s", enc));
  silc_free(enc);
  silc_mime_free(mime);

  /*
   * Empty data area, only headers present
   */
  SILC_LOG_DEBUG(("Allocating MIME message context"));
  mime = silc_mime_alloc();
  if (!mime)
    goto err;
  SILC_LOG_DEBUG(("Adding Content-Transfer-Encoding: binary"));
  silc_mime_add_field(mime, "Content-Transfer-Encoding", "binary");
  SILC_LOG_DEBUG(("No data area, only header present"));
  SILC_LOG_DEBUG(("Encoding MIME context"));
  enc = silc_mime_encode(mime, &enc_len);
  if (!enc)
    goto err;
  SILC_LOG_DEBUG(("Encoded MIME message: \n%s", enc));
  silc_mime_free(mime);
  SILC_LOG_DEBUG(("Decoding MIME message"));
  mime = silc_mime_decode(NULL, enc, enc_len);
  if (!mime)
    goto err;
  SILC_LOG_DEBUG(("Re-encoding MIME context"));
  silc_free(enc);
  enc = silc_mime_encode(mime, &enc_len);
  if (!enc)
    goto err;
  SILC_LOG_HEXDUMP(("Re-encoded MIME message:"), enc, enc_len);
  silc_free(enc);
  silc_mime_free(mime);

  /*
   * Multipart test, with nesting
   */
  SILC_LOG_DEBUG(("Allocating MIME message context"));
  mime = silc_mime_alloc();
  if (!mime)
    goto err;
  SILC_LOG_DEBUG(("Adding MIME-Version: 1.0"));
  silc_mime_add_field(mime, "MIME-Version", "1.0");
  SILC_LOG_DEBUG(("Adding Content-Transfer-Encoding: binary"));
  silc_mime_add_field(mime, "Content-Transfer-Encoding", "binary");
  SILC_LOG_DEBUG(("Marking as multipart MIME message"));
  silc_mime_set_multipart(mime, "mixed", "boundary");
  SILC_LOG_DEBUG(("Adding FOO: BaR"));
  silc_mime_add_field(mime, "FOO", "BaR");
  SILC_LOG_DEBUG(("Allocating part"));
  part = silc_mime_alloc();
  if (!part)
    goto err;
  SILC_LOG_DEBUG(("Adding MIME fields"));
  SILC_LOG_DEBUG(("Adding Content-Type: foo/bar"));
  silc_mime_add_field(part, "Content-Type", "foo/bar");
  SILC_LOG_DEBUG(("Adding MIME data, 100 A's + 1 B"));
  for (i = 0; i < 100; i++)
    tmp[i] = 'A';
  tmp[100] = 'B';
  silc_mime_add_data(part, tmp, 101);
  SILC_LOG_DEBUG(("Adding part to MIME message"));
  if (!silc_mime_add_multipart(mime, part))
    goto err;
  SILC_LOG_DEBUG(("Allocating part"));
  part = silc_mime_alloc();
  if (!part)
    goto err;
  SILC_LOG_DEBUG(("Adding Content-Type: image/foobar"));
  silc_mime_add_field(part, "Content-Type", "image/foobar");
  SILC_LOG_DEBUG(("Adding MIME data, 50 A's + 1 B"));
  for (i = 0; i < 50; i++)
    tmp[i] = 'A';
  tmp[50] = 'B';
  silc_mime_add_data(part, tmp, 51);
  SILC_LOG_DEBUG(("Adding part to MIME message"));
  if (!silc_mime_add_multipart(mime, part))
    goto err;
  SILC_LOG_DEBUG(("Allocating part"));
  part = silc_mime_alloc();
  if (!part)
    goto err;
  SILC_LOG_DEBUG(("Adding MIME data (NO HEADERS), 10 A's + 1 B"));
  for (i = 0; i < 10; i++)
    tmp[i] = 'A';
  tmp[10] = 'B';
  silc_mime_add_data(part, tmp, 11);
  SILC_LOG_DEBUG(("Adding part to MIME message"));
  if (!silc_mime_add_multipart(mime, part))
    goto err;
  SILC_LOG_DEBUG(("Allocating part"));
  part = silc_mime_alloc();
  if (!part)
    goto err;
  SILC_LOG_DEBUG(("Adding Content-Type: image/foobar"));
  SILC_LOG_DEBUG(("No data area, only header"));
  silc_mime_add_field(part, "Content-Type", "image/foobar");
  SILC_LOG_DEBUG(("Adding part to MIME message"));
  if (!silc_mime_add_multipart(mime, part))
    goto err;
  SILC_LOG_DEBUG(("Allocating part"));
  part = silc_mime_alloc();
  if (!part)
    goto err;
  SILC_LOG_DEBUG(("Adding part to MIME message"));
  if (!silc_mime_add_multipart(mime, part))
    goto err;
  silc_mime_set_multipart(part, "mixed", "booooooooundary");
  SILC_LOG_DEBUG(("Allocating part for nested multipart"));
  part2 = silc_mime_alloc();
  if (!part)
    goto err;
  SILC_LOG_DEBUG(("Adding Content-Type: foo/nested"));
  silc_mime_add_field(part2, "Content-Type", "foo/nested");
  SILC_LOG_DEBUG(("Adding MIME data, 150 A's + 1 B"));
  for (i = 0; i < 150; i++)
    tmp[i] = 'A';
  tmp[150] = 'B';
  silc_mime_add_data(part2, tmp, 151);
  SILC_LOG_DEBUG(("Adding part to another part message"));
  if (!silc_mime_add_multipart(part, part2))
    goto err;
  SILC_LOG_DEBUG(("Encoding MIME context"));
  enc = silc_mime_encode(mime, &enc_len);
  if (!enc)
    goto err;
  SILC_LOG_DEBUG(("Encoded MIME message: \n%s", enc));
  silc_mime_free(mime);
  SILC_LOG_DEBUG(("Decoding MIME message"));
  mime = silc_mime_decode(NULL, enc, enc_len);
  if (!mime)
    goto err;
  SILC_LOG_DEBUG(("Re-encoding MIME context"));
  silc_free(enc);
  enc = silc_mime_encode(mime, &enc_len);
  if (!enc)
    goto err;
  SILC_LOG_DEBUG(("Re-encoded MIME message: \n%s", enc));
  silc_free(enc);
  SILC_LOG_DEBUG(("Get multiparts"));
  frag = silc_mime_get_multiparts(mime, &mtype);
  if (!frag)
    goto err;
  SILC_LOG_DEBUG(("Multipart type '%s'", mtype));
  silc_dlist_start(frag);
  while ((part = silc_dlist_get(frag)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("Encoding MIME part"));
    enc = silc_mime_encode(part, &enc_len);
    if (!enc)
	 goto err;
    if (silc_mime_is_multipart(part))
	 SILC_LOG_DEBUG(("Is multipart"));
    SILC_LOG_DEBUG(("Encoded MIME part: \n%s", enc));
    silc_free(enc);
  }
  silc_mime_free(mime);

  /*
   * Fragmentation test
   */
  SILC_LOG_DEBUG(("Allocating MIME assembler"));
  ass = silc_mime_assembler_alloc();
  if (!ass)
    goto err;
  SILC_LOG_DEBUG(("Allocating MIME message context"));
  mime = silc_mime_alloc();
  if (!mime)
    goto err;
  SILC_LOG_DEBUG(("Adding MIME fields"));
  SILC_LOG_DEBUG(("Adding MIME-Version: 1.0"));
  silc_mime_add_field(mime, "MIME-Version", "1.0");
  SILC_LOG_DEBUG(("Adding Content-Type: foo/bar"));
  silc_mime_add_field(mime, "Content-Type", "foo/bar");
  SILC_LOG_DEBUG(("Adding Content-Transfer-Encoding: binary"));
  silc_mime_add_field(mime, "Content-Transfer-Encoding", "binary");
  SILC_LOG_DEBUG(("Adding FOO: BaR"));
  silc_mime_add_field(mime, "FOO", "BaR");
  SILC_LOG_DEBUG(("Adding MIME data, 300 A's + 1 B"));
  for (i = 0; i < 300; i++)
    tmp[i] = 'A';
  tmp[300] = 'B';
  silc_mime_add_data(mime, tmp, 301);
  SILC_LOG_DEBUG(("Encoding MIME context"));
  enc = silc_mime_encode(mime, &enc_len);
  if (!enc)
    goto err;
  SILC_LOG_DEBUG(("Encoded MIME message: \n%s", enc));
  silc_free(enc);
  SILC_LOG_DEBUG(("Fragment MIME message in 100 byte chunks"));
  frag = silc_mime_encode_partial(mime, 100);
  if (!frag)
    goto err;
  silc_dlist_start(frag);
  while ((buf = silc_dlist_get(frag)) != SILC_LIST_END)
    SILC_LOG_DEBUG(("Fragment \n%s", buf->data, silc_buffer_len(buf)));
  SILC_LOG_DEBUG(("Defragment"));
  silc_dlist_start(frag);
  while ((buf = silc_dlist_get(frag)) != SILC_LIST_END) {
    part = silc_mime_decode(NULL, buf->data, silc_buffer_len(buf));
    if (!silc_mime_is_partial(part))
	 goto err;
    part = silc_mime_assemble(ass, part);
    if (part) {
      SILC_LOG_DEBUG(("Defragmentation completed"));
      SILC_LOG_DEBUG(("Encoding MIME context"));
      enc = silc_mime_encode(mime, &enc_len);
      if (!enc)
        SILC_LOG_DEBUG(("Error encoding"));
      SILC_LOG_DEBUG(("Encoded MIME message: \n%s", enc));
      silc_free(enc);
    }
  }
  silc_mime_partial_free(frag);
  silc_mime_assembler_free(ass);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
