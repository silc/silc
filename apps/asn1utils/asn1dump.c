/*

  asn1dump.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"

SilcBool hexdump = FALSE;
SilcBool dec_base64 = FALSE;

const char *asn1_tag_name(SilcAsn1Tag tag)
{
  switch (tag) {
  case SILC_ASN1_TAG_CHOICE:
    return "choice";
  case SILC_ASN1_TAG_ANY:
    return "any";
  case SILC_ASN1_TAG_ANY_PRIMITIVE:
    return "any primitive";
  case SILC_ASN1_TAG_SEQUENCE_OF:
    return "sequence of";
  case SILC_ASN1_TAG_SEQUENCE:
    return "sequence";
  case SILC_ASN1_TAG_SET:
    return "set";
  case SILC_ASN1_TAG_INTEGER:
    return "integer";
  case SILC_ASN1_TAG_SHORT_INTEGER:
    return "short integer";
  case SILC_ASN1_TAG_OID:
    return "oid";
  case SILC_ASN1_TAG_BOOLEAN:
    return "boolean";
  case SILC_ASN1_TAG_OCTET_STRING:
    return "octet-string";
  case SILC_ASN1_TAG_BIT_STRING:
    return "bit-string";
  case SILC_ASN1_TAG_NULL:
    return "null";
  case SILC_ASN1_TAG_ENUM:
    return "enum";
  case SILC_ASN1_TAG_UTC_TIME:
    return "utc-time";
  case SILC_ASN1_TAG_GENERALIZED_TIME:
    return "generalized-time";
  case SILC_ASN1_TAG_UTF8_STRING:
    return "utf8-string";
  case SILC_ASN1_TAG_NUMERIC_STRING:
    return "numeric-string";
  case SILC_ASN1_TAG_PRINTABLE_STRING:
    return "printable-string";
  case SILC_ASN1_TAG_IA5_STRING:
    return "ia5-string";
  case SILC_ASN1_TAG_VISIBLE_STRING:
    return "visible-string";
  case SILC_ASN1_TAG_UNIVERSAL_STRING:
    return "universal-string";
  case SILC_ASN1_TAG_UNRESTRICTED_STRING:
    return "unrestricted-string";
  case SILC_ASN1_TAG_BMP_STRING:
    return "bmp-string";
  case SILC_ASN1_TAG_ODE:
    return "ode";
  case SILC_ASN1_TAG_ETI:
    return "eti";
  case SILC_ASN1_TAG_REAL:
    return "real";
  case SILC_ASN1_TAG_EMBEDDED:
    return "embedded";
  case SILC_ASN1_TAG_ROI:
    return "roi";
  case SILC_ASN1_TAG_TELETEX_STRING:
    return "teletex-string";
  case SILC_ASN1_TAG_VIDEOTEX_STRING:
    return "videotex-string";
  case SILC_ASN1_TAG_GRAPHIC_STRING:
    return "graphic-string";
  case SILC_ASN1_TAG_GENERAL_STRING:
    return "general-string";
  default:
    break;
  }
  return "unknown";
}

int asn1_dump(SilcAsn1 asn1, SilcBuffer src)
{
  SilcBool ret = FALSE;
  SilcBerEncoding renc;
  SilcUInt32 rtag;
  const unsigned char *rdata;
  SilcUInt32 rdata_len, len = 0;
  SilcBool rindef;
  char indent[256];
  int depth = 0;

  SILC_LOG_DEBUG(("Dumping ASN.1"));
  memset(indent, 0, sizeof(indent));

  while (silc_buffer_len(src)) {
    /* Decode the BER block */
    ret = silc_ber_decode(src, NULL, &renc, &rtag, &rdata,
			  &rdata_len, &rindef, &len);
    if (!ret) {
      fprintf(stderr, "Error: Cannot parse BER block, malformed ASN.1 data");
      return -1;
    }

    memset(indent, 32, depth);

    fprintf(stdout, "%04d: %s[%s] [%d]", depth, indent,
	    asn1_tag_name(rtag), (int)rtag);

    if (rtag != SILC_ASN1_TAG_SEQUENCE) {
      if (hexdump) {
	fprintf(stdout, " [length %lu]\n", rdata_len);
	silc_hexdump(rdata, rdata_len, stdout);
      } else {
	fprintf(stdout, "\n");
      }
    } else {
      fprintf(stdout, "\n");
    }

    if (rtag == SILC_ASN1_TAG_SEQUENCE && depth < sizeof(indent))
      depth++;

    if (renc == SILC_BER_ENC_PRIMITIVE)
      len = len + rdata_len;
    else
      len = len;

    if (len)
      silc_buffer_pull(src, len);
  }

  return 0;
}

void usage(void)
{
    fprintf(stdout, ""
"Usage: asn1dump [OPTIONS] FILE\n"
"\n"
"Operation modes:\n"
"  -h          Print this help, then exit\n"
"  -x          HEX dump ASN.1 data\n"
"  -b          Decode Base64 encoding\n"
"\n"
	    );
}

int main(int argc, char **argv)
{
  int opt, ret, i;
  SilcAsn1 asn1;
  SilcBufferStruct buf;
  unsigned char *data, *tmp;
  SilcUInt32 data_len;

  if (argc < 2) {
    usage();
    return 1;
  }

  i = 1;
  while ((opt = getopt(argc, argv, "hxb")) != EOF) {
    switch (opt) {
    case 'h':
      usage();
      return 1;
      break;

    case 'x':
      hexdump = TRUE;
      i++;
      break;

    case 'b':
      dec_base64 = TRUE;
      i++;
      break;

    default:
      usage();
      return 1;
    }
  }

  data = tmp = silc_file_readfile(argv[i], &data_len, NULL);
  if (!data) {
    fprintf(stderr, "Error: Cannot read file '%s': %s", argv[i],
	    strerror(errno));
    return 1;
  }

  if (dec_base64) {
    data = silc_base64_decode(NULL, data, data_len, &data_len);
    if (!data) {
      fprintf(stderr, "Error: Cannot decode Base64 encoding\n");
      return 1;
    }
    silc_free(tmp);
  }

  silc_buffer_set(&buf, data, data_len);

  asn1 = silc_asn1_alloc(NULL);

  ret = asn1_dump(asn1, &buf);

  silc_asn1_free(asn1);
  silc_free(data);

  return ret;
}
