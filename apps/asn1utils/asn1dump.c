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
SilcBool parse_all = FALSE;
SilcBool ignore_header = FALSE;

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

int asn1_dump(SilcAsn1 asn1, SilcBuffer src, int depth)
{
  SilcBool ret = FALSE;
  SilcBerEncoding renc;
  SilcUInt32 rtag;
  const unsigned char *rdata;
  SilcBufferStruct buf;
  SilcBerClass rclass;
  SilcUInt32 rdata_len, len = 0;
  SilcBool rindef;
  char indent[256];

  memset(indent, 0, sizeof(indent));

  while (silc_buffer_len(src)) {
    /* Decode the BER block */
    ret = silc_ber_decode(src, &rclass, &renc, &rtag, &rdata,
			  &rdata_len, &rindef, &len);
    if (!ret) {
      fprintf(stderr, "Error: Cannot parse BER block, malformed ASN.1 data\n");
      return -1;
    }

    /* If class is 0, encoding 0, tag 0 and data length 0 ignore them
       as they are zero bytes, unless user wants to see them */
    if (rclass == 0 && renc == 0 && rtag == 0 && rdata_len == 0 &&
	!parse_all) {
      if (len && silc_buffer_len(src) >= len)
	silc_buffer_pull(src, len);
      continue;
    }

    if (depth)
      memset(indent, 32, depth);

    fprintf(stdout, "%04d: %s%s [%d] %s %s %s", depth, indent,
	    asn1_tag_name(rtag), (int)rtag,
	    rclass == SILC_BER_CLASS_UNIVERSAL   ? "univ" :
	    rclass == SILC_BER_CLASS_APPLICATION ? "appl" :
	    rclass == SILC_BER_CLASS_CONTEXT     ? "cont" : "priv",
	    renc == SILC_BER_ENC_PRIMITIVE ? "primit" : "constr",
	    rindef ? "indef" : "defin");

    if (rtag != SILC_ASN1_TAG_SEQUENCE &&
	rtag != SILC_ASN1_TAG_SET &&
	rtag != SILC_ASN1_TAG_SEQUENCE_OF) {
      if (hexdump) {
	fprintf(stdout, " [len %lu]\n", rdata_len);
	silc_hexdump(rdata, rdata_len, stdout);
      } else {
	fprintf(stdout, "\n");
      }
    } else {
      fprintf(stdout, "\n");
    }

    if (renc == SILC_BER_ENC_PRIMITIVE)
      len = len + rdata_len;
    else
      len = len;

    if (len && silc_buffer_len(src) >= len)
      silc_buffer_pull(src, len);

    /* Decode sequences and sets recursively */
    if ((rtag == SILC_ASN1_TAG_SEQUENCE ||
	 rtag == SILC_ASN1_TAG_SET ||
	 rtag == SILC_ASN1_TAG_SEQUENCE_OF) &&
	depth + 1 < sizeof(indent) - 1) {
      silc_buffer_set(&buf, (unsigned char *)rdata, rdata_len);
      if (silc_buffer_len(src) >= rdata_len)
	silc_buffer_pull(src, rdata_len);
      if (asn1_dump(asn1, &buf, depth + 1) < 0)
	return -1;
      if (silc_buffer_len(src) == 0)
	return 0;
    }
  }

  return 0;
}

void usage(void)
{
    fprintf(stdout, ""
"Usage: asn1dump [OPTIONS] FILE\n"
"\n"
"Operation modes:\n"
"  -h        Print this help, then exit\n"
"  -x        HEX dump ASN.1 data\n"
"  -b        Remove Base64 encoding before parsing\n"
"  -i        Remove file header/footer that has at least four '-' characters\n"
"  -a        Parse all data, including possible trailing zeroes\n"
"\n"
"ASN.1 classes:\n"
"  univ      Universal\n"
"  appl      Application\n"
"  cont      Context\n"
"  priv      Private\n"
"\n"
"ASN.1 length types:\n"
"  defin     Definitive\n"
"  indef     Indefinitive\n"
"\n"
"ASN.1 encoding types:\n"
"  primit    Primitive\n"
"  constr    Constructed\n"
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

  while ((opt = getopt(argc, argv, "hxbai")) != EOF) {
    switch (opt) {
    case 'h':
      usage();
      return 1;
      break;

    case 'x':
      hexdump = TRUE;
      break;

    case 'b':
      dec_base64 = TRUE;
      break;

    case 'i':
      ignore_header = TRUE;
      break;

    case 'a':
      parse_all = TRUE;
      break;

    default:
      usage();
      return 1;
    }
  }

  data = tmp = silc_file_readfile(argv[argc - 1], &data_len, NULL);
  if (!data) {
    fprintf(stderr, "Error: Cannot read file '%s': %s\n", argv[argc - 1],
	    strerror(errno));
    return 1;
  }

  silc_buffer_set(&buf, data, data_len);

  if (ignore_header) {
    SilcBool header = FALSE;
    for (i = 0; i < data_len; i++) {
      if (data_len > i + 4 &&
	  data[i    ] == '-' && data[i + 1] == '-' &&
	  data[i + 2] == '-' && data[i + 3] == '-') {

	if (data_len > i + 5 && (data[i + 4] == '\r' ||
				 tmp[i + 4] == '\n')) {
	  /* End of line, header */
	  if (data_len > i + 6 && data[i + 4] == '\r' &&
	      data[i + 5] == '\n')
	    i++;
	  i += 5;
	  silc_buffer_pull(&buf, i);
	  header = TRUE;
	} else if (i > 0 && data_len > i + 5 && data[i + 4] != '-' &&
		   header) {
	  /* Start of line, footer */
	  silc_buffer_push_tail(&buf, silc_buffer_truelen(&buf) - i);
	  break;
	}
      }
    }
  }

  if (dec_base64) {
    data = silc_base64_decode(NULL, silc_buffer_data(&buf),
			      silc_buffer_len(&buf), &data_len);
    if (!data) {
      fprintf(stderr, "Error: Cannot decode Base64 encoding\n");
      return 1;
    }
    silc_buffer_set(&buf, data, data_len);
    silc_free(tmp);
  }

  asn1 = silc_asn1_alloc(NULL);

  ret = asn1_dump(asn1, &buf, 0);

  silc_asn1_free(asn1);
  silc_free(data);

  return ret;
}
