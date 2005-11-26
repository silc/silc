#include "silcincludes.h"

/*
silc_asn1_encode(asn1, node,
		 SILC_ASN1_BOOLEAN(SilcBool),
		 SILC_ASN1_END);
silc_asn1_encode(asn1, dest,
		 SILC_ASN1_SEQUENCE_T(SILC_ASN1_PRIVATE, 101),
		   SILC_ASN1_SEQUENCE_T(0, 9),
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_ANY_T(0, 33, node),
		       SILC_ASN1_BOOLEAN_T(0, 4, boolv),
		       SILC_ASN1_BOOLEAN(SilcBool),
		     SILC_ASN1_END,
		   SILC_ASN1_END,
		 SILC_ASN1_END);

  FATAL ERROR: Adding primitive node with implicit tagging is not possible.
  The node either must be constructed (SEQUENCE or SET), or the tagging
  must be explicit (in which case end result is same).
*/


/*
silc_asn1_encode(asn1, node,
		 SILC_ASN1_BOOLEAN(SilcBool),
		 SILC_ASN1_END);
silc_asn1_encode(asn1, dest,
		 SILC_ASN1_SEQUENCE_T(SILC_ASN1_PRIVATE, 101),
		   SILC_ASN1_SEQUENCE_T(0, 9),
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_ANY_T(SILC_ASN1_EXPLICIT, 33, node),
		       SILC_ASN1_BOOLEAN_T(0, 4, boolv),
		       SILC_ASN1_BOOLEAN(SilcBool),
		     SILC_ASN1_END,
		   SILC_ASN1_END,
		 SILC_ASN1_END);

  CORRECT: the tagging is now explicit.  Also note that tagging primitive
  node explicitly is analougous of having a constructed node and tagging
  that implicitly: the end result is same.

*/


int main(int argc, char **argv)
{
  SilcBufferStruct node, node2;
  SilcAsn1 asn1;
  SilcBool success = FALSE;
  SilcBool val = TRUE;
  int i;
  unsigned char *str;
  SilcUInt32 str_len;

  memset(&node, 0, sizeof(node));
  memset(&node2, 0, sizeof(node2));

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*asn1*,*ber*");
  }

  SILC_LOG_DEBUG(("Allocating ASN.1 context"));
  asn1 = silc_asn1_alloc();
  if (!asn1)
    goto out;

  SILC_LOG_DEBUG(("Encoding ASN.1 tree 1"));
  val = 1;
  success =
    silc_asn1_encode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_SEQUENCE_T(SILC_ASN1_EXPLICIT, 9),
		         SILC_ASN1_SEQUENCE_T(SILC_ASN1_EXPLICIT |
					      SILC_ASN1_INDEFINITE, 0),
		           SILC_ASN1_BOOLEAN_T(0, 4, val),
		           SILC_ASN1_BOOLEAN(val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Encoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Encoding success"));
  SILC_LOG_HEXDUMP(("ASN.1 tree"), node.data, silc_buffer_len(&node));
  SILC_LOG_DEBUG(("Decoding ASN.1 tree 1"));
  success =
    silc_asn1_decode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_SEQUENCE_T(SILC_ASN1_EXPLICIT, 9),
		         SILC_ASN1_SEQUENCE_T(SILC_ASN1_EXPLICIT |
					      SILC_ASN1_INDEFINITE, 0),
		           SILC_ASN1_BOOLEAN_T(0, 4, &val),
		           SILC_ASN1_BOOLEAN(&val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));

#if 1
  memset(&node, 0, sizeof(node));
  SILC_LOG_DEBUG(("Encoding ASN.1 tree 1"));
  val = 0;
  success =
    silc_asn1_encode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_SEQUENCE_T(SILC_ASN1_EXPLICIT, 9),
		         SILC_ASN1_SEQUENCE_T(SILC_ASN1_EXPLICIT |
					      SILC_ASN1_INDEFINITE, 0),
		           SILC_ASN1_BOOLEAN_T(0, 4, val),
		           SILC_ASN1_BOOLEAN(val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Encoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Encoding success"));
  SILC_LOG_HEXDUMP(("ASN.1 tree"), node.data, silc_buffer_len(&node));
  SILC_LOG_DEBUG(("Decoding ASN.1 tree 1"));
  success =
    silc_asn1_decode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_SEQUENCE_T(SILC_ASN1_EXPLICIT, 9),
		         SILC_ASN1_SEQUENCE_T(SILC_ASN1_EXPLICIT |
					      SILC_ASN1_INDEFINITE, 0),
		           SILC_ASN1_BOOLEAN_T(0, 4, &val),
		           SILC_ASN1_BOOLEAN(&val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  printf("\n");


  memset(&node, 0, sizeof(node));
  SILC_LOG_DEBUG(("Encoding ASN.1 tree 2"));
  val = 1;
  success =
    silc_asn1_encode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_SEQUENCE_T(SILC_ASN1_EXPLICIT, 9),
		         SILC_ASN1_SEQUENCE_T(SILC_ASN1_INDEFINITE, 0),
		           SILC_ASN1_BOOLEAN_T(0, 4, val),
		           SILC_ASN1_BOOLEAN(val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Encoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Encoding success"));
  SILC_LOG_HEXDUMP(("ASN.1 tree"), node.data, silc_buffer_len(&node));
  SILC_LOG_DEBUG(("Decoding ASN.1 tree 2"));
  success =
    silc_asn1_decode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_SEQUENCE_T(SILC_ASN1_EXPLICIT, 9),
		         SILC_ASN1_SEQUENCE_T(SILC_ASN1_INDEFINITE, 0),
		           SILC_ASN1_BOOLEAN_T(0, 4, &val),
		           SILC_ASN1_BOOLEAN(&val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  printf("\n");


  memset(&node, 0, sizeof(node));
  SILC_LOG_DEBUG(("Encoding ASN.1 tree 3"));
  val = 0;
  success =
    silc_asn1_encode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_BOOLEAN_T(0, 4, val),
		           SILC_ASN1_BOOLEAN(val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Encoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Encoding success"));
  SILC_LOG_HEXDUMP(("ASN.1 tree"), node.data, silc_buffer_len(&node));
  SILC_LOG_DEBUG(("Decoding ASN.1 tree 3"));
  success =
    silc_asn1_decode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_BOOLEAN_T(0, 4, &val),
		           SILC_ASN1_BOOLEAN(&val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  printf("\n");


  memset(&node, 0, sizeof(node));
  SILC_LOG_DEBUG(("Encoding ASN.1 tree 4"));
  val = 1;
  success =
    silc_asn1_encode(asn1, &node,
		     SILC_ASN1_SEQUENCE_T(SILC_ASN1_PRIVATE |
					  SILC_ASN1_EXPLICIT, 101),
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_BOOLEAN_T(0, 4, val),
		           SILC_ASN1_BOOLEAN(val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Encoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Encoding success"));
  SILC_LOG_HEXDUMP(("ASN.1 tree"), node.data, silc_buffer_len(&node));
  SILC_LOG_DEBUG(("Decoding ASN.1 tree 4"));
  success =
    silc_asn1_decode(asn1, &node,
		     SILC_ASN1_SEQUENCE_T(SILC_ASN1_PRIVATE |
					  SILC_ASN1_EXPLICIT, 101),
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_BOOLEAN_T(0, 4, &val),
		           SILC_ASN1_BOOLEAN(&val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  printf("\n");


  memset(&node, 0, sizeof(node));
  SILC_LOG_DEBUG(("Encoding ASN.1 tree 5"));
  success =
    silc_asn1_encode(asn1, &node2,
		     SILC_ASN1_BOOLEAN(val),
		     SILC_ASN1_END);
  SILC_LOG_DEBUG(("Encoding success"));
  success =
    silc_asn1_encode(asn1, &node,
		     SILC_ASN1_SEQUENCE_T(SILC_ASN1_PRIVATE, 101),
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_ANY(&node2),
		           SILC_ASN1_BOOLEAN_T(0, 4, val),
		           SILC_ASN1_BOOLEAN(val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Encoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Encoding success"));
  SILC_LOG_HEXDUMP(("ASN.1 tree"), node.data, silc_buffer_len(&node));
  memset(&node2, 0, sizeof(node2));
  SILC_LOG_DEBUG(("Decoding ASN.1 tree 5"));
  success =
    silc_asn1_decode(asn1, &node,
		     SILC_ASN1_SEQUENCE_T(SILC_ASN1_PRIVATE, 101),
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_ANY(&node2),
		           SILC_ASN1_BOOLEAN_T(0, 4, &val),
		           SILC_ASN1_BOOLEAN(&val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  success =
    silc_asn1_decode(asn1, &node2,
		     SILC_ASN1_BOOLEAN(&val),
		     SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  memset(&node2, 0, sizeof(node2));
  printf("\n");


  memset(&node, 0, sizeof(node));
  SILC_LOG_DEBUG(("Encoding ASN.1 tree 6"));
  success =
    silc_asn1_encode(asn1, &node2,
		     SILC_ASN1_BOOLEAN(val),
		     SILC_ASN1_END);
  SILC_LOG_DEBUG(("Encoding success"));
  success =
    silc_asn1_encode(asn1, &node,
		     SILC_ASN1_SEQUENCE_T(SILC_ASN1_PRIVATE, 101),
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_ANY_T(SILC_ASN1_EXPLICIT, 33, &node2),
		           SILC_ASN1_BOOLEAN_T(0, 4, val),
		           SILC_ASN1_BOOLEAN(val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Encoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Encoding success"));
  SILC_LOG_HEXDUMP(("ASN.1 tree"), node.data, silc_buffer_len(&node));
  memset(&node2, 0, sizeof(node2));
  SILC_LOG_DEBUG(("Decoding ASN.1 tree 6"));
  success =
    silc_asn1_decode(asn1, &node,
		     SILC_ASN1_SEQUENCE_T(SILC_ASN1_PRIVATE, 101),
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_ANY_T(SILC_ASN1_EXPLICIT, 33, &node2),
		           SILC_ASN1_BOOLEAN_T(0, 4, &val),
		           SILC_ASN1_BOOLEAN(&val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  success =
    silc_asn1_decode(asn1, &node2,
		     SILC_ASN1_BOOLEAN(&val),
		     SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  memset(&node2, 0, sizeof(node2));
  printf("\n");


  memset(&node, 0, sizeof(node));
  SILC_LOG_DEBUG(("Encoding ASN.1 tree 7"));
  val = 0;
  success =
    silc_asn1_encode(asn1, &node2,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_BOOLEAN(val),
		       SILC_ASN1_BOOLEAN(val),
		       SILC_ASN1_BOOLEAN(val),
		       SILC_ASN1_BOOLEAN(val),
		     SILC_ASN1_END, SILC_ASN1_END);
  SILC_LOG_DEBUG(("Encoding success"));
  val = 1;
  success =
    silc_asn1_encode(asn1, &node,
		     SILC_ASN1_SEQUENCE_T(SILC_ASN1_PRIVATE, 101),
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_ANY_T(0, 11, &node2),
		           SILC_ASN1_BOOLEAN_T(0, 4, val),
		           SILC_ASN1_BOOLEAN(val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Encoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Encoding success"));
  SILC_LOG_HEXDUMP(("ASN.1 tree"), node.data, silc_buffer_len(&node));
  memset(&node2, 0, sizeof(node2));
  SILC_LOG_DEBUG(("Decoding ASN.1 tree 7"));
  success =
    silc_asn1_decode(asn1, &node,
		     SILC_ASN1_SEQUENCE_T(SILC_ASN1_PRIVATE, 101),
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_ANY_T(0, 11, &node2), /* NOTE: tag */
		           SILC_ASN1_BOOLEAN_T(0, 4, &val),
		           SILC_ASN1_BOOLEAN(&val),
		         SILC_ASN1_END,
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  success =
    silc_asn1_decode(asn1, &node2,
		     SILC_ASN1_SEQUENCE_T(0, 11), /* NOTE: using implicit
						     tag! */
		       SILC_ASN1_BOOLEAN(&val),
		       SILC_ASN1_BOOLEAN(&val),
		       SILC_ASN1_BOOLEAN(&val),
		       SILC_ASN1_BOOLEAN(&val),
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  memset(&node2, 0, sizeof(node2));
  printf("\n");


  memset(&node, 0, sizeof(node));
  SILC_LOG_DEBUG(("Encoding ASN.1 tree 8"));
  success =
    silc_asn1_encode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_BOOLEAN_T(SILC_ASN1_IMPLICIT, 9999, val),
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Encoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Encoding success"));
  SILC_LOG_HEXDUMP(("ASN.1 tree"), node.data, silc_buffer_len(&node));
  SILC_LOG_DEBUG(("Decoding ASN.1 tree 8"));
  success =
    silc_asn1_decode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_BOOLEAN_T(0, 9999, &val),
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  memset(&node, 0, sizeof(node));
  printf("\n");

  memset(&node, 0, sizeof(node));
  SILC_LOG_DEBUG(("Encoding ASN.1 tree 9"));
  success =
    silc_asn1_encode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_BOOLEAN_T(0, 4, val),
		           SILC_ASN1_BOOLEAN(val),
		         SILC_ASN1_END,
		         SILC_ASN1_BOOLEAN_T(SILC_ASN1_EXPLICIT, 99, val),
		         SILC_ASN1_BOOLEAN_T(0, 100, val),
		       SILC_ASN1_END,
		       SILC_ASN1_SEQUENCE,
		         SILC_ASN1_NULL,
		         SILC_ASN1_BOOLEAN_T(SILC_ASN1_EXPLICIT, 0, val),
		         SILC_ASN1_OCTET_STRING("foobar", 6),
		         SILC_ASN1_BOOLEAN_T(SILC_ASN1_PRIVATE, 43, val),
		         SILC_ASN1_BOOLEAN_T(SILC_ASN1_APP |
					     SILC_ASN1_EXPLICIT, 1, val),
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Encoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Encoding success"));
  SILC_LOG_HEXDUMP(("ASN.1 tree"), node.data, silc_buffer_len(&node));
  SILC_LOG_DEBUG(("Decoding ASN.1 tree 9"));
  success =
    silc_asn1_decode(asn1, &node,
		     SILC_ASN1_SEQUENCE,
		       SILC_ASN1_SEQUENCE_T(0, 9),
		         SILC_ASN1_SEQUENCE,
		           SILC_ASN1_BOOLEAN_T(0, 4, &val),
		           SILC_ASN1_BOOLEAN(&val),
		         SILC_ASN1_END,
		         SILC_ASN1_BOOLEAN_T(SILC_ASN1_EXPLICIT, 99, &val),
		         SILC_ASN1_BOOLEAN_T(0, 100, &val),
		       SILC_ASN1_END,
		       SILC_ASN1_SEQUENCE,
		         SILC_ASN1_NULL,
		         SILC_ASN1_BOOLEAN_T(SILC_ASN1_EXPLICIT, 0, &val),
		         SILC_ASN1_OCTET_STRING(&str, &str_len),
		         SILC_ASN1_BOOLEAN_T(SILC_ASN1_PRIVATE, 43, &val),
		         SILC_ASN1_BOOLEAN_T(SILC_ASN1_APP |
					     SILC_ASN1_EXPLICIT, 1, &val),
		       SILC_ASN1_END,
		     SILC_ASN1_END, SILC_ASN1_END);
  if (!success) {
    SILC_LOG_DEBUG(("Decoding failed"));
    goto out;
  }
  SILC_LOG_DEBUG(("Decoding success"));
  SILC_LOG_DEBUG(("Boolean val %d", val));
  SILC_LOG_DEBUG(("Ooctet-string %s, len %d", str, str_len));
  printf("\n");

#endif
  silc_asn1_free(asn1);

 out:
  exit(success);
}
