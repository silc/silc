/*

  silcattrs.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccore/SILC Attribute Interface
 *
 * DESCRIPTION
 *
 * Implementation of the Attribute Payload that may be used to send and
 * retrieve user online precense information in the SILC network.  This
 * implements the draft-riikonen-precense-attrs draft.
 *
 ***/

#ifndef SILCATTRS_H
#define SILCATTRS_H

/****s* silccore/SilcAttributesAPI/SilcAttributePayload
 *
 * NAME
 *
 *    typedef struct SilcAttributePayloadStruct *SilcAttributePayload;
 *
 * DESCRIPTION
 *
 *    This context is the actual Attribute Payload and is allocated
 *    by silc_attribute_payload_parse and given as attribute usually to
 *    all silc_attribute_payload_* functions.  It is freed by the
 *    silc_attribute_payload_free function.
 *
 ***/
typedef struct SilcAttributePayloadStruct *SilcAttributePayload;

/****d* silccore/SilcAttributesAPI/SilcAttribute
 *
 * NAME
 *
 *    typedef SilcUInt8 SilcAttribute;
 *
 * DESCRIPTION
 *
 *    The SilcAttribute type definition and the attributes. The attributes
 *    listed here are the official attributes defined in the internet
 *    draft.  They define the contents of the attribute payload and the
 *    type of the attribute.
 *
 * SOURCE
 */
typedef SilcUInt8 SilcAttribute;

/* All defined attributes.  See the specs for detailed information.  The
   comment is the structure or data type that must be used with the
   silc_attribute_get_object function to fetch parsed attribute. */
#define SILC_ATTRIBUTE_NONE                   0
#define SILC_ATTRIBUTE_USER_INFO              1   /* SilcVCard */
#define SILC_ATTRIBUTE_SERVICE                2   /* SilcAttributeObjService */
#define SILC_ATTRIBUTE_STATUS_MOOD            3   /* SilcAttributeMood */
#define SILC_ATTRIBUTE_STATUS_FREETEXT        4   /* char * (UTF-8 string) */
#define SILC_ATTRIBUTE_STATUS_MESSAGE         5   /* SilcMime */
#define SILC_ATTRIBUTE_PREFERRED_LANGUAGE     6   /* char * (UTF-8 string) */
#define SILC_ATTRIBUTE_PREFERRED_CONTACT      7   /* SilcAttributeContact */
#define SILC_ATTRIBUTE_TIMEZONE               8   /* char * (UTF-8 string) */
#define SILC_ATTRIBUTE_GEOLOCATION            9   /* SilcAttributeObjGeo */
#define SILC_ATTRIBUTE_DEVICE_INFO            10  /* SilcAttributeObjDevice */
#define SILC_ATTRIBUTE_EXTENSION              11  /* SilcMime */
#define SILC_ATTRIBUTE_USER_PUBLIC_KEY        12  /* SilcAttributeObjPk */
#define SILC_ATTRIBUTE_SERVER_PUBLIC_KEY      13  /* SilcAttributeObjPk */
#define SILC_ATTRIBUTE_USER_DIGITAL_SIGNATURE 14  /* SilcAttributeObjPk */
#define SILC_ATTRIBUTE_SERVER_DIGITAL_SIGNATURE 15 /* SilcAttributeObjPk */
#define SILC_ATTRIBUTE_USER_ICON	      16  /* SilcMime */
#define SILC_ATTRIBUTE_PHONE_NUMBER	      17  /* SilcAttributeObjPN */
/***/

/* Maximum length of attribute request packet */
#define SILC_ATTRIBUTE_MAX_REQUEST_LEN (4 * 255)

/****d* silccore/SilcAttributesAPI/SilcAttributeFlags
 *
 * NAME
 *
 *    typedef SilcUInt8 SilcAttributeFlags;
 *
 * DESCRIPTION
 *
 *    Attribute Payload flags defined by the specification.
 *
 * SOURCE
 */
typedef SilcUInt8 SilcAttributeFlags;

/* All defined flags */
#define SILC_ATTRIBUTE_FLAG_NONE          0x00    /* No flags */
#define SILC_ATTRIBUTE_FLAG_INVALID       0x01	  /* Invalid attribute */
#define SILC_ATTRIBUTE_FLAG_VALID         0x02	  /* Valid attribute */
/***/

/****d* silccore/SilcAttributesAPI/SilcAttributeMood
 *
 * NAME
 *
 *    typedef enum { ... } SilcAttributeMood;
 *
 * DESCRIPTION
 *
 *    The user mood indicators defined by the specification.  This is
 *    bit mask.
 *
 * SOURCE
 */
typedef enum {
  SILC_ATTRIBUTE_MOOD_NORMAL      = 0x00000000,	  /* normal mood */
  SILC_ATTRIBUTE_MOOD_HAPPY       = 0x00000001,	  /* user feel happy */
  SILC_ATTRIBUTE_MOOD_SAD         = 0x00000002,	  /* user feel sad */
  SILC_ATTRIBUTE_MOOD_ANGRY       = 0x00000004,	  /* user feel angry */
  SILC_ATTRIBUTE_MOOD_JEALOUS     = 0x00000008,	  /* user feel jealous */
  SILC_ATTRIBUTE_MOOD_ASHAMED     = 0x00000010,	  /* user feel ashamed */
  SILC_ATTRIBUTE_MOOD_INVINCIBLE  = 0x00000020,	  /* user feel invincible */
  SILC_ATTRIBUTE_MOOD_INLOVE      = 0x00000040,	  /* user feel in love */
  SILC_ATTRIBUTE_MOOD_SLEEPY      = 0x00000080,	  /* user feel sleepy */
  SILC_ATTRIBUTE_MOOD_BORED       = 0x00000100,	  /* user feel bored */
  SILC_ATTRIBUTE_MOOD_EXCITED     = 0x00000200,	  /* user feel exited */
  SILC_ATTRIBUTE_MOOD_ANXIOUS     = 0x00000400,	  /* user feel anxious */
} SilcAttributeMood;
/***/

/****d* silccore/SilcAttributesAPI/SilcAttributeContact
 *
 * NAME
 *
 *    typedef enum { ... } SilcAttributeContact;
 *
 * DESCRIPTION
 *
 *    The defined preferred contact methods defined by the specification.
 *    This is bit mask.
 *
 * SOURCE
 */
typedef enum {
  SILC_ATTRIBUTE_CONTACT_NONE    = 0x00000000,	  /* no specific method */
  SILC_ATTRIBUTE_CONTACT_EMAIL   = 0x00000001,	  /* email preferred */
  SILC_ATTRIBUTE_CONTACT_CALL    = 0x00000002,	  /* phone call preferred */
  SILC_ATTRIBUTE_CONTACT_PAGE    = 0x00000004,	  /* "paging" preferred */
  SILC_ATTRIBUTE_CONTACT_SMS     = 0x00000008,	  /* SMS preferred */
  SILC_ATTRIBUTE_CONTACT_MMS     = 0x00000010,	  /* MMS preferred */
  SILC_ATTRIBUTE_CONTACT_CHAT    = 0x00000020,	  /* chatting preferred */
  SILC_ATTRIBUTE_CONTACT_VIDEO   = 0x00000040,	  /* video conferencing */
} SilcAttributeContact;
/***/

/****d* silccore/SilcAttributesAPI/SilcAttributeDevice
 *
 * NAME
 *
 *    typedef enum { ... } SilcAttributeDevice;
 *
 * DESCRIPTION
 *
 *    The defined device types defined by the specification.
 *
 * SOURCE
 */
typedef enum {
  SILC_ATTRIBUTE_DEVICE_COMPUTER      = 0,	  /* device is computer */
  SILC_ATTRIBUTE_DEVICE_MOBILE_PHONE  = 1,	  /* device is mobile phone */
  SILC_ATTRIBUTE_DEVICE_PDA           = 2,	  /* device is PDA */
  SILC_ATTRIBUTE_DEVICE_TERMINAL      = 3,	  /* device is terminal */
} SilcAttributeDevice;
/***/

/****d* silccore/SilcAttributesAPI/SilcAttributePNFormat
 *
 * NAME
 *
 *    typedef enum { ... } SilcAttributePNFormat;
 *
 * DESCRIPTION
 *
 *    The defined phone number formats.
 *
 * SOURCE
 */
typedef enum {
  SILC_ATTRIBUTE_NUMBER_ITU_E164        = 0,	  /* ITU E.164 */
  SILC_ATTRIBUTE_NUMBER_ITU_E123_PHONE  = 1,	  /* ITU E.123 */
  SILC_ATTRIBUTE_NUMBER_ENUM            = 2,	  /* ENUM, RFC 3761 */
} SilcAttributePNFormat;
/***/

/****f* silccore/SilcAttributesAPI/silc_attribute_payload_alloc
 *
 * SYNOPSIS
 *
 *    SilcAttributesPayload
 *    silc_attribute_payload_alloc(SilcAttribute attribute,
 *                                 SilcAttributeFlags flags,
 *                                 void *object,
 *                                 SilcUInt32 object_size);
 *
 * DESCRIPTION
 *
 *    Allocates and encodes the attribute indicated by `attribute' and
 *    returns pointer to the attribute.
 *
 *    The `object' must always be the same data type as defined with
 *    SilcAttribute (see the comments) for all attributes.
 *
 ***/
SilcAttributePayload silc_attribute_payload_alloc(SilcAttribute attribute,
						  SilcAttributeFlags flags,
						  void *object,
						  SilcUInt32 object_size);

/****f* silccore/SilcAttributesAPI/silc_attribute_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcDList
 *    silc_attribute_payload_parse(const unsigned char *payload,
 *                                 SilcUInt32 payload_len);
 *
 * DESCRIPTION
 *
 *    Parses list of Attribute payloads returning list of payloads.
 *    One entry in the returned list is SilcAttributesPayload.  You
 *    can produce such a list with silc_attribute_payload_encode
 *    function.
 *
 ***/
SilcDList silc_attribute_payload_parse(const unsigned char *payload,
				       SilcUInt32 payload_len);

/****f* silccore/SilcAttributesAPI/silc_attribute_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_attribute_payload_encode(SilcBuffer attrs,
 *                                             SilcAttribute attribute,
 *                                             SilcAttributeFlags flags,
 *                                             void *object,
 *                                             SilcUInt32 object_size);
 *
 * DESCRIPTION
 *
 *    Encodes one attribute payload into the `attrs' buffer and returns
 *    pointer to the buffer, which may be different in case the buffer
 *    was reallocated.  If `attrs' is NULL for first attribute this
 *    allocates the buffer and returns it.  This can be called multiple
 *    times to add multiple attributes to the `attrs' buffer.  The `flags'
 *    indicates the validity of the added attribute.  Returns NULL on
 *    error.
 *
 *    The `object' must always be the same data type as defined with
 *    SilcAttribute (see the comments) for all attributes.
 *
 ***/
SilcBuffer silc_attribute_payload_encode(SilcBuffer attrs,
					 SilcAttribute attribute,
					 SilcAttributeFlags flags,
					 void *object,
					 SilcUInt32 object_size);

/****f* silccore/SilcAttributesAPI/silc_attribute_payload_encode_data
 *
 * SYNOPSIS
 *
 *    SilcBuffer
 *    silc_attribute_payload_encode_data(SilcBuffer attrs,
 *                                       SilcAttribute attribute,
 *                                       SilcAttributeFlags flags,
 *                                       const unsigned char *data,
 *                                       SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Same function as silc_attribute_payload_encode except the attribute
 *    is already encoded into `data' of `data_len' bytes in length.
 *    Encodes the attribute into the `attrs' buffer and returns pointer
 *    to the buffer, which may be different in case the buffer was
 *    reallocated.  If `attrs' is NULL for first attribute this allocates
 *    the buffer and returns it.  Returns NULL on error.
 *
 ***/
SilcBuffer silc_attribute_payload_encode_data(SilcBuffer attrs,
					      SilcAttribute attribute,
					      SilcAttributeFlags flags,
					      const unsigned char *data,
					      SilcUInt32 data_len);

/****f* silccore/SilcAttributesAPI/silc_attribute_payload_free
 *
 * SYNOPSIS
 *
 *    void silc_attribute_payload_free(SilcAttributePayload payload);
 *
 * DESCRIPTION
 *
 *    Frees the Attribute Payload and all data in it.
 *
 ***/
void silc_attribute_payload_free(SilcAttributePayload payload);

/****f* silccore/SilcAttributesAPI/silc_attribute_payload_list_free
 *
 * SYNOPSIS
 *
 *    void silc_attribute_payload_list_free(SilcDList list);
 *
 * DESCRIPTION
 *
 *    Frees list of Attribute Payloads and all data in them.
 *
 ***/
void silc_attribute_payload_list_free(SilcDList list);

/****f* silccore/SilcAttributesAPI/silc_attribute_get_attribute
 *
 * SYNOPSIS
 *
 *    SilcAttribute silc_attribute_get_attribute(SilcAttributePayload payload);
 *
 * DESCRIPTION
 *
 *    Return the attribute type from the payload indicated by `payload'.
 *
 ***/
SilcAttribute silc_attribute_get_attribute(SilcAttributePayload payload);

/****f* silccore/SilcAttributesAPI/silc_attribute_get_flags
 *
 * SYNOPSIS
 *
 *    SilcAttributeFlags
 *    silc_attribute_get_flags(SilcAttributePayload payload);
 *
 * DESCRIPTION
 *
 *    Return the attribute flags from the payload indicated by `payload'.
 *
 ***/
SilcAttributeFlags silc_attribute_get_flags(SilcAttributePayload payload);

/****f* silccore/SilcAttributesAPI/silc_attribute_get_data
 *
 * SYNOPSIS
 *
 *    const unsigned char *
 *    silc_attribute_get_data(SilcAttributePayload payload,
 *                            SilcUInt32 *data_len);
 *
 * DESCRIPTION
 *
 *    Returns the attribute data from the payload indicated by the `payload'
 *    The caller must not free the returned data pointer.
 *
 ***/
const unsigned char *silc_attribute_get_data(SilcAttributePayload payload,
					     SilcUInt32 *data_len);

/****f* silccore/SilcAttributesAPI/silc_attribute_get_verify_data
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_attribute_get_verify_data(SilcDList attrs,
 *                                   SilcBool server_verification,
 *                                   SilcUInt32 *data_len);
 *
 * DESCRIPTION
 *
 *    Constructs the data to be verified with the sender's digital
 *    signature and sender's public key.  This allocates the data from
 *    the list of attribute payloads and returns the buffer.  The caller
 *    must free it.  If `server_verification' is FALSE then data is
 *    constructed for user's digital signature verification, if it is
 *    TRUE then it is constructed for server's digital signature
 *    verification.
 *
 ***/
unsigned char *silc_attribute_get_verify_data(SilcDList attrs,
					      SilcBool server_verification,
					      SilcUInt32 *data_len);

/* Object structures */

/****s* silccore/SilcAttributesAPI/SilcAttributeObjService
 *
 * NAME
 *
 *    typedef struct { ... } SilcAttributeObjService;
 *
 * DESCRIPTION
 *
 *    SILC_ATTRIBUTE_SERVICE type object structure.
 *
 * SOURCE
 */
typedef struct SilcAttributeObjServiceStruct {
  SilcUInt32 port;		/* IANA specified service port */
  SilcUInt32 idle;		/* Idle time in the service */
  char signon[64];		/* Signon date and time (UTC) */
  char address[256];		/* service address */
  SilcBool status;		/* online status (TRUE present in service) */
} SilcAttributeObjService;
/***/

/****s* silccore/SilcAttributesAPI/SilcAttributeObjGeo
 *
 * NAME
 *
 *    typedef struct { ... } SilcAttributeObjGeo;
 *
 * DESCRIPTION
 *
 *    SILC_ATTRIBUTE_GEOLOCATION type object.  The caller must free the
 *    strings inside the structure.
 *
 * SOURCE
 */
typedef struct SilcAttributeObjGeoStruct {
  char *longitude;		/* Longitude */
  char *latitude;		/* Latitude */
  char *altitude;		/* Altitude */
  char *accuracy;		/* Accuracy in meters */
} SilcAttributeObjGeo;
/***/

/****s* silccore/SilcAttributesAPI/SilcAttributeObjDevice
 *
 * NAME
 *
 *    typedef struct { ... } SilcAttributeObjDevice;
 *
 * DESCRIPTION
 *
 *    SILC_ATTRIBUTE_DEVICE_INFO type object.  The caller must free the
 *    strings inside the structure.
 *
 * SOURCE
 */
typedef struct SilcAttributeObjDeviceStruct {
  SilcAttributeDevice type;	/* device type */
  char *manufacturer;		/* manufacturer of the device */
  char *version;		/* device version string */
  char *model;			/* device model string */
  char *language;		/* device language (ISO 639-2/T) */
} SilcAttributeObjDevice;
/***/

/****s* silccore/SilcAttributesAPI/SilcAttributeObjPk
 *
 * NAME
 *
 *    typedef struct { ... } SilcAttributeObjPk;
 *
 * DESCRIPTION
 *
 *    Data type for public key, certificate or digital signatures.  The
 *    caller must free the data inside the structure.  The 'type' is one
 *    of following: "silc-rsa", "silc-dss, "ssh-rsa", "ssh-dss",
 *    "pgp-sign-rsa", "pgp-sign-dss", "x509v3-sign-rsa", "x509v3-sign-dss".
 *    The 'type' is NULL when this structure includes a digital signature.
 *
 *    In SILC, at least the "silc-rsa" must be supported.  In this case
 *    the key is normal SILC Public key.  To verify a signature with the
 *    SILC Public key, construct the signature data with the
 *    silc_attribute_get_verify_data and verify the signature with
 *    for example silc_pkcs_verify_with_hash function.  The public key
 *    to the verification is the `data' and `data_len', and can be decoded
 *    with silc_pkcs_public_key_decode function.
 *
 * SOURCE
 */
typedef struct SilcAttributeObjPkStruct {
  char *type;			/* public key/certificate type, NULL
				   when contains digital signature. */
  unsigned char *data;		/* public key/cert/signature data. The
				   encoding depends of the `type'. */
  SilcUInt32 data_len;		/* data length */
} SilcAttributeObjPk;
/***/

/****s* silccore/SilcAttributesAPI/SilcAttributeObjPN
 *
 * NAME
 *
 *    typedef struct { ... } SilcAttributeObjPN;
 *
 * DESCRIPTION
 *
 *    SILC_ATTRIBUTE_PHONE_NUMBER type object.  The caller must free the
 *    phone number string inside the structure.
 *
 * SOURCE
 */
typedef struct SilcAttributeObjPNStruct {
  SilcAttributePNFormat format;	/* Phone number format */
  char *number;			/* Phone number */
} SilcAttributeObjPN;
/***/

/****f* silccore/SilcAttributesAPI/silc_attribute_get_object
 *
 * SYNOPSIS
 *
 *    SilcBool silc_attribute_get_object(SilcAttributePayload payload,
 *                                       void *object,
 *                                       SilcUInt32 object_size);
 *
 * DESCRIPTION
 *
 *    Returns the already parsed attribute object from the payload
 *    indicated by `payload'.  Copies the data into the `object' which
 *    must be sent as argument (and must be of correct type and size).
 *    The `object_size' indicates the size of the `*object' sent.
 *    Returns TRUE if the `attribute' attribute was found and FALSE
 *    if such attribute is not present in the `payload', or the `object_size'
 *    is not sufficient.  See the definition of SilcAttribute for the
 *    list of attributes and the required object types for attributes.
 *    You can use silc_attribute_get_attribute to get the SilcAttribute
 *    type from the `payload'.
 *
 * EXAMPLE
 *
 *    SilcAttributeObjDevice dev;
 *
 *    ...
 *    case SILC_ATTRIBUTE_DEVICE_INFO:
 *    memset(&dev, 0, sizeof(dev));
 *    if (!silc_attribute_get_object(payload, (void *)&dev, sizeof(dev)))
 *      error();
 *
 *    case SILC_ATTRIBUTE_USER_ICON:
 *    mime = silc_mime_alloc();
 *    if (!silc_attribute_get_object(payload, (void *)mime, sizeof(*mime)))
 *      error();
 *    ...
 *
 ***/
SilcBool silc_attribute_get_object(SilcAttributePayload payload,
				   void *object, SilcUInt32 object_size);

#endif /* SILCATTRS_H */
