/*

  silcattrs.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

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
#define SILC_ATTRIBUTE_NONE                     0
#define SILC_ATTRIBUTE_USER_INFO                1
#define SILC_ATTRIBUTE_SERVICE                  2 /* SilcAttributeObjService */
#define SILC_ATTRIBUTE_STATUS_MOOD              3 /* SilcAttributeMood */
#define SILC_ATTRIBUTE_STATUS_FREETEXT          4 /* char * (UTF-8 string) */
#define SILC_ATTRIBUTE_STATUS_MESSAGE           5 /* SilcAttributeObjMime */
#define SILC_ATTRIBUTE_PREFERRED_LANGUAGE       6 /* char * (UTF-8 string) */
#define SILC_ATTRIBUTE_PREFERRED_CONTACT        7 /* SilcAttributeContact */
#define SILC_ATTRIBUTE_TIMEZONE                 8 /* char * (UTF-8 string */
#define SILC_ATTRIBUTE_GEOLOCATION              9 /* SilcAttributeObjGeo */
#define SILC_ATTRIBUTE_DEVICE_INFO              10 /* SilcAttributeObjDevice */
#define SILC_ATTRIBUTE_EXTENSION                11 /* SilcAttributeObjMime */
#define SILC_ATTRIBUTE_USER_PUBLIC_KEY          12 /* SilcAttributeObjPk */
#define SILC_ATTRIBUTE_SERVER_PUBLIC_KEY        13 /* SilcAttributeObjPk */
#define SILC_ATTRIBUTE_USER_DIGITAL_SIGNATURE   14 /* SilcAttributeObjPk */
#define SILC_ATTRIBUTE_SERVER_DIGITAL_SIGNATURE 15 /* SilcAttributeObjPk */
/***/

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

/****f* silccore/SilcAttributesAPI/silc_attribute_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcAttributePayload
 *    silc_attribute_payload_parse(const unsigned char *payload,
 *                                 SilcUInt32 payload_len);
 *
 * DESCRIPTION
 *
 *    Parses one attribute payload sent as argument and saves it to
 *    SilcAttributePayload context.  The new allocated context is returned.
 *
 ***/
SilcAttributePayload
silc_attribute_payload_parse(const unsigned char *payload,
			     SilcUInt32 payload_len);

/****f* silccore/SilcAttributesAPI/silc_attribute_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_attribute_payload_encode(SilcAttribute attribute,
 *                                             SilcAttributeFlags flags,
 *                                             const unsigned char *data,
 *                                             SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Encodes one attribute payload and returns allocated buffer.  The
 *    `attributes' is the attribute type with `flags' and the actual
 *    attribute data indicated by `data' and `data_len'.
 *
 ***/
SilcBuffer silc_attribute_payload_encode(SilcAttribute attribute,
					 SilcAttributeFlags flags,
					 const unsigned char *data,
					 SilcUInt32 data_len);

/****f* silccore/SilcAttributesAPI/silc_attribute_payload_parse_list
 *
 * SYNOPSIS
 *
 *    SilcDList
 *    silc_attribute_payload_parse_list(const unsigned char *payload,
 *                                      SilcUInt32 payload_len);
 *
 * DESCRIPTION
 *
 *    Parses list of Attribute payloads returning list of payloads. This
 *    is equivalent to the silc_attribute_payload_parse except that the
 *    `buffer' now includes multiple Attribute Payloads one after the other.
 *    You can produce such a list with silc_attribute_payload_encode_list
 *    function.
 *
 ***/
SilcDList silc_attribute_payload_parse_list(const unsigned char *payload,
					    SilcUInt32 payload_len);

/****f* silccore/SilcAttributesAPI/silc_attribute_payload_encode_list
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_attribute_payload_encode(SilcUInt32 num_attrs, ...);
 *
 * DESCRIPTION
 *
 *    Encodes a list of Attribute payloads.  The `num_attrs' indicates the
 *    number of attributes sent as argument.  The variable argument list
 *    sent as argument includes the attribute, attribute flags, attribute
 *    data and attribute data length.  One attribute is one of these
 *    { attribute, attribute flags, data and data length } arguments.
 *    Returns the attribute payloads in data buffer one after the other.
 *    You can parse such list with silc_attribute_payload_parse_list
 *    function.
 *
 ***/
SilcBuffer silc_attribute_payload_encode_list(SilcUInt32 num_attrs, ...);

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

/* Object structures */

/****s* silccore/SilcAttributesAPI/SilcAttributesObjService
 *
 * NAME
 * 
 *    typedef struct { ... } SilcAttributesObjService;
 *
 * DESCRIPTION
 *
 *    SILC_ATTRIBUTE_SERVICE type object structure.
 *
 * SOURCE
 */
typedef struct {
  SilcUInt32 port;		/* IANA specified service port */
  char address[256];		/* service address */
  bool status;			/* online status (TRUE present in service) */
} SilcAttributeObjService;
/***/

/****s* silccore/SilcAttributesAPI/SilcAttributesObjMime
 *
 * NAME
 * 
 *    typedef struct { ... } SilcAttributesObjMime;
 *
 * DESCRIPTION
 *
 *    Data type for MIME object as attribute.  The data in the structure
 *    is valid as long as the payload structure is valid.
 *
 * SOURCE
 */
typedef struct {
  const unsigned char *mime;	/* MIME buffer */
  SilcUInt32 mime_len;		/* length of the MIME buffer */
} SilcAttributeObjMime;
/***/

/****s* silccore/SilcAttributesAPI/SilcAttributesObjGeo
 *
 * NAME
 * 
 *    typedef struct { ... } SilcAttributesObjGeo;
 *
 * DESCRIPTION
 *
 *    SILC_ATTRIBUTE_GEOLOCATION type object.  The caller must free the
 *    strings inside the structure.
 *
 * SOURCE
 */
typedef struct {
  char *longitude;		/* Longitude */
  char *latitude;		/* Latitude */
  char *altitude;		/* Altitude */
  char *accuracy;		/* Accuracy in meters */
} SilcAttributeObjGeo;
/***/

/****s* silccore/SilcAttributesAPI/SilcAttributesObjDevice
 *
 * NAME
 * 
 *    typedef struct { ... } SilcAttributesObjDevice;
 *
 * DESCRIPTION
 *
 *    SILC_ATTRIBUTE_DEVICE_INFO type object.  The caller must free the
 *    strings inside the structure.
 *
 * SOURCE
 */
typedef struct {
  SilcAttributeDevice type;	/* device type */
  char *manufacturer;		/* manufacturer of the device */
  char *version;		/* device version string */
  char *model;			/* device model string */
  char *language;		/* device language (ISO 639-2/T) */
} SilcAttributeObjDevice;
/***/

/****s* silccore/SilcAttributesAPI/SilcAttributesObjPk
 *
 * NAME
 * 
 *    typedef struct { ... } SilcAttributesObjPk;
 *
 * DESCRIPTION
 *
 *    Data type for public key, certificate or digital signatures.  The
 *    caller must free the data inside the structure.
 *
 * SOURCE
 */
typedef struct {
  char *type;			/* public key/certificate type, NULL
				   when contains digital signature. */
  unsigned char *data;		/* public key/cert/signature data. The
				   encoding depends of the `type'. */
  SilcUInt32 data_len;		/* data length */
} SilcAttributeObjPk;
/***/

/****f* silccore/SilcAttributesAPI/silc_attribute_get_object
 *
 * SYNOPSIS
 *
 *    bool silc_attribute_get_object(SilcAttributePayload payload,
 *                                   SilcAttribute attribute,
 *                                   const void **object,
 *                                   SilcUInt32 object_size);
 *
 * DESCRIPTION
 *
 *    Returns the already parsed attribute object by the attribute type
 *    indicated by `attribute'.  Copies the data into the `object' which
 *    must be sent as argument (and must be of correct type and size).
 *    The `object_size' indicates the size of the `*object' sent.
 *    Returns TRUE if the `attribute' attribute was found and FALSE
 *    if such attribute is not present in the `payload', or the `object_size'
 *    is not sufficient.  See the definition of SilcAttribute for the
 *    list of attributes and the required object types for attributes.
 *
 ***/
bool silc_attribute_get_object(SilcAttributePayload payload,
			       SilcAttribute attribute,
			       void **object, SilcUInt32 object_size);

#endif /* SILCATTRS_H */
