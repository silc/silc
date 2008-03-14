/*

  silc-queries.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "module.h"
#include "signals.h"
#include "misc.h"
#include "silc-queries.h"
#include "settings.h"
#include "levels.h"
#include "modules.h"
#include "commands.h"
#include "misc.h"

#include "fe-common/core/printtext.h"
#include "fe-common/core/fe-channels.h"
#include "fe-common/core/keyboard.h"
#include "fe-common/silc/module-formats.h"

static void silc_query_attributes_print_final(bool success, void *context);
static void silc_query_attributes_accept(const char *line, void *context);

QUERY_REC *silc_query_create(const char *server_tag,
			     const char *nick, int automatic)
{
  QUERY_REC *rec;

  g_return_val_if_fail(nick != NULL, NULL);

  rec = g_new0(QUERY_REC, 1);
  rec->chat_type = SILC_PROTOCOL;
  rec->name = g_strdup(nick);
  rec->server_tag = g_strdup(server_tag);
  query_init(rec, automatic);
  return rec;
}

void silc_queries_init(void)
{
}

void silc_queries_deinit(void)
{
}

/* ATTR command */

void command_attr(const char *data, SILC_SERVER_REC *server,
		  WI_ITEM_REC *item)
{
  char *tmp;
  unsigned char **argv;
  SilcUInt32 argc;
  SilcUInt32 *argv_lens, *argv_types;
  const char *sv;
  bool allowed;

  /* Now parse all arguments */
  tmp = g_strconcat("ATTR", " ", data, NULL);
  silc_parse_command_line(tmp, &argv, &argv_lens, &argv_types, &argc, 3);
  g_free(tmp);

  if (argc == 1) {
    /* Show all attributes */
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_ATTR_HEADER);

    allowed = settings_get_bool("attr_allow");
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_ATTR_ALLOW,
		       allowed ? "Yes" : "No");

    sv = settings_get_str("attr_vcard");
    if (sv && *sv)
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_VCARD_FILE, sv);

    sv = settings_get_str("attr_services");
    if (sv && *sv)
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_SERVICES, sv);

    sv = settings_get_str("attr_status_mood");
    if (sv && *sv)
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_STATUS_MOOD, sv);

    sv = settings_get_str("attr_status_text");
    if (sv && *sv)
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_STATUS_TEXT, sv);

    sv = settings_get_str("attr_status_message");
    if (sv && *sv)
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_STATUS_MESSAGE_FILE,
			 sv);

    sv = settings_get_str("attr_preferred_language");
    if (sv && *sv)
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_PREFERRED_LANGUAGE,
			 sv);

    sv = settings_get_str("attr_preferred_contact");
    if (sv && *sv)
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_PREFERRED_CONTACT,
			 sv);

    sv = settings_get_str("attr_geolocation");
    if (sv && *sv)
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_GEOLOCATION,
			 sv);

    sv = settings_get_str("attr_device_info");
    if (sv && *sv)
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_DEVICE_INFO,
			 sv);

    sv = settings_get_str("attr_public_keys");
    if (sv && *sv)
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_PUBLIC_KEYS,
			 sv);

    allowed = settings_get_bool("attr_timezone");
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_ATTR_TIMEZONE_ALLOW,
		       allowed ? "Yes" : "No");

    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_ATTR_FOOTER);
    return;
  }

  if (argc < 3)
    cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

  if (!strcasecmp(argv[1], "-del")) {
    /* Delete attribute */
    if (!strcasecmp(argv[2], "vcard")) {
      silc_client_attribute_del(silc_client, server->conn,
				SILC_ATTRIBUTE_USER_INFO, NULL);
      settings_set_str("attr_vcard", "");
    } else if (!strcasecmp(argv[2], "services")) {
      silc_client_attribute_del(silc_client, server->conn,
				SILC_ATTRIBUTE_SERVICE, NULL);
      settings_set_str("attr_services", argv[2]);
    } else if (!strcasecmp(argv[2], "status_mood")) {
      silc_client_attribute_del(silc_client, server->conn,
				SILC_ATTRIBUTE_STATUS_MOOD, NULL);
      settings_set_str("attr_status_mood", "");
    } else if (!strcasecmp(argv[2], "status_text")) {
      silc_client_attribute_del(silc_client, server->conn,
				SILC_ATTRIBUTE_STATUS_FREETEXT, NULL);
      settings_set_str("attr_status_text", "");
    } else if (!strcasecmp(argv[2], "status_message")) {
      silc_client_attribute_del(silc_client, server->conn,
				SILC_ATTRIBUTE_STATUS_MESSAGE, NULL);
      settings_set_str("attr_status_message", "");
    } else if (!strcasecmp(argv[2], "preferred_language")) {
      silc_client_attribute_del(silc_client, server->conn,
				SILC_ATTRIBUTE_PREFERRED_LANGUAGE, NULL);
      settings_set_str("attr_preferred_language", "");
    } else if (!strcasecmp(argv[2], "preferred_contact")) {
      silc_client_attribute_del(silc_client, server->conn,
				SILC_ATTRIBUTE_PREFERRED_CONTACT, NULL);
      settings_set_str("attr_preferred_contact", "");
    } else if (!strcasecmp(argv[2], "timezone")) {
      return;
    } else if (!strcasecmp(argv[2], "geolocation")) {
      silc_client_attribute_del(silc_client, server->conn,
				SILC_ATTRIBUTE_GEOLOCATION, NULL);
      settings_set_str("attr_geolocation", "");
    } else if (!strcasecmp(argv[2], "device_info")) {
      silc_client_attribute_del(silc_client, server->conn,
				SILC_ATTRIBUTE_DEVICE_INFO, NULL);
      settings_set_str("attr_device_info", "");
    } else if (!strcasecmp(argv[2], "public_keys")) {
      silc_client_attribute_del(silc_client, server->conn,
				SILC_ATTRIBUTE_USER_PUBLIC_KEY, NULL);
      settings_set_str("attr_public_keys", "");
    } else {
      cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);
    }
    return;
  }

  /* Add new attribute */
  if (!strcasecmp(argv[1], "allow")) {
    allowed = !strcasecmp(argv[2], "ON") || !strcasecmp(argv[2], "YES");
    settings_set_bool("attr_allow", allowed);
  } else if (!strcasecmp(argv[1], "vcard")) {
    settings_set_str("attr_vcard", argv[2]);
  } else if (!strcasecmp(argv[1], "services")) {
    settings_set_str("attr_services", argv[2]);
  } else if (!strcasecmp(argv[1], "status_mood")) {
    settings_set_str("attr_status_mood", argv[2]);
  } else if (!strcasecmp(argv[1], "status_text")) {
    settings_set_str("attr_status_text", argv[2]);
  } else if (!strcasecmp(argv[1], "status_message")) {
    settings_set_str("attr_status_message", argv[2]);
  } else if (!strcasecmp(argv[1], "preferred_language")) {
    settings_set_str("attr_preferred_language", argv[2]);
  } else if (!strcasecmp(argv[1], "preferred_contact")) {
    settings_set_str("attr_preferred_contact", argv[2]);
  } else if (!strcasecmp(argv[1], "timezone")) {
    allowed = !strcasecmp(argv[2], "ON") || !strcasecmp(argv[2], "YES");
    settings_set_bool("attr_timezone", allowed);
  } else if (!strcasecmp(argv[1], "geolocation")) {
    settings_set_str("attr_geolocation", argv[2]);
  } else if (!strcasecmp(argv[1], "device_info")) {
    settings_set_str("attr_device_info", argv[2]);
  } else if (!strcasecmp(argv[1], "public_keys")) {
    settings_set_str("attr_public_keys", argv[2]);
  } else {
    cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);
  }

  silc_query_attributes_default(silc_client, server->conn);
}

/* Put default attributes to client library */

void silc_query_attributes_default(SilcClient client,
				   SilcClientConnection conn)
{
  char *tmp, **list, **entry;
  const char *sv;
  SilcUInt32 tmp_len, mask;
  SilcAttributeObjService service;
  SilcMime mime;
  SilcAttributeObjGeo geo;
  SilcAttributeObjDevice dev;
  SilcAttributeObjPk pk;
  SilcVCardStruct vcard;
  bool allowed;

  memset(&service, 0, sizeof(service));
  memset(&geo, 0, sizeof(geo));
  memset(&dev, 0, sizeof(dev));
  memset(&pk, 0, sizeof(pk));
  memset(&vcard, 0, sizeof(vcard));

  allowed = settings_get_bool("attr_allow");
  if (!allowed) {
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_USER_INFO, NULL);
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_SERVICE, NULL);
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_STATUS_MOOD, NULL);
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_STATUS_FREETEXT, NULL);
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_STATUS_MESSAGE, NULL);
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_PREFERRED_LANGUAGE, NULL);
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_PREFERRED_CONTACT, NULL);
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_TIMEZONE, NULL);
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_GEOLOCATION, NULL);
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_DEVICE_INFO, NULL);
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_USER_PUBLIC_KEY, NULL);
    return;
  }

  sv = settings_get_str("attr_vcard");
  if (sv && *sv) {
    /* Put USER_INFO */
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_USER_INFO, NULL);
    tmp = silc_file_readfile(sv, &tmp_len, NULL);
    if (tmp) {
      tmp[tmp_len] = 0;
      if (silc_vcard_decode(tmp, tmp_len, &vcard))
	silc_client_attribute_add(silc_client, conn,
				  SILC_ATTRIBUTE_USER_INFO, (void *)&vcard,
				  sizeof(vcard));
    }
    silc_vcard_free(&vcard);
    silc_free(tmp);
  }

  sv = settings_get_str("attr_services");
  if (sv && *sv) {
    /* Put SERVICE */
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_SERVICE, NULL);
    list = g_strsplit(sv, " ", -1);
    for (entry = list; *entry != NULL; entry++) {
      if (!strchr(*entry, ':'))
	continue;
      tmp = strchr(*entry, ':') + 1;
      if (!tmp || !(*tmp))
	continue;
      memset(&service, 0, sizeof(service));
      service.port = atoi(tmp);
      *strchr(*entry, ':') = '\0';
      silc_strncat(service.address, sizeof(service.address), *entry,
		   strlen(*entry));
      service.status = TRUE;
      service.idle = 0;
      silc_client_attribute_add(silc_client, conn,
				SILC_ATTRIBUTE_SERVICE, &service,
				sizeof(service));
    }
    g_strfreev(list);
  }

  sv = settings_get_str("attr_status_mood");
  if (sv && *sv) {
    /* Put STATUS_MOOD */
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_STATUS_MOOD, NULL);
    mask = 0;
    list = g_strsplit(sv, " ", -1);
    for (entry = list; *entry != NULL; entry++) {
      if (!strcasecmp(*entry, "NORMAL"))
	mask |= SILC_ATTRIBUTE_MOOD_NORMAL;
      if (!strcasecmp(*entry, "HAPPY"))
	mask |= SILC_ATTRIBUTE_MOOD_HAPPY;
      if (!strcasecmp(*entry, "SAD"))
	mask |= SILC_ATTRIBUTE_MOOD_SAD;
      if (!strcasecmp(*entry, "ANGRY"))
	mask |= SILC_ATTRIBUTE_MOOD_ANGRY;
      if (!strcasecmp(*entry, "JEALOUS"))
	mask |= SILC_ATTRIBUTE_MOOD_JEALOUS;
      if (!strcasecmp(*entry, "ASHAMED"))
	mask |= SILC_ATTRIBUTE_MOOD_ASHAMED;
      if (!strcasecmp(*entry, "INVINCIBLE"))
	mask |= SILC_ATTRIBUTE_MOOD_INVINCIBLE;
      if (!strcasecmp(*entry, "INLOVE"))
	mask |= SILC_ATTRIBUTE_MOOD_INLOVE;
      if (!strcasecmp(*entry, "SLEEPY"))
	mask |= SILC_ATTRIBUTE_MOOD_SLEEPY;
      if (!strcasecmp(*entry, "BORED"))
	mask |= SILC_ATTRIBUTE_MOOD_BORED;
      if (!strcasecmp(*entry, "EXCITED"))
	mask |= SILC_ATTRIBUTE_MOOD_EXCITED;
      if (!strcasecmp(*entry, "ANXIOUS"))
	mask |= SILC_ATTRIBUTE_MOOD_ANXIOUS;
    }
    silc_client_attribute_add(silc_client, conn,
			      SILC_ATTRIBUTE_STATUS_MOOD,
			      SILC_32_TO_PTR(mask),
			      sizeof(SilcUInt32));
    g_strfreev(list);
  }

  sv = settings_get_str("attr_status_text");
  if (sv && *sv) {
    /* Put STATUS_TEXT */
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_STATUS_FREETEXT, NULL);
    silc_client_attribute_add(silc_client, conn,
			      SILC_ATTRIBUTE_STATUS_FREETEXT, (void *)sv,
			      strlen(sv));
  }

  sv = settings_get_str("attr_status_message");
  if (sv && *sv) {
    /* Put STATUS_MESSAGE */
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_STATUS_MESSAGE, NULL);
    tmp = silc_file_readfile(sv, &tmp_len, NULL);
    if (tmp) {
      mime = silc_mime_decode(NULL, tmp, tmp_len);
      if (mime)
	silc_client_attribute_add(silc_client, conn,
				  SILC_ATTRIBUTE_STATUS_MESSAGE, mime,
				  sizeof(*mime));
    }
    silc_free(tmp);
  }

  sv = settings_get_str("attr_preferred_language");
  if (sv && *sv) {
    /* Put PREFERRED_LANGUAGE */
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_PREFERRED_LANGUAGE, NULL);
    list = g_strsplit(sv, " ", -1);
    for (entry = list; *entry != NULL; entry++) {
      silc_client_attribute_add(silc_client, conn,
				SILC_ATTRIBUTE_PREFERRED_LANGUAGE, *entry,
				strlen(*entry));
    }
    g_strfreev(list);
  }

  sv = settings_get_str("attr_preferred_contact");
  if (sv && *sv) {
    /* Put PREFERRED_CONTACT */
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_PREFERRED_CONTACT, NULL);
    mask = 0;
    list = g_strsplit(sv, " ", -1);
    for (entry = list; *entry != NULL; entry++) {
      if (!strcasecmp(*entry, "NONE"))
	mask = 0;
      if (!strcasecmp(*entry, "EMAIL"))
	mask |= SILC_ATTRIBUTE_CONTACT_EMAIL;
      if (!strcasecmp(*entry, "CALL"))
	mask |= SILC_ATTRIBUTE_CONTACT_CALL;
      if (!strcasecmp(*entry, "PAGE"))
	mask |= SILC_ATTRIBUTE_CONTACT_PAGE;
      if (!strcasecmp(*entry, "SMS"))
	mask |= SILC_ATTRIBUTE_CONTACT_SMS;
      if (!strcasecmp(*entry, "MMS"))
	mask |= SILC_ATTRIBUTE_CONTACT_MMS;
      if (!strcasecmp(*entry, "CHAT"))
	mask |= SILC_ATTRIBUTE_CONTACT_CHAT;
      if (!strcasecmp(*entry, "VIDEO"))
	mask |= SILC_ATTRIBUTE_CONTACT_VIDEO;
    }
    silc_client_attribute_add(silc_client, conn,
			      SILC_ATTRIBUTE_PREFERRED_CONTACT,
			      SILC_32_TO_PTR(mask),
			      sizeof(SilcUInt32));
    g_strfreev(list);
  }

  /* Put TIMEZONE */
  allowed = settings_get_bool("attr_timezone");
  silc_client_attribute_del(silc_client, conn,
			    SILC_ATTRIBUTE_TIMEZONE, NULL);
  if (allowed)
    silc_client_attribute_add(silc_client, conn,
			      SILC_ATTRIBUTE_TIMEZONE, "foo", 3);

  sv = settings_get_str("attr_geolocation");
  if (sv && *sv) {
    /* Put GEOLOCATION */
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_GEOLOCATION, NULL);
    list = g_strsplit(sv, ":", -1);
    for (entry = list; *entry != NULL; entry++) {
      if (!geo.longitude) {
	geo.longitude = *entry;
	continue;
      }
      if (!geo.latitude) {
	geo.latitude = *entry;
	continue;
      }
      if (!geo.altitude) {
	geo.altitude = *entry;
	continue;
      }
      if (!geo.accuracy) {
	geo.accuracy = *entry;
	continue;
      }
    }
    silc_client_attribute_add(silc_client, conn,
			      SILC_ATTRIBUTE_GEOLOCATION, &geo,
			      sizeof(geo));
    g_strfreev(list);
  }

  sv = settings_get_str("attr_device_info");
  if (sv && *sv) {
    /* Put DEVICE_INFO */
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_DEVICE_INFO, NULL);
    allowed = FALSE;
    list = g_strsplit(sv, ":", -1);
    for (entry = list; *entry != NULL; entry++) {
      if (!allowed) {
	allowed = TRUE;
	if (!strcasecmp(*entry, "COMPUTER"))
	  dev.type = SILC_ATTRIBUTE_DEVICE_COMPUTER;
	if (!strcasecmp(*entry, "MOBILE_PHONE"))
	  dev.type = SILC_ATTRIBUTE_DEVICE_MOBILE_PHONE;
	if (!strcasecmp(sv, "PDA"))
	  dev.type = SILC_ATTRIBUTE_DEVICE_PDA;
	if (!strcasecmp(sv, "TERMINAL"))
	  dev.type = SILC_ATTRIBUTE_DEVICE_TERMINAL;
	continue;
      }
      if (!dev.manufacturer) {
	dev.manufacturer = *entry;
	continue;
      }
      if (!dev.version) {
	dev.version = *entry;
	continue;
      }
      if (!dev.model) {
	dev.model = *entry;
	continue;
      }
      if (!dev.language) {
	dev.language = *entry;
	continue;
      }
    }
    silc_client_attribute_add(silc_client, conn,
			      SILC_ATTRIBUTE_DEVICE_INFO, &dev,
			      sizeof(dev));
    g_strfreev(list);
  }

  sv = settings_get_str("attr_public_keys");
  if (sv && *sv) {
    /* Put USER_PUBLIC_KEY */
    silc_client_attribute_del(silc_client, conn,
			      SILC_ATTRIBUTE_USER_PUBLIC_KEY, NULL);
    list = g_strsplit(sv, " ", -1);
    for (entry = list; *entry != NULL; entry++) {
      if (!strncasecmp(*entry, "silc-rsa:", 8)) {
	tmp = silc_file_readfile((*entry) + 8, &tmp_len, NULL);
	if (tmp) {
	  tmp[tmp_len] = 0;
	  pk.type = "silc-rsa";
	  pk.data = tmp;
	  pk.data_len = tmp_len;
	  silc_client_attribute_add(silc_client, conn,
				    SILC_ATTRIBUTE_USER_PUBLIC_KEY, &pk,
				    sizeof(pk));
	}
	silc_free(tmp);
      } else {
	silc_say_error("Unsupported public key type '%s'", *entry);
      }
    }
    g_strfreev(list);
  }
}

typedef struct {
  SilcClient client;
  SILC_SERVER_REC *server;
  char *name;
  SilcAttributeObjPk userpk;
  SilcPublicKey public_key;
  SilcVCardStruct vcard;
  SilcMime message;
  SilcMime extension;
  bool nopk;
} *AttrVerify;

static void silc_query_attributes_verify(SilcBool success, void *context)
{
  *(SilcBool *)context = success;
}

void silc_query_attributes_print(SILC_SERVER_REC *server,
				 SilcClient client,
				 SilcClientConnection conn,
				 SilcDList attrs,
				 SilcClientEntry client_entry)
{
  SilcAttributePayload attr;
  SilcAttribute attribute;
  char tmp[512];
  SilcAttributeObjPk serverpk, usersign, serversign;
  AttrVerify verify;

  printformat_module("fe-common/silc", server, NULL,
		     MSGLEVEL_CRAP, SILCTXT_ATTR_HEADER);

  memset(&serverpk, 0, sizeof(serverpk));
  memset(&usersign, 0, sizeof(usersign));
  memset(&serversign, 0, sizeof(serversign));

  verify = silc_calloc(1, sizeof(*verify));
  if (!verify)
    return;
  verify->client = client;
  verify->server = server;
  verify->name = strdup(client_entry->nickname);

  silc_dlist_start(attrs);
  while ((attr = silc_dlist_get(attrs)) != SILC_LIST_END) {
    attribute = silc_attribute_get_attribute(attr);
    memset(tmp, 0, sizeof(tmp));

    switch (attribute) {

    case SILC_ATTRIBUTE_USER_INFO:
      {
	if (!silc_attribute_get_object(attr, (void *)&verify->vcard,
				       sizeof(verify->vcard)))
	  continue;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_VCARD_FILE,
			   "present");
      }
      break;

    case SILC_ATTRIBUTE_SERVICE:
      {
	SilcAttributeObjService service;
	memset(&service, 0, sizeof(service));
	if (!silc_attribute_get_object(attr, (void *)&service,
				       sizeof(service)))
	  continue;
	snprintf(tmp, sizeof(tmp) - 1, "%s:%d (logged %s) idle %d seconds",
		 service.address, (unsigned int)service.port,
		 service.status ? "in" : "out",
		 (unsigned int)service.idle);
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_SERVICES, tmp);
      }
      break;

    case SILC_ATTRIBUTE_STATUS_MOOD:
      {
	SilcUInt32 mask;
	if (!silc_attribute_get_object(attr, (void *)&mask, sizeof(mask)))
	  continue;
	if (!mask)
	  silc_strncat(tmp, sizeof(tmp), "NORMAL ", strlen(" NORMAL"));
	if (mask & SILC_ATTRIBUTE_MOOD_HAPPY)
	  silc_strncat(tmp, sizeof(tmp), "HAPPY ", strlen(" HAPPY"));
	if (mask & SILC_ATTRIBUTE_MOOD_SAD)
	  silc_strncat(tmp, sizeof(tmp), "SAD ", strlen(" SAD"));
	if (mask & SILC_ATTRIBUTE_MOOD_ANGRY)
	  silc_strncat(tmp, sizeof(tmp), "ANGRY ", strlen(" ANGRY"));
	if (mask & SILC_ATTRIBUTE_MOOD_JEALOUS)
	  silc_strncat(tmp, sizeof(tmp), "JEALOUS ", strlen(" JEALOUS"));
	if (mask & SILC_ATTRIBUTE_MOOD_ASHAMED)
	  silc_strncat(tmp, sizeof(tmp), "ASHAMED ", strlen(" ASHAMED"));
	if (mask & SILC_ATTRIBUTE_MOOD_INVINCIBLE)
	  silc_strncat(tmp, sizeof(tmp), "INVINCIBLE ", strlen(" INVINCIBLE"));
	if (mask & SILC_ATTRIBUTE_MOOD_INLOVE)
	  silc_strncat(tmp, sizeof(tmp), "INLOVE ", strlen(" INLOVE"));
	if (mask & SILC_ATTRIBUTE_MOOD_SLEEPY)
	  silc_strncat(tmp, sizeof(tmp), "SLEEPY ", strlen(" SLEEPY"));
	if (mask & SILC_ATTRIBUTE_MOOD_BORED)
	  silc_strncat(tmp, sizeof(tmp), "BORED ", strlen(" BORED"));
	if (mask & SILC_ATTRIBUTE_MOOD_EXCITED)
	  silc_strncat(tmp, sizeof(tmp), "EXCITED ", strlen(" EXCITED"));
	if (mask & SILC_ATTRIBUTE_MOOD_ANXIOUS)
	  silc_strncat(tmp, sizeof(tmp), "ANXIOUS ", strlen(" ANXIOUS"));
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_STATUS_MOOD, tmp);
      }
      break;

    case SILC_ATTRIBUTE_STATUS_FREETEXT:
      {
	if (!silc_attribute_get_object(attr, (void *)&tmp, sizeof(tmp) - 1))
	  continue;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_STATUS_TEXT, tmp);
      }
      break;

    case SILC_ATTRIBUTE_STATUS_MESSAGE:
      {
	verify->message = silc_mime_alloc();
	if (!verify->message)
	  continue;
	if (!silc_attribute_get_object(attr, (void *)verify->message,
				       sizeof(*verify->message)))
	  continue;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_STATUS_MESSAGE,
			   "present");
      }
      break;

    case SILC_ATTRIBUTE_PREFERRED_LANGUAGE:
      {
	if (!silc_attribute_get_object(attr, (void *)&tmp, sizeof(tmp) - 1))
	  continue;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_PREFERRED_LANGUAGE,
			   tmp);
      }
      break;

    case SILC_ATTRIBUTE_PREFERRED_CONTACT:
      {
	SilcUInt32 mask;
	if (!silc_attribute_get_object(attr, (void *)&mask, sizeof(mask)))
	  continue;
	if (!mask)
	  silc_strncat(tmp, sizeof(tmp), "NONE ", strlen(" NONE"));
	if (mask & SILC_ATTRIBUTE_CONTACT_CHAT)
	  silc_strncat(tmp, sizeof(tmp), "CHAT ", strlen(" CHAT"));
	if (mask & SILC_ATTRIBUTE_CONTACT_EMAIL)
	  silc_strncat(tmp, sizeof(tmp), "EMAIL ", strlen(" EMAIL"));
	if (mask & SILC_ATTRIBUTE_CONTACT_CALL)
	  silc_strncat(tmp, sizeof(tmp), "CALL ", strlen(" CALL"));
	if (mask & SILC_ATTRIBUTE_CONTACT_PAGE)
	  silc_strncat(tmp, sizeof(tmp), "PAGE ", strlen(" PAGE"));
	if (mask & SILC_ATTRIBUTE_CONTACT_SMS)
	  silc_strncat(tmp, sizeof(tmp), "SMS ", strlen(" SMS"));
	if (mask & SILC_ATTRIBUTE_CONTACT_MMS)
	  silc_strncat(tmp, sizeof(tmp), "MMS ", strlen(" MMS"));
	if (mask & SILC_ATTRIBUTE_CONTACT_VIDEO)
	  silc_strncat(tmp, sizeof(tmp), "VIDEO ", strlen(" VIDEO"));
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_PREFERRED_CONTACT, tmp);
      }
      break;

    case SILC_ATTRIBUTE_TIMEZONE:
      {
	if (!silc_attribute_get_object(attr, (void *)&tmp, sizeof(tmp) - 1))
	  continue;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_TIMEZONE, tmp);
      }
      break;

    case SILC_ATTRIBUTE_EXTENSION:
      {
	verify->extension = silc_mime_alloc();
	if (!verify->extension)
	  continue;
	if (!silc_attribute_get_object(attr, (void *)verify->extension,
				       sizeof(*verify->extension)))
	  continue;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_EXTENSION,
			   "present");
      }
      break;

    case SILC_ATTRIBUTE_GEOLOCATION:
      {
	SilcAttributeObjGeo geo;
	memset(&geo, 0, sizeof(geo));
	if (!silc_attribute_get_object(attr, (void *)&geo, sizeof(geo)))
	  continue;
	snprintf(tmp, sizeof(tmp) - 1, "%s:%s:%s:%s",
		 geo.longitude ? geo.longitude : "",
		 geo.latitude ? geo.latitude : "",
		 geo.altitude ? geo.altitude : "",
		 geo.accuracy ? geo.accuracy : "");
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_GEOLOCATION, tmp);
      }
      break;

    case SILC_ATTRIBUTE_DEVICE_INFO:
      {
	SilcAttributeObjDevice dev;
	memset(&dev, 0, sizeof(dev));
	if (!silc_attribute_get_object(attr, (void *)&dev, sizeof(dev)))
	  continue;
	snprintf(tmp, sizeof(tmp) - 1, "%s:%s:%s:%s:%s",
		 (dev.type == SILC_ATTRIBUTE_DEVICE_COMPUTER ? "COMPUTER" :
		  dev.type == SILC_ATTRIBUTE_DEVICE_PDA ? "PDA" :
		  dev.type == SILC_ATTRIBUTE_DEVICE_MOBILE_PHONE ?
		  "MOBILE PHONE" :
		  dev.type == SILC_ATTRIBUTE_DEVICE_TERMINAL ? "TERMINAL" :
		  ""),
		 dev.manufacturer ? dev.manufacturer : "",
		 dev.version ? dev.version : "",
		 dev.model ? dev.model: "",
		 dev.language ? dev.language : "");
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_DEVICE_INFO, tmp);
      }
      break;

    case SILC_ATTRIBUTE_USER_PUBLIC_KEY:
      {
	if (verify->userpk.type)
	  continue;
	if (!silc_attribute_get_object(attr, (void *)&verify->userpk,
				       sizeof(verify->userpk)))
	  continue;
      }
      break;

    case SILC_ATTRIBUTE_SERVER_PUBLIC_KEY:
      {
	if (serverpk.type)
	  continue;
	if (!silc_attribute_get_object(attr, (void *)&serverpk,
				       sizeof(serverpk)))
	  continue;
      }
      break;

    case SILC_ATTRIBUTE_USER_DIGITAL_SIGNATURE:
      {
	if (usersign.data)
	  continue;
	if (!silc_attribute_get_object(attr, (void *)&usersign,
				       sizeof(usersign)))
	  continue;
      }
      break;

    case SILC_ATTRIBUTE_SERVER_DIGITAL_SIGNATURE:
      {
	if (serversign.data)
	  continue;
	if (!silc_attribute_get_object(attr, (void *)&serversign,
				       sizeof(serversign)))
	  continue;
      }
      break;

    default:
      break;
    }
  }

  /* Handle the signature verifications and public key verifying here */

  if (verify->userpk.data) {
    SilcPKCSType type = 0;

    if (!strcmp(verify->userpk.type, "silc-rsa"))
      type = SILC_PKCS_SILC;
    else if (!strcmp(verify->userpk.type, "ssh-rsa"))
      type = SILC_PKCS_SSH2;
    else if (!strcmp(verify->userpk.type, "x509v3-sign-rsa"))
      type = SILC_PKCS_X509V3;
    else if (!strcmp(verify->userpk.type, "pgp-sign-rsa"))
      type = SILC_PKCS_OPENPGP;

    silc_pkcs_public_key_alloc(type, verify->userpk.data,
			       verify->userpk.data_len,
			       &verify->public_key);
  }

  if (usersign.data) {
    /* Verify the signature now */
    unsigned char *verifyd;
    SilcUInt32 verify_len;
    SilcBool verified = FALSE;

    if (verify->public_key) {
      verifyd = silc_attribute_get_verify_data(attrs, FALSE, &verify_len);
      if (verifyd)
	silc_pkcs_verify_async(verify->public_key, usersign.data,
			       usersign.data_len, verifyd, verify_len,
			       TRUE, sha1hash,
			       silc_query_attributes_verify, &verified);

      if (verified) {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_USER_SIGN_VERIFIED);
      } else {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_USER_SIGN_FAILED);
      }

      silc_free(verifyd);
    } else {
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_USER_SIGN_FAILED);
    }
  } else {
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_ATTR_USER_SIGN_NOT_PRESENT);
  }

  if (serversign.data) {
    /* Verify the signature now */
    SilcPublicKey public_key;
    SilcPKCSType type = 0;
    unsigned char *verifyd;
    SilcUInt32 verify_len;
    SilcBool verified = FALSE;

    if (!strcmp(serverpk.type, "silc-rsa"))
      type = SILC_PKCS_SILC;
    else if (!strcmp(serverpk.type, "ssh-rsa"))
      type = SILC_PKCS_SSH2;
    else if (!strcmp(serverpk.type, "x509v3-sign-rsa"))
      type = SILC_PKCS_X509V3;
    else if (!strcmp(serverpk.type, "pgp-sign-rsa"))
      type = SILC_PKCS_OPENPGP;

    if (silc_pkcs_public_key_alloc(type, serverpk.data,
				   serverpk.data_len,
				   &public_key)) {
      verifyd = silc_attribute_get_verify_data(attrs, TRUE, &verify_len);
      if (verifyd)
	silc_pkcs_verify_async(public_key, serversign.data,
			       serversign.data_len, verifyd,
			       verify_len, TRUE, sha1hash,
			       silc_query_attributes_verify, &verified);
      if (verified) {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_SERVER_SIGN_VERIFIED);
      } else {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ATTR_SERVER_SIGN_FAILED);
      }

      silc_pkcs_public_key_free(public_key);
      silc_free(verifyd);
    } else {
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_ATTR_SERVER_SIGN_FAILED);
    }
  }

  if (verify->public_key) {
    silc_verify_public_key(client, conn, SILC_CONN_CLIENT,
			   verify->public_key,
			   silc_query_attributes_print_final, verify);
  } else {
    verify->nopk = TRUE;
    silc_query_attributes_print_final(FALSE, verify);
  }
}

static void silc_query_attributes_print_final(bool success, void *context)
{
  AttrVerify verify = context;
  SILC_SERVER_REC *server = verify->server;
  char *format = NULL;
  unsigned char filename[256], *fingerprint = NULL, *tmp;
  struct stat st;
  int i;

  if (!verify->nopk) {
    if (success) {
      printformat_module("fe-common/silc", NULL, NULL,
			 MSGLEVEL_CRAP, SILCTXT_PUBKEY_VERIFIED, "user",
			 verify->name);
    } else {
      printformat_module("fe-common/silc", NULL, NULL,
			 MSGLEVEL_CRAP, SILCTXT_PUBKEY_NOTVERIFIED, "user",
			 verify->name);
    }
  }

  printformat_module("fe-common/silc", server, NULL,
		     MSGLEVEL_CRAP, SILCTXT_ATTR_FOOTER);

  /* Replace all whitespaces with `_'. */
  fingerprint = silc_hash_fingerprint(sha1hash,
				      verify->userpk.data,
				      verify->userpk.data_len);
  for (i = 0; i < strlen(fingerprint); i++)
    if (fingerprint[i] == ' ')
      fingerprint[i] = '_';

  /* Filename for dir */
  tmp = fingerprint + strlen(fingerprint) - 9;
  snprintf(filename, sizeof(filename) - 1, "%s/friends/%s",
	   get_irssi_dir(), tmp);
  silc_free(fingerprint);

  if ((stat(filename, &st)) == -1) {
    /* Ask to accept save requested attributes */
    format = format_get_text("fe-common/silc", NULL, NULL, NULL,
			     SILCTXT_ATTR_SAVE);
    keyboard_entry_redirect((SIGNAL_FUNC)silc_query_attributes_accept,
			    format, 0, verify);
  } else {
    /* Save new data to existing directory */
    silc_query_attributes_accept("Y", verify);
  }

  g_free(format);
}

static void silc_query_attributes_accept(const char *line, void *context)
{
  AttrVerify verify = context;
  SILC_SERVER_REC *server = verify->server;
  struct stat st;
  struct passwd *pw;
  unsigned char filename[256], filename2[256], *fingerprint = NULL, *tmp;
  SilcUInt32 len;
  int i;

  if (line[0] == 'Y' || line[0] == 'y') {
    /* Save the attributes */
    memset(filename, 0, sizeof(filename));
    memset(filename2, 0, sizeof(filename2));

    pw = getpwuid(getuid());
    if (!pw)
      goto out;

    /* Replace all whitespaces with `_'. */
    fingerprint = silc_hash_fingerprint(sha1hash,
					verify->userpk.data,
					verify->userpk.data_len);
    for (i = 0; i < strlen(fingerprint); i++)
      if (fingerprint[i] == ' ')
	fingerprint[i] = '_';

    /* Filename for dir */
    tmp = fingerprint + strlen(fingerprint) - 9;
    snprintf(filename, sizeof(filename) - 1, "%s/friends/%s",
	     get_irssi_dir(), tmp);

    /* Create dir if it doesn't exist */
    if ((stat(filename, &st)) == -1) {
      /* If dir doesn't exist */
      if (errno == ENOENT) {
	if (pw->pw_uid == geteuid()) {
	  if ((mkdir(filename, 0755)) == -1) {
	    silc_say_error("Couldn't create `%s' directory",
			   filename);
	    goto out;
	  }
	} else {
	  silc_say_error("Couldn't create `%s' directory due to a "
			 "wrong uid!", filename);
	  goto out;
	}
      } else {
	silc_say_error("%s", strerror(errno));
	goto out;
      }
    }

    /* Save the stuff to the directory */

    /* Save VCard */
    snprintf(filename2, sizeof(filename2) - 1, "%s/vcard", filename);
    if (verify->vcard.full_name) {
      tmp = silc_vcard_encode(&verify->vcard, &len);
      silc_file_writefile(filename2, tmp, len);
      silc_free(tmp);
    }

    /* Save public key */
    if (verify->public_key) {
      memset(filename2, 0, sizeof(filename2));
      snprintf(filename2, sizeof(filename2) - 1, "%s/clientkey_%s.pub",
	       filename, fingerprint);
      silc_pkcs_save_public_key(filename2, verify->public_key,
				SILC_PKCS_FILE_BASE64);
    }

    /* Save extension data */
    if (verify->extension) {
      memset(filename2, 0, sizeof(filename2));
      snprintf(filename2, sizeof(filename2) - 1, "%s/extension.mime",
	       filename);
      tmp = silc_mime_encode(verify->extension, &len);
      if (tmp)
	silc_file_writefile(filename2, tmp, len);
    }

    /* Save MIME message data */
    if (verify->message) {
      memset(filename2, 0, sizeof(filename2));
      snprintf(filename2, sizeof(filename2) - 1, "%s/status_message.mime",
	       filename);
      tmp = silc_mime_encode(verify->message, &len);
      if (tmp)
	silc_file_writefile(filename2, tmp, len);
    }

    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_ATTR_SAVED, filename);
  }

 out:
  silc_free(fingerprint);
  silc_free(verify->name);
  silc_vcard_free(&verify->vcard);
  silc_free(verify);
}
