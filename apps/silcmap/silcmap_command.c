/*

  silcmap_command.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silcincludes.h"
#include "silcclient.h"
#include "silcmap.h"

/******* Command Script Parsing **********************************************/

SILC_CONFIG_CALLBACK(silc_map_cmd_server);
SILC_CONFIG_CALLBACK(silc_map_cmd_loadmap);
SILC_CONFIG_CALLBACK(silc_map_cmd_writemap);
SILC_CONFIG_CALLBACK(silc_map_cmd_writemaphtml);
SILC_CONFIG_CALLBACK(silc_map_cmd_writehtml);
SILC_CONFIG_CALLBACK(silc_map_cmd_writerel);
SILC_CONFIG_CALLBACK(silc_map_cmd_cut);
SILC_CONFIG_CALLBACK(silc_map_cmd_rectangle);
SILC_CONFIG_CALLBACK(silc_map_cmd_circle);
SILC_CONFIG_CALLBACK(silc_map_cmd_line);
SILC_CONFIG_CALLBACK(silc_map_cmd_text);

static const SilcConfigTable silc_map_table_loadmap[] =
{
  { "filename", SILC_CONFIG_ARG_STR, silc_map_cmd_loadmap, NULL },
  { NULL },
};

static const SilcConfigTable silc_map_table_writemap[] =
{
  { "filename", SILC_CONFIG_ARG_STR, silc_map_cmd_writemap, NULL },
  { NULL },
};

static const SilcConfigTable silc_map_table_writemaphtml[] =
{
  { "filename", SILC_CONFIG_ARG_STR, silc_map_cmd_writemaphtml, NULL },
  { "image", SILC_CONFIG_ARG_STR, silc_map_cmd_writemaphtml, NULL },
  { "cut_lat", SILC_CONFIG_ARG_STRE, silc_map_cmd_writemaphtml, NULL },
  { "cut_lon", SILC_CONFIG_ARG_STRE, silc_map_cmd_writemaphtml, NULL },
  { NULL },
};

static const SilcConfigTable silc_map_table_writehtml[] =
{
  { "filename", SILC_CONFIG_ARG_STR, silc_map_cmd_writehtml, NULL },
  { "class", SILC_CONFIG_ARG_STRE, silc_map_cmd_writehtml, NULL },
  { NULL },
};

static const SilcConfigTable silc_map_table_writerel[] =
{
  { "filename", SILC_CONFIG_ARG_STR, silc_map_cmd_writerel, NULL },
  { "class", SILC_CONFIG_ARG_STRE, silc_map_cmd_writerel, NULL },
  { NULL },
};

static const SilcConfigTable silc_map_table_cut[] =
{
  { "lat", SILC_CONFIG_ARG_STR, silc_map_cmd_cut, NULL },
  { "lon", SILC_CONFIG_ARG_STR, silc_map_cmd_cut, NULL },
  { "width", SILC_CONFIG_ARG_INT, silc_map_cmd_cut, NULL },
  { "height", SILC_CONFIG_ARG_INT, silc_map_cmd_cut, NULL },
  { "filename", SILC_CONFIG_ARG_STR, silc_map_cmd_cut, NULL },
  { NULL },
};

static const SilcConfigTable silc_map_table_rectangle[] =
{
  { "lat", SILC_CONFIG_ARG_STR, silc_map_cmd_rectangle, NULL },
  { "lon", SILC_CONFIG_ARG_STR, silc_map_cmd_rectangle, NULL },
  { "color", SILC_CONFIG_ARG_STR, silc_map_cmd_rectangle, NULL },
  { "label", SILC_CONFIG_ARG_STR, silc_map_cmd_rectangle, NULL },
  { "lposx", SILC_CONFIG_ARG_INT, silc_map_cmd_rectangle, NULL },
  { "lposy", SILC_CONFIG_ARG_INT, silc_map_cmd_rectangle, NULL },
  { "lcolor", SILC_CONFIG_ARG_STR, silc_map_cmd_rectangle, NULL },
  { NULL },
};

static const SilcConfigTable silc_map_table_circle[] =
{
  { "lat", SILC_CONFIG_ARG_STR, silc_map_cmd_circle, NULL },
  { "lon", SILC_CONFIG_ARG_STR, silc_map_cmd_circle, NULL },
  { "color", SILC_CONFIG_ARG_STR, silc_map_cmd_circle, NULL },
  { "label", SILC_CONFIG_ARG_STR, silc_map_cmd_circle, NULL },
  { "lposx", SILC_CONFIG_ARG_INT, silc_map_cmd_circle, NULL },
  { "lposy", SILC_CONFIG_ARG_INT, silc_map_cmd_circle, NULL },
  { "lcolor", SILC_CONFIG_ARG_STR, silc_map_cmd_circle, NULL },
  { NULL },
};

static const SilcConfigTable silc_map_table_line[] =
{
  { "a_lat", SILC_CONFIG_ARG_STR, silc_map_cmd_line, NULL },
  { "a_lon", SILC_CONFIG_ARG_STR, silc_map_cmd_line, NULL },
  { "b_lat", SILC_CONFIG_ARG_STR, silc_map_cmd_line, NULL },
  { "b_lon", SILC_CONFIG_ARG_STR, silc_map_cmd_line, NULL },
  { "width", SILC_CONFIG_ARG_STR, silc_map_cmd_line, NULL },
  { "color", SILC_CONFIG_ARG_STR, silc_map_cmd_line, NULL },
  { NULL },
};

static const SilcConfigTable silc_map_table_text[] =
{
  { "lat", SILC_CONFIG_ARG_STR, silc_map_cmd_text, NULL },
  { "lon", SILC_CONFIG_ARG_STR, silc_map_cmd_text, NULL },
  { "color", SILC_CONFIG_ARG_STR, silc_map_cmd_text, NULL },
  { "text", SILC_CONFIG_ARG_STR, silc_map_cmd_text, NULL },
  { NULL },
};

static const SilcConfigTable silc_map_table_server[] =
{
  /* Details */
  { "hostname", SILC_CONFIG_ARG_STR, silc_map_cmd_server, NULL },
  { "ip", SILC_CONFIG_ARG_STR, silc_map_cmd_server, NULL },
  { "port", SILC_CONFIG_ARG_INT, silc_map_cmd_server, NULL },
  { "public_key", SILC_CONFIG_ARG_STR, silc_map_cmd_server, NULL },
  { "country", SILC_CONFIG_ARG_STR, silc_map_cmd_server, NULL },
  { "city", SILC_CONFIG_ARG_STR, silc_map_cmd_server, NULL },
  { "admin", SILC_CONFIG_ARG_STR, silc_map_cmd_server, NULL },
  { "description", SILC_CONFIG_ARG_STRE, silc_map_cmd_server, NULL },
  { "html_url", SILC_CONFIG_ARG_STRE, silc_map_cmd_server, NULL },

  /* Connect params */
  { "connect", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "connect_timeout", SILC_CONFIG_ARG_INT, silc_map_cmd_server, NULL },

  /* Statistics */
  { "starttime", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "uptime", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "clients", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "channels", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "server_ops", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "router_ops", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "cell_clients", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "cell_channels", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "cell_servers", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "all_clients", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "all_channels", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "all_servers", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "all_routers", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "all_server_ops", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "all_router_ops", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },
  { "motd", SILC_CONFIG_ARG_TOGGLE, silc_map_cmd_server, NULL },

  /* Colors */
  { "up_color", SILC_CONFIG_ARG_STR, silc_map_cmd_server, NULL },
  { "down_color", SILC_CONFIG_ARG_STR, silc_map_cmd_server, NULL },
  { "up_text_color", SILC_CONFIG_ARG_STR, silc_map_cmd_server, NULL },
  { "down_text_color", SILC_CONFIG_ARG_STR, silc_map_cmd_server, NULL },

  /* Map commands */
  { "cut", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_cut, silc_map_table_cut },
  { "rectangle", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_rectangle, silc_map_table_rectangle },
  { "circle", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_circle, silc_map_table_circle },
  { "line", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_line, silc_map_table_line },
  { "text", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_text, silc_map_table_text },
  { NULL },
};

static const SilcConfigTable silc_map_table_main[] =
{
  { "server", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_server, silc_map_table_server },
  { "loadmap", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_loadmap, silc_map_table_loadmap },
  { "writemap", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_writemap, silc_map_table_writemap },
  { "writemaphtml", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_writemaphtml, silc_map_table_writemaphtml },
  { "writehtml", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_writehtml, silc_map_table_writehtml },
  { "writerel", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_writerel, silc_map_table_writerel },
  { "cut", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_cut, silc_map_table_cut },
  { "rectangle", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_rectangle, silc_map_table_rectangle },
  { "circle", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_circle, silc_map_table_circle },
  { "line", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_line, silc_map_table_line },
  { "text", SILC_CONFIG_ARG_BLOCK,
    silc_map_cmd_text, silc_map_table_text },
  { NULL },
};

/* Command datas.  Used when command is outside server { } section. */
static char *filename = NULL;
static char *lat = NULL;
static char *lon = NULL;
static char *lat2 = NULL;
static char *lon2 = NULL;
static SilcUInt32 width = 0;
static SilcUInt32 height = 0;
static SilcInt16 r = 0;
static SilcInt16 g = 0;
static SilcInt16 b = 0;
static SilcInt16 lr = -1;
static SilcInt16 lg = -1;
static SilcInt16 lb = -1;
static char *text = NULL;
static SilcInt32 lposx = 0;
static SilcInt32 lposy = 0;
static bool color_set = FALSE;
static bool lcolor_set = FALSE;

/* Current server section. */
SilcMapConnection curr_conn = NULL;

/* Command: server, performs the connection to the remote server and
   gathers statistical information. */

SILC_CONFIG_CALLBACK(silc_map_cmd_server)
{
  SilcMap map = context;
  int retval = SILC_CONFIG_OK;

  if (!map->bitmap) {
    fprintf(stderr, "You must call loadmap command before server command\n");
    return SILC_CONFIG_ESILENT;
  }

  if (type == SILC_CONFIG_ARG_BLOCK) {
    SILC_LOG_DEBUG(("Server config parsed"));

    if (!curr_conn->ips) {
      fprintf(stderr, "IP must be configured\n");
      return SILC_CONFIG_EMISSFIELDS;
    }
    if (!curr_conn->hostnames) {
      fprintf(stderr, "Hostname must be configured\n");
      return SILC_CONFIG_EMISSFIELDS;
    }
    if (!curr_conn->port) {
      fprintf(stderr, "Port must be configured\n");
      return SILC_CONFIG_EMISSFIELDS;
    }

    /* The server data is now gathered.  We continue by creating the
       connection to the server and executing the requested commands. */
    silc_map_connect(map, curr_conn);
    map->conns_num++;

    /* Cleanup */
    curr_conn = NULL;

    return retval;
  }

  /* Mark the current parsed server */
  if (!curr_conn) {
    curr_conn = silc_calloc(1, sizeof(*curr_conn));
    if (!curr_conn)
      return SILC_CONFIG_ESILENT;

    curr_conn->hostnames = silc_dlist_init();
    curr_conn->ips = silc_dlist_init();
    curr_conn->commands = silc_dlist_init();
    curr_conn->map = map;
    if (!map->conns)
      map->conns = silc_dlist_init();
    silc_dlist_add(map->conns, curr_conn);
  }

  if (!strcmp(name, "hostname")) {
    silc_dlist_add(curr_conn->hostnames, strdup((char *)val));
  } else if (!strcmp(name, "ip")) {
    silc_dlist_add(curr_conn->ips, strdup((char *)val));
  } else if (!strcmp(name, "port")) {
    curr_conn->port = (SilcUInt32)*(int *)val;
  } else if (!strcmp(name, "public_key")) {
    curr_conn->public_key = strdup((char *)val);
  } else if (!strcmp(name, "country")) {
    curr_conn->country = strdup((char *)val);
  } else if (!strcmp(name, "city")) {
    curr_conn->city = strdup((char *)val);
  } else if (!strcmp(name, "admin")) {
    curr_conn->admin = strdup((char *)val);
  } else if (!strcmp(name, "description")) {
    curr_conn->description = strdup((char *)val);
  } else if (!strcmp(name, "html_url")) {
    curr_conn->html_url = strdup((char *)val);
  } else if (!strcmp(name, "connect")) {
    curr_conn->connect = (bool)*(int *)val;
  } else if (!strcmp(name, "connect_timeout")) {
    curr_conn->connect_timeout = (SilcUInt32)*(int *)val;
  } else if (!strcmp(name, "starttime")) {
    curr_conn->starttime = (bool)*(int *)val;
  } else if (!strcmp(name, "uptime")) {
    curr_conn->uptime = (bool)*(int *)val;
  } else if (!strcmp(name, "clients")) {
    curr_conn->clients = (bool)*(int *)val;
  } else if (!strcmp(name, "channels")) {
    curr_conn->channels = (bool)*(int *)val;
  } else if (!strcmp(name, "server_ops")) {
    curr_conn->server_ops = (bool)*(int *)val;
  } else if (!strcmp(name, "router_ops")) {
    curr_conn->router_ops = (bool)*(int *)val;
  } else if (!strcmp(name, "cell_clients")) {
    curr_conn->cell_clients = (bool)*(int *)val;
  } else if (!strcmp(name, "cell_channels")) {
    curr_conn->cell_channels = (bool)*(int *)val;
  } else if (!strcmp(name, "cell_servers")) {
    curr_conn->cell_servers = (bool)*(int *)val;
  } else if (!strcmp(name, "all_clients")) {
    curr_conn->all_clients = (bool)*(int *)val;
  } else if (!strcmp(name, "all_channels")) {
    curr_conn->all_channels = (bool)*(int *)val;
  } else if (!strcmp(name, "all_servers")) {
    curr_conn->all_servers = (bool)*(int *)val;
  } else if (!strcmp(name, "all_routers")) {
    curr_conn->all_routers = (bool)*(int *)val;
  } else if (!strcmp(name, "all_server_ops")) {
    curr_conn->all_server_ops = (bool)*(int *)val;
  } else if (!strcmp(name, "all_router_ops")) {
    curr_conn->all_router_ops = (bool)*(int *)val;
  } else if (!strcmp(name, "motd")) {
    curr_conn->motd = (bool)*(int *)val;
  } else if (!strcmp(name, "up_color")) {
    curr_conn->up_color = strdup((char *)val);
  } else if (!strcmp(name, "down_color")) {
    curr_conn->down_color = strdup((char *)val);
  } else if (!strcmp(name, "up_text_color")) {
    curr_conn->up_text_color = strdup((char *)val);
  } else if (!strcmp(name, "down_text_color")) {
    curr_conn->down_text_color = strdup((char *)val);
  } else {
    retval = SILC_CONFIG_ESILENT;
  }

  return retval;
}

/* Command: loadmap, loadmaps the bitmap map image. */

SILC_CONFIG_CALLBACK(silc_map_cmd_loadmap)
{
  SilcMap map = context;
  int retval = SILC_CONFIG_OK;

  if (type == SILC_CONFIG_ARG_BLOCK) {
    if (!filename)
      return SILC_CONFIG_EMISSFIELDS;

    SILC_LOG_DEBUG(("loadmap: file: %s", filename));

    /* Destroy old bitmap if loadmaped */
    silc_free(map->bitmap);

    /* Loadmap the bitmap image */
    if (!silc_map_load_ppm(map, filename))
      retval = SILC_CONFIG_ESILENT;

    /* Cleanup */
    silc_free(filename);
    filename = NULL;

    return retval;
  }

  if (!strcmp(name, "filename"))
    filename = strdup((char *)val);
  else
    retval = SILC_CONFIG_ESILENT;

  return retval;
}

/* Command: writemap, writemap the map into bitmap file. */

SILC_CONFIG_CALLBACK(silc_map_cmd_writemap)
{
  SilcMap map = context;
  int retval = SILC_CONFIG_OK;

  if (type == SILC_CONFIG_ARG_BLOCK) {
    if (!filename)
      return SILC_CONFIG_EMISSFIELDS;

    SILC_LOG_DEBUG(("writemap: file: %s", filename));

    /* Execute directly if there are no connections */
    if (map->conns_num == 0) {
      /* Writemap the map */
      if (!silc_map_write_ppm(map, filename))
	retval = SILC_CONFIG_ESILENT;
    } else {
      map->writemap.filename = strdup(filename);
      map->writemap.writemap = TRUE;
    }

    /* Cleanup */
    silc_free(filename);
    filename = NULL;

    return retval;
  }

  if (!strcmp(name, "filename"))
    filename = strdup((char *)val);
  else
    retval = SILC_CONFIG_ESILENT;

  return retval;
}

/* Command: writemaphtml, writes HTML map of the image map. */

SILC_CONFIG_CALLBACK(silc_map_cmd_writemaphtml)
{
  SilcMap map = context;
  int retval = SILC_CONFIG_OK;

  if (type == SILC_CONFIG_ARG_BLOCK) {
    int i;
    if (!filename)
      return SILC_CONFIG_EMISSFIELDS;

    SILC_LOG_DEBUG(("writemaphtml: file: %s", filename));

    /* Will generate HTML map page */
    i = map->writemaphtml_count;
    map->writemaphtml = silc_realloc(map->writemaphtml,
				     sizeof(*map->writemaphtml) * (i + 1));
    map->writemaphtml[i].filename = filename;
    map->writemaphtml[i].text = text;
    if (lon)
      map->writemaphtml[i].x = silc_map_lon2x(map, lon);
    if (lat)
      map->writemaphtml[i].y = silc_map_lat2y(map, lat);
    map->writemaphtml[i].writemaphtml = TRUE;
    map->writemaphtml_count++;

    /* Clean up */
    silc_free(lat);
    silc_free(lon);
    filename = NULL;
    text = NULL;
    lat = lon = NULL;

    return retval;
  }

  if (!strcmp(name, "filename"))
    filename = strdup((char *)val);
  else if (!strcmp(name, "image"))
    text = strdup((char *)val);
  else if (!strcmp(name, "cut_lat"))
    lat = strdup((char *)val);
  else if (!strcmp(name, "cut_lon"))
    lon = strdup((char *)val);
  else
    retval = SILC_CONFIG_ESILENT;

  return retval;
}

/* Command: writehtml, writes the gathered data into HTML pages. */

SILC_CONFIG_CALLBACK(silc_map_cmd_writehtml)
{
  SilcMap map = context;
  int retval = SILC_CONFIG_OK;

  if (type == SILC_CONFIG_ARG_BLOCK) {
    if (!filename)
      return SILC_CONFIG_EMISSFIELDS;

    SILC_LOG_DEBUG(("writehtml: file: %s", filename));

    /* Will generate HTML pages */
    map->writehtml.filename = filename;
    map->writehtml.text = text;		/* class */
    map->writehtml.writehtml = TRUE;
    filename = text = NULL;

    return retval;
  }
  if (!strcmp(name, "filename"))
    filename = strdup((char *)val);
  else if (!strcmp(name, "class"))
    text = strdup((char *)val);
  else
    retval = SILC_CONFIG_ESILENT;

  return retval;
}

/* Command: writerel, writes the uptime reliability graph. */

SILC_CONFIG_CALLBACK(silc_map_cmd_writerel)
{
  SilcMap map = context;
  int retval = SILC_CONFIG_OK;

  if (type == SILC_CONFIG_ARG_BLOCK) {
    if (!filename)
      return SILC_CONFIG_EMISSFIELDS;

    SILC_LOG_DEBUG(("writerel: file: %s", filename));

    /* Will generate uptime reliability graph */
    map->writerel.filename = filename;
    map->writerel.text = text;		/* class */
    map->writerel.writerel = TRUE;
    filename = text = NULL;

    return retval;
  }
  if (!strcmp(name, "filename"))
    filename = strdup((char *)val);
  else if (!strcmp(name, "class"))
    text = strdup((char *)val);
  else
    retval = SILC_CONFIG_ESILENT;

  return retval;
}

/* Command: cut, cut's a specified area from the map. */

SILC_CONFIG_CALLBACK(silc_map_cmd_cut)
{
  SilcMap map = context;
  int retval = SILC_CONFIG_OK;
  bool ret;

  if (type == SILC_CONFIG_ARG_BLOCK) {
    SilcMap map2;
    int i;

    if (!filename || !lat || !lon || !width || !height)
      return SILC_CONFIG_EMISSFIELDS;

    SILC_LOG_DEBUG(("cut: lat: %s lon: %s w: %ld h: %ld file: %s",
		    lat, lon, width, height, filename));

    /* Execute directly if not inside connection block */
    if (!curr_conn) {
      if (!map->conns_num) {
	/* Before any connection blocks */

	/* Cut the chunk from the map. */
	ret = silc_map_cut(map, silc_map_lon2x(map, lon),
			   silc_map_lat2y(map, lat),
			   width, height, &map2);
	if (ret) {
	  /* Writemap the chunk. */
	  ret = silc_map_write_ppm(map2, filename);
	  silc_map_free(map2);
	}
	if (!ret)
	  retval = SILC_CONFIG_ESILENT;
      } else {
	/* After all connection blocks */
	i = map->cut_count;
	map->cut = silc_realloc(map->cut, sizeof(*map->cut) * (i + 1));
	map->cut[i].filename = strdup(filename);
	map->cut[i].x = silc_map_lon2x(map, lon);
	map->cut[i].y = silc_map_lat2y(map, lat);
	map->cut[i].width = width;
	map->cut[i].height = height;
	map->cut[i].cut = TRUE;
	map->cut_count++;
      }
    } else {
      SilcMapCommand cmd = silc_calloc(1, sizeof(*cmd));
      if (!cmd)
	return SILC_CONFIG_ESILENT;

      silc_dlist_add(curr_conn->commands, cmd);
      cmd->filename = strdup(filename);
      cmd->x = silc_map_lon2x(map, lon);
      cmd->y = silc_map_lat2y(map, lat);
      cmd->width = width;
      cmd->height = height;
      cmd->cut = TRUE;
    }

    /* Cleanup */
    silc_free(filename);
    silc_free(lat);
    silc_free(lon);
    filename = NULL;
    lat = NULL;
    lon = NULL;
    width = 0;
    height = 0;

    return retval;
  }

  if (!strcmp(name, "lat"))
    lat = strdup((char *)val);
  else if (!strcmp(name, "lon"))
    lon = strdup((char *)val);
  else if (!strcmp(name, "width"))
    width = (SilcUInt32)*(int *)val;
  else if (!strcmp(name, "height"))
    height = (SilcUInt32)*(int *)val;
  else if (!strcmp(name, "filename"))
    filename = strdup((char *)val);
  else
    retval = SILC_CONFIG_ESILENT;

  return retval;
}

/* Command: rectangle, draws a rectangle on the map. */

SILC_CONFIG_CALLBACK(silc_map_cmd_rectangle)
{
  SilcMap map = context;
  int retval = SILC_CONFIG_OK;
  bool ret;

  if (type == SILC_CONFIG_ARG_BLOCK) {
    if (!lat || !lon)
      return SILC_CONFIG_EMISSFIELDS;

    SILC_LOG_DEBUG(("rectangle: lat: %s lon: %s color: %d %d %d",
		    lat, lon, r, g, b));

    if (lr == -1) {
      lr = r;
      lg = g;
      lb = b;
    }

    /* Execute directly if not for connection */
    if (!curr_conn) {
      /* Draw the rectangle */
      ret = silc_map_draw_rectangle(map, silc_map_lon2x(map, lon),
				    silc_map_lat2y(map, lat),
				    r, g, b, text, lposx, lposy, lr, lg, lb);
      if (!ret)
	retval = SILC_CONFIG_ESILENT;
    } else {
      SilcMapCommand cmd = silc_calloc(1, sizeof(*cmd));
      if (!cmd)
	return SILC_CONFIG_ESILENT;

      silc_dlist_add(curr_conn->commands, cmd);
      cmd->r = r;
      cmd->g = g;
      cmd->b = b;
      cmd->lr = lr;
      cmd->lg = lg;
      cmd->lb = lb;
      cmd->x = silc_map_lon2x(map, lon);
      cmd->y = silc_map_lat2y(map, lat);
      cmd->text = text ? strdup(text) : NULL;
      cmd->lposx = lposx;
      cmd->lposy = lposy;
      cmd->draw_rectangle = TRUE;
      cmd->color_set = color_set;
      cmd->lcolor_set = lcolor_set;
    }

    /* Cleanup */
    silc_free(text);
    silc_free(lat);
    silc_free(lon);
    text = NULL;
    lat = NULL;
    lon = NULL;
    lposx = 0;
    lposy = 0;
    lr = lg = lb = -1;
    color_set = lcolor_set = FALSE;

    return retval;
  }

  if (!strcmp(name, "lat"))
    lat = strdup((char *)val);
  else if (!strcmp(name, "lon"))
    lon = strdup((char *)val);
  else if (!strcmp(name, "color")) {
    if (!silc_map_parse_color((const char *)val, &r, &g, &b))
      retval = SILC_CONFIG_ESILENT;
    color_set = TRUE;
  } else if (!strcmp(name, "label"))
    text = strdup((char *)val);
  else if (!strcmp(name, "lposx"))
    lposx = (SilcInt32)*(int *)val;
  else if (!strcmp(name, "lposy"))
    lposy = (SilcInt32)*(int *)val;
  else if (!strcmp(name, "lcolor")) {
    if (!silc_map_parse_color((const char *)val, &lr, &lg, &lb))
      retval = SILC_CONFIG_ESILENT;
    lcolor_set = TRUE;
 } else
    retval = SILC_CONFIG_ESILENT;

  return retval;
}

/* Command: circle, draws a circle on the map. */

SILC_CONFIG_CALLBACK(silc_map_cmd_circle)
{
  SilcMap map = context;
  int retval = SILC_CONFIG_OK;
  bool ret;

  if (type == SILC_CONFIG_ARG_BLOCK) {
    if (!lat || !lon)
      return SILC_CONFIG_EMISSFIELDS;

    SILC_LOG_DEBUG(("circle: lat: %s lon: %s color: %d %d %d",
		    lat, lon, r, g, b));

    if (lr == -1) {
      lr = r;
      lg = g;
      lb = b;
    }

    /* Execute directly if not for connection */
    if (!curr_conn) {
      /* Draw the circle */
      ret = silc_map_draw_circle(map, silc_map_lon2x(map, lon),
				 silc_map_lat2y(map, lat),
				 r, g, b, text, lposx, lposy, lr, lg, lb);
      if (!ret)
	retval = SILC_CONFIG_ESILENT;
    } else {
      SilcMapCommand cmd = silc_calloc(1, sizeof(*cmd));
      if (!cmd)
	return SILC_CONFIG_ESILENT;

      silc_dlist_add(curr_conn->commands, cmd);
      cmd->r = r;
      cmd->g = g;
      cmd->b = b;
      cmd->lr = lr;
      cmd->lg = lg;
      cmd->lb = lb;
      cmd->x = silc_map_lon2x(map, lon);
      cmd->y = silc_map_lat2y(map, lat);
      cmd->text = text ? strdup(text) : NULL;
      cmd->lposx = lposx;
      cmd->lposy = lposy;
      cmd->draw_circle = TRUE;
      cmd->color_set = color_set;
      cmd->lcolor_set = lcolor_set;
    }

    /* Cleanup */
    silc_free(text);
    silc_free(lat);
    silc_free(lon);
    text = NULL;
    lat = NULL;
    lon = NULL;
    lposx = 0;
    lposy = 0;
    lr = lg = lb = -1;
    color_set = lcolor_set = FALSE;

    return retval;
  }

  if (!strcmp(name, "lat"))
    lat = strdup((char *)val);
  else if (!strcmp(name, "lon"))
    lon = strdup((char *)val);
  else if (!strcmp(name, "color")) {
    if (!silc_map_parse_color((const char *)val, &r, &g, &b))
      retval = SILC_CONFIG_ESILENT;
    color_set = TRUE;
  } else if (!strcmp(name, "label"))
    text = strdup((char *)val);
  else if (!strcmp(name, "lposx"))
    lposx = (SilcInt32)*(int *)val;
  else if (!strcmp(name, "lposy"))
    lposy = (SilcInt32)*(int *)val;
  else if (!strcmp(name, "lcolor")) {
    if (!silc_map_parse_color((const char *)val, &lr, &lg, &lb))
      retval = SILC_CONFIG_ESILENT;
    lcolor_set = TRUE;
  } else
    retval = SILC_CONFIG_ESILENT;

  return retval;
}

/* Command: line, draws a line between two points in the map. */

SILC_CONFIG_CALLBACK(silc_map_cmd_line)
{
  SilcMap map = context;
  int retval = SILC_CONFIG_OK;
  bool ret;

  if (type == SILC_CONFIG_ARG_BLOCK) {
    if (!lat || !lon || !lat2 || !lon2)
      return SILC_CONFIG_EMISSFIELDS;

    SILC_LOG_DEBUG(("line: alat: %s alon: %s blat: %s blon: %s "
		    "width: %ld color: %d %d %d",
		    lat, lon, lat2, lon2, width, r, g, b));

    if (!width)
      width = 1;

    /* Execute directly if not for connection */
    if (!curr_conn) {
      /* Draw the line */
      ret = silc_map_draw_line(map, width,
			       silc_map_lon2x(map, lon),
			       silc_map_lat2y(map, lat),
			       silc_map_lon2x(map, lon2),
			       silc_map_lat2y(map, lat2),
			       r, g, b);
      if (!ret)
	retval = SILC_CONFIG_ESILENT;
    } else {
      SilcMapCommand cmd = silc_calloc(1, sizeof(*cmd));
      if (!cmd)
	return SILC_CONFIG_ESILENT;

      silc_dlist_add(curr_conn->commands, cmd);
      cmd->r = r;
      cmd->g = g;
      cmd->b = b;
      cmd->x = silc_map_lon2x(map, lon);
      cmd->y = silc_map_lat2y(map, lat);
      cmd->x2 = silc_map_lon2x(map, lon2);
      cmd->y2 = silc_map_lat2y(map, lat2);
      cmd->width = width;
      cmd->draw_line = TRUE;
      cmd->color_set = color_set;
    }

    /* Cleanup */
    silc_free(lat);
    silc_free(lon);
    silc_free(lat2);
    silc_free(lon2);
    lat = NULL;
    lon = NULL;
    lat2 = NULL;
    lon2 = NULL;
    width = 0;
    color_set = FALSE;

    return retval;
  }

  if (!strcmp(name, "a_lat"))
    lat = strdup((char *)val);
  else if (!strcmp(name, "a_lon"))
    lon = strdup((char *)val);
  else if (!strcmp(name, "b_lat"))
    lat2 = strdup((char *)val);
  else if (!strcmp(name, "b_lon"))
    lon2 = strdup((char *)val);
  else if (!strcmp(name, "width"))
    width = (SilcUInt32)*(int *)val;
  else if (!strcmp(name, "color")) {
    if (!silc_map_parse_color((const char *)val, &r, &g, &b))
      retval = SILC_CONFIG_ESILENT;
    color_set = TRUE;
  } else
    retval = SILC_CONFIG_ESILENT;

  return retval;
}

/* Command: text, prints a text on the map. */

SILC_CONFIG_CALLBACK(silc_map_cmd_text)
{
  SilcMap map = context;
  int retval = SILC_CONFIG_OK;
  bool ret;

  if (type == SILC_CONFIG_ARG_BLOCK) {
    if (!lat || !lon || !text)
      return SILC_CONFIG_EMISSFIELDS;

    SILC_LOG_DEBUG(("text: lat: %s lon: %s color: %d %d %d text: %s",
		    lat, lon, r, g, b, text));

    /* Execute directly if not for connection */
    if (!curr_conn) {
      /* Print the text */
      ret = silc_map_draw_text(map, text,
			       silc_map_lon2x(map, lon),
			       silc_map_lat2y(map, lat),
			       r, g, b);
      if (!ret)
	retval = SILC_CONFIG_ESILENT;
    } else {
      SilcMapCommand cmd = silc_calloc(1, sizeof(*cmd));
      if (!cmd)
	return SILC_CONFIG_ESILENT;

      silc_dlist_add(curr_conn->commands, cmd);
      cmd->r = r;
      cmd->g = g;
      cmd->b = b;
      cmd->x = silc_map_lon2x(map, lon);
      cmd->y = silc_map_lat2y(map, lat);
      cmd->text = text ? strdup(text) : NULL;
      cmd->draw_text = TRUE;
      cmd->color_set = color_set;
    }

    /* Cleanup */
    silc_free(text);
    silc_free(lat);
    silc_free(lon);
    text = NULL;
    lat = NULL;
    lon = NULL;
    color_set = FALSE;

    return retval;
  }

  if (!strcmp(name, "lat"))
    lat = strdup((char *)val);
  else if (!strcmp(name, "lon"))
    lon = strdup((char *)val);
  else if (!strcmp(name, "color")) {
    if (!silc_map_parse_color((const char *)val, &r, &g, &b))
      retval = SILC_CONFIG_ESILENT;
    color_set = TRUE;
  } else if (!strcmp(name, "text"))
    text = strdup((char *)val);
  else
    retval = SILC_CONFIG_ESILENT;

  return retval;
}

/* Parses the commands from the file `filename'. */

bool silc_map_commands_parse(SilcMap map, const char *filename)
{
  SilcConfigEntity ent;
  SilcConfigFile *file;
  bool retval = TRUE;
  int ret;

  SILC_LOG_DEBUG(("Parsing commands"));

  /* Open commands file */
  file = silc_config_open(filename);
  if (!file) {
    fprintf(stderr, "Cannot open commands file '%s'\n", filename);
    return FALSE;
  }

  /* Parse the commands */
  ent = silc_config_init(file);
  silc_config_register_table(ent, silc_map_table_main, map);
  ret = silc_config_main(ent);

  SILC_LOG_DEBUG(("Parsing status: %s", silc_config_strerror(ret)));

  if (ret && ret != SILC_CONFIG_ESILENT) {
    fprintf(stderr, "Error parsing commands: %s, line %ld\n",
	    silc_config_strerror(ret), silc_config_get_line(file));
    retval = FALSE;
  }

  /* Cleanup */
  silc_config_close(file);
  return retval;
}
