/*

  silcmap.h

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

#ifndef SILCMAP_H
#define SILCMAP_H

/* Font context */
typedef struct {
  int height;
  struct {
    char width;
    unsigned char data[16 * 16];
  } font[94];
} MapFonts;

/* SilcMap command context. */
typedef struct {
  /* Map command datas */
  char *filename;
  SilcInt32 x;
  SilcInt32 y;
  SilcInt32 x2;
  SilcInt32 y2;
  SilcUInt32 width;
  SilcUInt32 height;
  char *text;
  SilcInt32 lposx;
  SilcInt32 lposy;

  SilcInt16 r;
  SilcInt16 g;
  SilcInt16 b;
  SilcInt16 lr;
  SilcInt16 lg;
  SilcInt16 lb;
  unsigned int color_set      : 1;
  unsigned int lcolor_set     : 1;

  /* Command */
  unsigned int writemap       : 1;
  unsigned int writehtml      : 1;
  unsigned int writemaphtml   : 1;
  unsigned int cut            : 1;
  unsigned int draw_line      : 1;
  unsigned int draw_text      : 1;
  unsigned int draw_circle    : 1;
  unsigned int draw_rectangle : 1;
} *SilcMapCommand, SilcMapCommandStruct;

/* The SilcMap context. */
typedef struct {
  /* Connection data */
  SilcClient client;		/* SILC Client context */
  char *conffile;		/* Config file name */
  SilcDList conns;		/* Connections */
  SilcUInt32 conns_num;		/* Number of created connections */
  SilcUInt32 conn_num;		/* Current number of processed connections */

  /* Bitmap data */
  unsigned char *bitmap;	/* Loaded bitmap image */
  SilcUInt32 bitsilc_map_size;	/* Size of bitmap */
  SilcUInt32 width;		/* Bitmap width in pixels */
  SilcUInt32 height;		/* Bitmap height in pixels */
  SilcUInt32 maxcolor;		/* Max color value in bitmap */
  MapFonts font;		/* Current font */

  /* Output methods */
  SilcMapCommandStruct writemap;
  SilcMapCommandStruct writehtml;
  SilcMapCommandStruct writemaphtml;
  SilcMapCommandStruct cut;
} *SilcMap;

/* SilcMap connecetion context. */
typedef struct {
  /* Server and connection details */
  SilcDList hostnames;
  SilcDList ips;
  int port;
  char *public_key;
  char *country;
  char *city;
  char *admin;
  char *description;
  int connect_timeout;
  char *html_url;

  /* Flags */
  unsigned int connect        : 1;
  unsigned int starttime      : 1;
  unsigned int uptime         : 1;
  unsigned int clients        : 1;
  unsigned int channels       : 1;
  unsigned int server_ops     : 1;
  unsigned int router_ops     : 1;
  unsigned int cell_clients   : 1;
  unsigned int cell_channels  : 1;
  unsigned int cell_servers   : 1;
  unsigned int all_clients    : 1;
  unsigned int all_channels   : 1;
  unsigned int all_servers    : 1;
  unsigned int all_routers    : 1;
  unsigned int all_server_ops : 1;
  unsigned int all_router_ops : 1;
  unsigned int motd           : 1;
  unsigned int down           : 1;
  unsigned int stats_received : 1;
  unsigned int motd_received  : 1;

  /* Gathered data */
  struct {
    SilcUInt32 starttime;
    SilcUInt32 uptime;
    SilcUInt32 clients;
    SilcUInt32 channels;
    SilcUInt32 server_ops;
    SilcUInt32 router_ops;
    SilcUInt32 cell_clients;
    SilcUInt32 cell_channels;
    SilcUInt32 cell_servers;
    SilcUInt32 all_clients;
    SilcUInt32 all_channels;
    SilcUInt32 all_servers;
    SilcUInt32 all_routers;
    SilcUInt32 all_server_ops;
    SilcUInt32 all_router_ops;
    char *motd;
  } data;

  /* Status colors */
  char *up_color;
  char *down_color;
  char *up_text_color;
  char *down_text_color;

  /* Map commands */
  SilcDList commands;

  /* Back pointers */
  SilcMap map;
  SilcClientConnection conn;
} *SilcMapConnection;

extern SilcClientOperations silc_map_client_ops;

SilcMap silc_map_alloc(const char *conffile);
void silc_map_free(SilcMap map);
bool silc_map_commands_parse(SilcMap map, const char *filename);
void silc_map_connect(SilcMap map, SilcMapConnection mapconn);
bool silc_map_load_ppm(SilcMap map, const char *filename);
bool silc_map_write_ppm(SilcMap map, const char *filename);
bool silc_map_cut(SilcMap map, SilcInt32 x, SilcInt32 y,
		  SilcUInt32 width, SilcUInt32 height,
		  SilcMap *ret_map);
bool silc_map_draw(SilcMap map,
		   SilcInt32 x, SilcInt32 y,
		   const unsigned char *bitmap,
		   SilcUInt32 width, SilcUInt32 height);
bool silc_map_draw_raw(SilcMap map,
		       SilcInt32 x, SilcInt32 y,
		       const unsigned char *bitmap,
		       SilcUInt32 width, SilcUInt32 height,
		       SilcInt16 r, SilcInt16 g, SilcInt16 b);
bool silc_map_draw_line(SilcMap map, SilcUInt32 width,
			SilcInt32 a_x, SilcInt32 a_y,
			SilcInt32 b_x, SilcInt32 b_y,
			SilcInt16 r, SilcInt16 g, SilcInt16 b);
bool silc_map_draw_text(SilcMap map, const char *text,
			SilcInt32 x, SilcInt32 y,
			SilcInt16 r, SilcInt16 g, SilcInt16 b);
bool silc_map_draw_circle(SilcMap map, SilcInt32 x, SilcInt32 y,
			  SilcInt16 r, SilcInt16 g, SilcInt16 b,
			  const char *label, SilcInt32 lposx, SilcInt32 lposy,
			  SilcInt16 lr, SilcInt16 lg, SilcInt16 lb);
bool silc_map_draw_rectangle(SilcMap map, SilcInt32 x, SilcInt32 y,
			     SilcInt16 r, SilcInt16 g, SilcInt16 b,
			     const char *label, SilcInt32 lposx,
			     SilcInt32 lposy,
			     SilcInt16 lr, SilcInt16 lg, SilcInt16 lb);
double silc_map_parse_pos(char *pos);
int silc_map_lon2x(SilcMap map, char *latitude);
int silc_map_lat2y(SilcMap map, char *longitude);
bool silc_map_parse_color(const char *color,
			  SilcInt16 *r, SilcInt16 *g, SilcInt16 *b);
bool silc_map_load_font(SilcMap map, const char *filename);
bool silc_map_writehtml(SilcMap map, SilcMapConnection mapconn);
bool silc_map_writehtml_index(SilcMap map);
bool silc_map_writemaphtml(SilcMap map);

#endif /* SILCMAP_H */
