/*

  silcmap_bitmap.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2004 Pekka Riikonen

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
#include <math.h>
#include "silcmap.h"
#include "data.h"

/******* Bitmap Routines *****************************************************/

/* Load a bitmap file.  The file is the map image that is loaded into
   the SilcMap context.  This is no perfect PPM loader. */

bool silc_map_load_ppm(SilcMap map, const char *filename)
{
  int fd;
  char type[3];
  unsigned char header[80];
  int ret, retval = TRUE, i;

  SILC_LOG_DEBUG(("Load PPM '%s'", filename));

  fd = open(filename, O_RDONLY, 0600);
  if (fd < 0) {
    fprintf(stderr, "open: %s: %s\n", strerror(errno), filename);
    return FALSE;
  }

  /* Read file header */
  memset(header, 0, sizeof(header));
  ret = read(fd, (void *)header, sizeof(header) - 1);
  if (ret < 0) {
    fprintf(stderr, "read: %s: %s\n", strerror(errno), filename);
    return FALSE;
  }

  /* Read width and height */
  ret = sscanf(header, "%2s %ld %ld %ld\n", type,
	       (unsigned long *)&map->width,
	       (unsigned long *)&map->height,
	       (unsigned long *)&map->maxcolor);
  if (ret < 4) {
    fprintf(stderr, "Invalid PPM file");
    retval = FALSE;
    goto out;
  }

  for (i = sizeof(header) - 1; i >= 0; i--)
    if (header[i] == '\n' || header[i] == ' ')
      break;
  lseek(fd, i + 1, SEEK_SET);

  /* Read the picture */
  map->bitmap_size = map->width * 3 * map->height;
  map->bitmap = silc_malloc(map->bitmap_size);
  ret = read(fd, map->bitmap, map->bitmap_size);
  if (ret < 0) {
    fprintf(stderr, "read: %s\n", strerror(errno));
    retval = FALSE;
    goto out;
  }

 out:
  close(fd);
  return retval;
}

/* Write the map into a bitmap file. */

bool silc_map_write_ppm(SilcMap map, const char *filename)
{
  int fd;
  int retval = TRUE;
  char header[80];

  SILC_LOG_DEBUG(("Write PPM '%s'", filename));

  fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0600);
  if (fd < 0) {
    fprintf(stderr, "open: %s: %s\n", strerror(errno), filename);
    return FALSE;
  }

  /* Write the header */
  memset(header, 0, sizeof(header));
  snprintf(header, sizeof(header) - 1, "P6 %ld %ld %ld\n",
	  (unsigned long)map->width,
	  (unsigned long)map->height,
	  (unsigned long)map->maxcolor);
  write(fd, header, strlen(header));

  /* Write the bitmap */
  write(fd, map->bitmap, map->bitmap_size);
  close(fd);

  return retval;
}

/* Cut the map into a `width' * `height' size chunk at `x' and `y'.  This
   returns the allocated map bitmap into `ret_bitmap'.  The original map
   is not modified. */

bool silc_map_cut(SilcMap map, SilcInt32 x, SilcInt32 y,
		  SilcUInt32 width, SilcUInt32 height,
		  SilcMap *ret_map)
{
  int i;

  SILC_LOG_DEBUG(("cut"));

  /* Sanity checks */
  if (height > map->height - y) {
    fprintf(stderr, "Requesting too much height: %ld\n",
	    (unsigned long)height);
    return FALSE;
  }
  if (width > map->width - x) {
    fprintf(stderr, "Requesting too much width: %ld\n",
	    (unsigned long)width);
    return FALSE;
  }

  /* Compute coordinates in the bitmap */
  y = (map->width * 3) * y;
  x = (x * 3);

  /* Allocate new SilcMap context */
  *ret_map = silc_calloc(1, sizeof(**ret_map));
  (*ret_map)->width = width;
  (*ret_map)->height = height;
  (*ret_map)->maxcolor = map->maxcolor;
  (*ret_map)->bitmap_size = (width * 3) * height;
  (*ret_map)->bitmap = silc_malloc((*ret_map)->bitmap_size);

  /* Copy the requested area */
  for (i = 0; i < height; i++) {
    memcpy((*ret_map)->bitmap + (i * width * 3),
	   map->bitmap + y + x, width * 3);

    /* Next line */
    y += (map->width * 3);
  }

  return TRUE;
}

/* Draw a bitmap indicated by `bitmap' of size of `width' * 'height'
   into the SilcMap context into the coordinates `x' and `y' (the upper left
   corner of the bitmap will be at x and y).  The `bitmap' must be RGB
   color bitmap. */

bool silc_map_draw(SilcMap map,
		   SilcInt32 x, SilcInt32 y,
		   const unsigned char *bitmap,
		   SilcUInt32 width, SilcUInt32 height)
{
  int i, k;
  unsigned char val;

  /* Compute coordinates in the bitmap */
  y = (map->width * 3) * y;
  x = (x * 3);

  /* Draw the bitmap into the map bitmap */
  for (i = 0; i < height; i++) {
    for (k = 0; k < width; k++) {
      val = bitmap[i * (width * 3) + (k * 3)];
      map->bitmap[y + x + (k * 3)    ] = val;		  /* R */

      val = bitmap[i * (width * 3) + (k * 3) + 1];
      map->bitmap[y + x + (k * 3) + 1] = val;		  /* G */

      val = bitmap[i * (width * 3) + (k * 3) + 2];
      map->bitmap[y + x + (k * 3) + 2] = val;		  /* B */
    }

    /* Next line */
    y += (map->width * 3);
  }

  return TRUE;
}

/* Same as silc_map_draw but the `bitmap' is a grayscale bitmap
   and the RGB color information is provided as argument to this function. */

bool silc_map_draw_raw(SilcMap map,
		       SilcInt32 x, SilcInt32 y,
		       const unsigned char *bitmap,
		       SilcUInt32 width, SilcUInt32 height,
		       SilcInt16 r, SilcInt16 g, SilcInt16 b)
{
  int i, k;
  unsigned char val;

  /* Compute coordinates in the bitmap */
  y = (map->width * 3) * y;
  x = (x * 3);

  /* Draw the bitmap into the map bitmap */
  for (i = 0; i < height; i++) {
    for (k = 0; k < width; k++) {
      val = bitmap[i * width + k];
      if (val != 0) {
        map->bitmap[y + x + (k * 3)    ] = r;		  /* R */
        map->bitmap[y + x + (k * 3) + 1] = g;		  /* G */
        map->bitmap[y + x + (k * 3) + 2] = b;		  /* B */
      }
    }

    /* Next line */
    y += (map->width * 3);
  }

  return TRUE;
}

/* Draw a straight line between points a and b.  The coordinates for the
   points are provided as arguments.  The `width' is the line width in
   pixels.  The RGB color for the line can be provided too.  Implements
   DDA algorithm. */

bool silc_map_draw_line(SilcMap map, SilcUInt32 width,
			SilcInt32 a_x, SilcInt32 a_y,
			SilcInt32 b_x, SilcInt32 b_y,
			SilcInt16 r, SilcInt16 g, SilcInt16 b)
{
  unsigned char p[3] = { r, g, b };
  int xdiff, ydiff, i;
  double x, y, slox, sloy;

  SILC_LOG_DEBUG(("draw_line"));

  /* Compute the difference of points */
  xdiff = b_x - a_x;
  ydiff = b_y - a_y;
  if (!xdiff && !ydiff)
    return FALSE;

  /* Draw the line */
  if (abs(xdiff) > abs(ydiff)) {
    sloy = (double)ydiff / (double)xdiff;
    y = a_y + 0.5;			 /* rounding */
    if (xdiff > 0) {
      for (x = a_x; x <= b_x; x++)  {
	for (i = 0; i < width; i++)
	  silc_map_draw(map, x + i, floor(y), p, 1, 1);
	y += sloy;
      }
    } else {
      for (x = a_x; x >= b_x; x--)  {
	for (i = 0; i < width; i++)
	  silc_map_draw(map, x + i, floor(y), p, 1, 1);
	y -= sloy;
      }
    }
  } else  {
    slox = (double)xdiff / (double)ydiff;
    x = a_x + 0.5;			 /* rounding */
    if (ydiff > 0) {
      for (y = a_y; y <= b_y; y++)  {
	for (i = 0; i < width; i++)
	  silc_map_draw(map, floor(x + i), y, p, 1, 1);
	x += slox;
      }
    } else {
      for (y = a_y; y >= b_y; y--)  {
	for (i = 0; i < width; i++)
	  silc_map_draw(map, floor(x + i), y, p, 1, 1);
	x -= slox;
      }
    }
  }

  return TRUE;
}

/* Print the text string `text' on the bitmap at `x' and `y'.  The color
   for the text can be provided as argument. */

bool silc_map_draw_text(SilcMap map, const char *text,
			SilcInt32 x, SilcInt32 y,
			SilcInt16 r, SilcInt16 g, SilcInt16 b)
{
  int k, w;
  int c;

  SILC_LOG_DEBUG(("draw_text"));

  /* Write the text. */
  w = 0;
  for (k = 0; k < strlen(text); k++) {
    c = text[k] - 33;
    silc_map_draw_raw(map, x + w, y,
		      map->font.font[c].data,
		      map->font.font[c].width,
		      map->font.height, r, g, b);
    w += map->font.font[c].width;
  }

  return TRUE;
}

/* Draw circle on the bitmap map at `x' and `y'.  The center of the
   circle will be at the `x' and `y'.  If the `label' is provided the
   text will appear with the circle at `lposx' and `lposy' in relation
   with the circle. */

bool silc_map_draw_circle(SilcMap map, SilcInt32 x, SilcInt32 y,
			  SilcInt16 r, SilcInt16 g, SilcInt16 b,
			  const char *label, SilcInt32 lposx, SilcInt32 lposy,
			  SilcInt16 lr, SilcInt16 lg, SilcInt16 lb)
{
  bool ret;

  SILC_LOG_DEBUG(("draw_circle"));

  y = y - (silc_map_circle.height / 2);
  x = x - (silc_map_circle.width / 2);

  ret = silc_map_draw_raw(map, x, y,
			  silc_map_circle.data,
			  silc_map_circle.width, silc_map_circle.height,
			  r, g, b);
  if (!ret)
    return FALSE;

  if (label)
    ret = silc_map_draw_text(map, label, x + lposx, y - lposy, lr, lg, lb);

  return ret;
}

/* Draw rectangle on the bitmap map at `x' and `y'.  The center of the
   rectangle will be at the `x' and `y'.  If the `label' is provided the
   text will appear with the circle at `lposx' and `lposy' in relation
   with the circle. */

bool silc_map_draw_rectangle(SilcMap map, SilcInt32 x, SilcInt32 y,
			     SilcInt16 r, SilcInt16 g, SilcInt16 b,
			     const char *label,
			     SilcInt32 lposx, SilcInt32 lposy,
			     SilcInt16 lr, SilcInt16 lg, SilcInt16 lb)
{
  bool ret;

  SILC_LOG_DEBUG(("draw_rectangle"));

  y = y - (silc_map_rectangle.height / 2);
  x = x - (silc_map_rectangle.width / 2);

  ret = silc_map_draw_raw(map, x, y,
			  silc_map_rectangle.data, silc_map_rectangle.width,
			  silc_map_rectangle.height,
			  r, g, b);
  if (!ret)
    return FALSE;

  if (label)
    ret = silc_map_draw_text(map, label, x + lposx, y - lposy, lr, lg, lb);

  return ret;
}

/* Parses the degree position string.  For example, longitude 40 23 10,
   as in 40 degrees, 23 minutes and 10 seconds east.  Negative degree is to
   West.  For latitude positive is north and negative south. */

double silc_map_parse_pos(char *pos)
{
  double d = 0, m = 0, s = 0;
  int ret;

  ret = sscanf(pos, "%lf %lf %lf", &d, &m, &s);
  if (ret < 1) {
    fprintf(stderr, "Malfromed position string '%s'\n", pos);
    return 0;
  }

  if (d < 0) {
    m = (m < 0 ? m : -m);
    s = (s < 0 ? s : -s);
  }

  return ((d < 0 ? -1 : d > 0 ? 1 : 0) *
	  abs(d) + (m / 60) + (s / 3600));
}

/* Converts longitude into position in the bitmap */

int silc_map_lon2x(SilcMap map, char *longitude)
{
  double meridian, aspmul, lon;

  /* Parse position string */
  lon = silc_map_parse_pos(longitude);

  /* Compute "aspect ratio multiplier" to get the position in the map. */
  meridian = (double)map->width / (double)2.0;
  aspmul = meridian / 180.0;

  /* Compute the position in the bitmap map */
  return (int)(double)(meridian + (lon * aspmul));
}

/* Converts latitude into position in the bitmap */

int silc_map_lat2y(SilcMap map, char *latitude)
{
  double meridian, aspmul, lat;

  /* Parse position string */
  lat = silc_map_parse_pos(latitude);

  /* Compute "aspect ratio multiplier" to get the position in the map. */
  meridian = (double)map->height / (double)2.0;
  aspmul = meridian / 90.0;

  /* Compute the position in the bitmap map */
  return (int)(double)(meridian - (lat * aspmul));
}

/* Parses RGB color string. */

bool silc_map_parse_color(const char *color,
			  SilcInt16 *r, SilcInt16 *g, SilcInt16 *b)
{
  int ret;
  int rr, gg, bb;

  ret = sscanf(color, "%d %d %d", &rr, &gg, &bb);
  if (ret < 3) {
    fprintf(stderr, "Invalid color string: %s\n", color);
    return FALSE;
  }

  *r = (SilcInt16)rr;
  *g = (SilcInt16)gg;
  *b = (SilcInt16)bb;

  return TRUE;
}

/* Loads a font file.  The font file format is the following:

   height\n
   width
   font data
   width
   font data
   etc.

   If this function is called multiple times the new font replaces the
   old font. */

bool silc_map_load_font(SilcMap map, const char *filename)
{
  FILE *fp;
  int i, x, y;

  /* Load the file */
  fp = fopen(filename, "r");
  if (!fp) {
    fprintf(stderr, "fopen: %s: %s\n", strerror(errno), filename);
    return FALSE;
  }

  /* Read the font height */
  i = fscanf(fp, "%d\n", &map->font.height);
  if (i < 1)
    return FALSE;

  /* Read the font data */
  for (i = 0; i < 94; i++) {
    map->font.font[i].width = fgetc(fp);

    for (y = 0; y < map->font.height; y++)
      for (x = 0; x < map->font.font[i].width; x++)
	map->font.font[i].data[(y * map->font.font[i].width) + x] = fgetc(fp);
  }

  return TRUE;
}
