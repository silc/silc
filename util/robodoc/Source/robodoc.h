/*
 *    ROBODoc - a documentation extraction program for several languages.
 *
 *    Copyright (C) 1994-1999  Frans Slothouber and Jacco van Weert.
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 *    MA  02111-1307  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef VERSION
#define VERSION "unknown"
#endif

#define COMMENT_ROBODOC \
    "Generated with ROBODoc Version " VERSION " (" __DATE__ ")\n"
#define COMMENT_COPYRIGHT\
    "ROBODoc (c) 1994-2001 by Frans Slothouber and Jacco van Weert.\n"

#define DO_SORT             (1<<0)
#define DO_MAKE_XREFS       (1<<1)
#define DO_USE_XREFS        (1<<2)
#define DO_TOC              (1<<3)
#define DO_MAKE_DOCUMENT    (1<<4)
#define DO_INCLUDE_INTERNAL (1<<5)
#define DO_INTERNAL_ONLY    (1<<6)
#define DO_TELL             (1<<7)
#define DO_INDEX            (1<<8)
#define DO_SINGLEDOC        (1<<9)
#define DO_NOSOURCE         (1<<10)

/* Output Modes */

enum
  {
    ASCII = 0, AMIGAGUIDE, HTML, LATEX, RTF, SIZE_MODES
  };

/* Reserved for Future Use */

enum
  {
    ANSI, GNUINFO, TROFF, XML
  };

/* Evil macros !! */

#define skip_while(cond) { for (;*cur_char && (cond);cur_char++) ; }
#define find_eol   { for (;*cur_char && *cur_char!='\n';cur_char++) ; }
#define find_quote { for (;*cur_char && *cur_char!='\"';cur_char++) ; }

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE  1
#endif

/* Prototypes */

void RB_Analyse_Arguments (int, char **, char **, char **);
void RB_Set_Doc_Base (char *path);
void RB_Close_The_Shop (void);


#define MAX_LINE_LEN 512

extern char *whoami;
extern char *document_title;
extern int output_mode;
extern int course_of_action;
extern int tab_size;
extern char doc_base[1024];	/* PetteriK */
extern int line_number;
extern char line_buffer[MAX_LINE_LEN];
