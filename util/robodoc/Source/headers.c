#include <stdio.h>
#include <stddef.h>
#include "robodoc.h"
#include "headers.h"


/****v* ROBODoc/header_markers [3.0h]
 * NAME
 *   header_markers -- strings that mark the begin of a header.
 * FUNCTION
 *   These specify what robodoc recognizes as the beginning
 *   of a header.
 * SOURCE
 */

char *header_markers[] =
{
  "/****",			/* C, C++ */
  "//****",			/* C++ */
  "(****",			/* Pascal, Modula-2, B52 */
  "{****",			/* Pascal */
  ";****",			/* M68K assembler */
  "****",			/* M68K assembler */
  "C     ****",			/* Fortran */
  "REM ****",			/* BASIC */
  "%****",			/* LaTeX, TeX, Postscript */
  "#****",			/* Tcl/Tk */
  "      ****",			/* COBOL */
  "--****",			/* Occam */
  "<!--****",			/* HTML Code */
  "<!---****",			/* HTML Code,  the three-dashed comment 
				 * tells the [server] pre-processor not 
				 * to send that comment with the HTML */
  "|****",			/* GNU Assembler */
  "!!****",			/* FORTAN 90 */
  NULL};

/****/


/****v* ROBODoc/remark_markers [3.0h]
 * NAME
 *   remark_markers
 * FUNCTION
 *   These specify what robodoc recognizes as a comment marker.
 * SOURCE
 */

char *remark_markers[] =
{
  " *",				/* C, C++, Pascal, Modula-2 */
  "//",				/* C++ */
  "*",				/* C, C++, M68K assembler, Pascal, *
				 * Modula-2 */
  ";*",				/* M68K assembler */
  ";",				/* M68K assembler */
  "C    ",			/* Fortran */
  "REM ",			/* BASIC */
  "%",				/* LaTeX, TeX, Postscript */
  "#",				/* Tcl/Tk */
  "      *",			/* COBOL */
  "--",				/* Occam */
  "|",				/* GNU Assembler */
  "!!",				/* FORTAN 90 */
  NULL};

/****/

/****v* ROBODoc/end_markers [3.0h]
 * NAME
 *   end_markers -- strings that mark the end of a header.
 * FUNCTION
 *   These specify what robodoc recognizes as the end of a 
 *   documentation header. In most cases this will be
 *   "***" or " ***". If the header contains a SOURCE item
 *   then the end of the source has to be marked, which
 *   is when the other strings in this array are used.
 * SOURCE
 */

char *end_markers[] =
{
  "/***",			/* C, C++ */
  "//***",			/* C++ */
  " ***",			/* C, C++, Pascal, Modula-2 */
  "{***",			/* Pascal */
  "(***",			/* Pascal, Modula-2, B52 */
  ";***",			/* M68K assembler */
  "***",			/* M68K assembler */
  "C     ***",			/* Fortran */
  "REM ***",			/* BASIC */
  "%***",			/* LaTeX, TeX, Postscript */
  "#***",			/* Tcl/Tk */
  "      ***",			/* COBOL */
  "--***",			/* Occam */
  "<!--***",			/* HTML */
  "<!---***",			/* HTML */
  "|***",			/* GNU Assembler */
  "!!***",			/* FORTAN 90 */
  NULL};

/****/

/****v* ROBODoc/RB_header_typenames
 * NAME
 *   RB_header_typename
 * FUNCTION
 *   Handy table to translate a header type number (see RB_header_types)
 *   to an ascii string.
 *****
 */

char *RB_header_type_names[] =
{
  "none",
  "main",
  "generic",
  "internal",
  "function",
  "struct",
  "class",
  "method",
  "constant",
  "variable",
  "blank"
};

/****v* ROBODoc/first_header
 * NAME
 *   first_header -- pointer to the first header in the list of headers.
 * SOURCE
 */

struct RB_header *first_header = NULL;

/*****/

/****v* ROBODoc/last_header
 * NAME
 *   last_header -- pointer to the last header in the list of headers.
 * SOURCE
 */

struct RB_header *last_header = NULL;

/******/

/****v* ROBODoc/first_link
 * NAME
 *   first_link -- pointer to the first link in the list of links.
 * SOURCE
 */

struct RB_link *first_link = NULL;

/*****/


int header_index_size = 0;
struct RB_header **header_index = NULL;
