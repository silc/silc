/*   -*- c -*-
 * 
 *  ----------------------------------------------------------------------
 *  Deque for struct type with only one link pointer (x->next).
 *  ----------------------------------------------------------------------
 *  Created      : Fri Dec  5 11:19:37 1997 tri
 *  Last modified: Thu Apr 16 17:35:57 1998 tri
 *  ----------------------------------------------------------------------
 *  Copyright © 1995-1998
 *  Timo J. Rinne <tri@iki.fi>
 *  All rights reserved.  See file COPYRIGHT for details.
 * 
 *  Address: Cirion oy, PO-BOX 250, 00121 Helsinki, Finland
 *  ----------------------------------------------------------------------
 *  Any express or implied warranties are disclaimed.  In no event
 *  shall the author be liable for any damages caused (directly or
 *  otherwise) by the use of this software.
 *
 *  Please, send your patches to <tri@iki.fi>.
 *  ----------------------------------------------------------------------
 *
 * $Id$
 *
 * $Log$
 * Revision 1.1  2001/07/23 11:07:56  priikone
 * 	updates.
 *
 * Revision 1.1.1.1  2000/10/31 19:59:30  priikone
 * 	Imported TRQ and SilList and SilcDList API's.
 *
 * Revision 1.1  1998/04/16 14:39:42  tri
 * Initial revision
 *
 *
 */
#ifndef __TRQ_CONF__H__
#define __TRQ_CONF__H__ 1

/*
 * stddef.h is included here if such file exists.
 * offsetof should be defined there.
 */
#include <stddef.h>

/*
 * If compiler supports inline functions, __TRQ__INLINE__FUNCTION__
 * is defined to the correct keyword.  Usually this is defined
 * as inline, __inline__ or __inline.  If inline functions are
 * not supported, __TRQ__INLINE__FUNCTION__ is undefined.
 */
#define __TRQ__INLINE__FUNCTION__ __inline

typedef unsigned long trq_p_i_t; /* Integral type size of an pointer */

#ifdef offsetof
#define _Q_STRUCT_OFFSET(t, m) ((trq_p_i_t)(offsetof(t, m)))
#else
#define _Q_STRUCT_OFFSET(t, m) (((trq_p_i_t)(&(((t *)0)->m))))
#endif

#endif /* !__TRQ_CONF__H__ */
/* eof (trq_conf.h) */
