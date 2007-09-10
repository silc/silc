/*

  sha256_x86.S

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/* SHA-256 x86 assembler implementation.  This implements only the SHA-256
   transform function and other parts are implemented in sha256.c.  The
   function preserves ebp, edx, edi and esi but does not preserve other
   registers.

   This implementation uses only 32-bit registers.  It does not use MMX or
   SSE registers which could be used to enhance the performance, especially
   when loading the W.  This is about as fast as we can get with less than
   8 32-bit registers on 32-bit CPU.

   Benchmarks (megabytes (MB) per second), bigger is better:

   Code           P4 3.60 GHz      PM 1.60 GHz     Xeon 5160 3.00 GHz
   ----------------------------------------------------------------------
   SHA-256, asm   110.57 MB/sec    58.50 MB/sec    146.43 MB/sec
   SHA-256, gcc    49.07 MB/sec    39.55 MB/sec     82.14 MB/sec
   SHA-256, icc   109.97 MB/sec    55.69 MB/sec     N/A

   Notes:
   - Test program was lib/silccrypt/tests/test_hash
   - nice -n -20 was used with test_hash running as root
   - P4 is Pentium 4, PM is Pentium M, Xeon 5160 is 64-bit CPU but the OS
     had 32-bit kernel in the test.
   - ICC generates significantly better code compared to GCC for SSE2
     capable CPU, and the generated code uses SSE registers.  Hence the
     comparable speed with the assembler code.  Note that, the GCC code
     was also compiled with -msse2.  Note that, this assembler code
     specifically does not use SSE or MMX, for better compatibility.

*/

#include "../../silcdefs.h"

#ifdef SILC_SHA256_X86

#define STACK_STATE	(8 * 4)
#define STACK_W		(64 * 4)
#define STACK_SIZE	STACK_STATE + STACK_W
#define ARG_STATE	STACK_SIZE + 20(%esp)
#define ARG_BUF		STACK_SIZE + 24(%esp)

#define A		0
#define B	      	4
#define C	       	8
#define D	       	12
#define E	       	16
#define F	       	20
#define G	       	24
#define H	       	28

#define r0	       	%eax
#define r1	       	%ebx
#define r2	       	%ecx
#define r3	       	%edx
#define r4	       	%edi
#define r5	       	%esi

/* One round of SHA-256.  The a (r0) and e (r1) are inputs already in
   registers.  r0 will be the next round a, r1 the next round e.  The
   d and h are outputs and they are the r0 and r1 for next round. */
#define RND(a, b, c, d, e, f, g, h, W, ki)				\
	movl	f(%ebp), r2;						\
	movl	g(%ebp), r3;						\
									\
  	movl    e,   r4;		/* e to Sigma1 */		\
  	rorl    $6,  r4;		/* Sigma1 >>= 6 */		\
  	movl    r4,  r5;		/* Sigma1 to temp */		\
  	rorl    $5,  r4;		/* Sigma1 >>= 5 (11) */		\
  	xorl    r4,  r5;		/* temp ^= Sigma1 */		\
  	rorl    $14, r4;		/* Sigma1 >>= 14 (25) */	\
  	xorl    r5,  r4;		/* Sigma1 ^= temp */  		\
									\
 	movl    r3,  r5;		/* g to Ch */			\
  	xorl    r2,  r5;		/* Ch ^= f */			\
  	andl    e,   r5;		/* Ch &= e */			\
  	xorl    r3,  r5;		/* Ch ^= g */			\
									\
  	leal    ki(r4, r5), r4;		/* t0 = Sigma1 + Ch + ki */	\
	movl    h(%ebp), r3;						\
  	movl    d(%ebp), r1;						\
  	addl    W * 4(%esp), r4;	/* t0 += W[i] */		\
  	addl    r4, r3;			/* h += t0 */			\
  	addl    r3, r1;			/* d += h (t0) */		\
									\
        movl    a,   r4;		/* a to Sigma0 */		\
  	rorl    $2,  r4;		/* Sigma0 >>= 2 */		\
  	movl    r4,  r5;		/* Sigma0 to temp */		\
  	rorl    $11, r4;		/* Sigma0 >>= 11 (13) */	\
  	xorl    r4,  r5;		/* temp ^= Sigma0 */		\
  	rorl    $9,  r4;		/* Sigma0 >>= 9 (22) */		\
  	xorl    r5,  r4;		/* Sigma0 ^= temp */		\
									\
        addl    r3, r4;			/* t1 = Sigma0 + h (t0) */	\
 	movl    b(%ebp), r2;						\
  	movl    c(%ebp), r3;						\
									\
	movl    r2,  r5;		/* b to temp */			\
  	orl     a,   r5;		/* temp |= a */			\
  	andl    r3,  r5;		/* temp &= c */			\
  	andl    r2,  a;			/* a &= b */			\
  	orl     r5,  a;			/* a |= temp */			\
  	addl    r4,  r0;		/* h = t0 + t1 */

#define ROUND(a, b, c, d, e, f, g, h, W, ki)				\
	RND(a, b, c, d, e, f, g, h, W, ki)				\
	movl    r1, d(%ebp);		/* Update d in stack */		\
	movl    r0, h(%ebp);		/* Update h in stack */

/* Get 64 bits from input buffer in MSB first order */
#define GET_BUF(i)							\
	movl    i * 4(r5), r4;						\
	movl    (i + 1) * 4(r5), r3;					\
	bswapl  r4;							\
	bswapl  r3;							\
	movl    r4, i * 4(%esp);					\
	movl    r3, (i + 1) * 4(%esp);

/* Expand the input */
#define EXP_BUF(i)							\
	rorl    $17, r4;		/* Gamma1 >>= 17 */		\
	movl    r4,  r5;		/* Gamma1 to temp */		\
	rorl    $2,  r4;		/* Gamma1 >>= 2 (19) */		\
	xorl    r4,  r5;		/* temp ^= Gamma1 */		\
	shrl	$10, r2;		/* w-2 >> 10 */			\
	xorl    r5,  r2;		/* Gamma1 = w-2 ^ temp */	\
									\
  	movl    (i - 15) * 4(%esp), r3;					\
	movl    r3,  r4;		/* w-15 to Gamma0 */		\
	rorl    $7,  r4;		/* Gamma0 >>= 7 */		\
	movl    r4,  r5;		/* Gamma0 to temp */		\
	rorl    $11, r4;		/* Gamma0 >>= 11 (18) */	\
	xorl    r4,  r5;		/* temp ^= Gamma0 */		\
	shrl	$3,  r3;		/* w-15 >> 3 */			\
	xorl    r5,  r3;		/* Gamma0 = w-15 ^ temp */	\
									\
	addl    (i - 7) * 4(%esp), r2;	/* Gamma1 += w-7 */		\
	addl	(i - 16) * 4(%esp), r2;	/* Gamma1 += w-16 */		\
	addl    r2,  r3;		/* Gamma0 += Gamma1 */		\
	movl    r3, i * 4(%esp);

#define EXP_BUF0(i)							\
	movl    r4, r2;							\
	EXP_BUF(i)

#define EXP_BUFX(i)							\
	movl    (i - 2) * 4(%esp), r2;					\
	movl    r2,  r4;		/* w-2 to Gamma1 */		\
  	EXP_BUF(i)


.text
.balign 32
.globl sha256_transform
sha256_transform:
	pushl	%ebp
	pushl	%ebx
	pushl	%edi
	pushl	%esi
	subl	$STACK_SIZE, %esp

	/* State to stack */
	movl	ARG_STATE, %ebp
	movl	A(%ebp), r0
	movl	B(%ebp), r1
	movl	C(%ebp), r2
	movl	D(%ebp), r3
	movl	r0, A + STACK_W(%esp)
	movl	r1, B + STACK_W(%esp)
	movl	r2, C + STACK_W(%esp)
	movl	r3, D + STACK_W(%esp)
	movl	E(%ebp), r1
	movl	F(%ebp), r2
	movl	G(%ebp), r3
	movl	H(%ebp), r4
	movl	r1, E + STACK_W(%esp)
	movl	r2, F + STACK_W(%esp)
	movl	r3, G + STACK_W(%esp)
	movl	r4, H + STACK_W(%esp)

	/* Get buf in MSB first order, W[0..15] */
	movl	ARG_BUF, r5
	GET_BUF(0) GET_BUF(2) GET_BUF(4) GET_BUF(6)
	GET_BUF(8) GET_BUF(10) GET_BUF(12) GET_BUF(14)

	/* Expand input, fill in W[16..63] */
	EXP_BUF0(16) EXP_BUFX(17) EXP_BUFX(18) EXP_BUFX(19) EXP_BUFX(20)
	EXP_BUFX(21) EXP_BUFX(22) EXP_BUFX(23) EXP_BUFX(24) EXP_BUFX(25)
	EXP_BUFX(26) EXP_BUFX(27) EXP_BUFX(28) EXP_BUFX(29) EXP_BUFX(30)
	EXP_BUFX(31) EXP_BUFX(32) EXP_BUFX(33) EXP_BUFX(34) EXP_BUFX(35)
	EXP_BUFX(36) EXP_BUFX(37) EXP_BUFX(38) EXP_BUFX(39) EXP_BUFX(40)
	EXP_BUFX(41) EXP_BUFX(42) EXP_BUFX(43) EXP_BUFX(44) EXP_BUFX(45)
	EXP_BUFX(46) EXP_BUFX(47) EXP_BUFX(48) EXP_BUFX(49) EXP_BUFX(50)
	EXP_BUFX(51) EXP_BUFX(52) EXP_BUFX(53) EXP_BUFX(54) EXP_BUFX(55)
	EXP_BUFX(56) EXP_BUFX(57) EXP_BUFX(58) EXP_BUFX(59) EXP_BUFX(60)
	EXP_BUFX(61) EXP_BUFX(62) EXP_BUFX(63)

	/* Hash, r0 and r1 set above, ebp is base address to state */
	leal	STACK_W(%esp), %ebp

	ROUND(r0, B, C, D, r1, F, G, H, 0, 0x428a2f98);
	ROUND(r0, A, B, C, r1, E, F, G, 1, 0x71374491);
	ROUND(r0, H, A, B, r1, D, E, F, 2, 0xb5c0fbcf);
	ROUND(r0, G, H, A, r1, C, D, E, 3, 0xe9b5dba5);
	ROUND(r0, F, G, H, r1, B, C, D, 4, 0x3956c25b);
	ROUND(r0, E, F, G, r1, A, B, C, 5, 0x59f111f1);
	ROUND(r0, D, E, F, r1, H, A, B, 6, 0x923f82a4);
	ROUND(r0, C, D, E, r1, G, H, A, 7, 0xab1c5ed5);

	ROUND(r0, B, C, D, r1, F, G, H, 8, 0xd807aa98);
	ROUND(r0, A, B, C, r1, E, F, G, 9, 0x12835b01);
	ROUND(r0, H, A, B, r1, D, E, F, 10, 0x243185be);
	ROUND(r0, G, H, A, r1, C, D, E, 11, 0x550c7dc3);
	ROUND(r0, F, G, H, r1, B, C, D, 12, 0x72be5d74);
	ROUND(r0, E, F, G, r1, A, B, C, 13, 0x80deb1fe);
	ROUND(r0, D, E, F, r1, H, A, B, 14, 0x9bdc06a7);
	ROUND(r0, C, D, E, r1, G, H, A, 15, 0xc19bf174);

	ROUND(r0, B, C, D, r1, F, G, H, 16, 0xe49b69c1);
	ROUND(r0, A, B, C, r1, E, F, G, 17, 0xefbe4786);
	ROUND(r0, H, A, B, r1, D, E, F, 18, 0x0fc19dc6);
	ROUND(r0, G, H, A, r1, C, D, E, 19, 0x240ca1cc);
	ROUND(r0, F, G, H, r1, B, C, D, 20, 0x2de92c6f);
	ROUND(r0, E, F, G, r1, A, B, C, 21, 0x4a7484aa);
	ROUND(r0, D, E, F, r1, H, A, B, 22, 0x5cb0a9dc);
	ROUND(r0, C, D, E, r1, G, H, A, 23, 0x76f988da);

	ROUND(r0, B, C, D, r1, F, G, H, 24, 0x983e5152);
	ROUND(r0, A, B, C, r1, E, F, G, 25, 0xa831c66d);
	ROUND(r0, H, A, B, r1, D, E, F, 26, 0xb00327c8);
	ROUND(r0, G, H, A, r1, C, D, E, 27, 0xbf597fc7);
	ROUND(r0, F, G, H, r1, B, C, D, 28, 0xc6e00bf3);
	ROUND(r0, E, F, G, r1, A, B, C, 29, 0xd5a79147);
	ROUND(r0, D, E, F, r1, H, A, B, 30, 0x06ca6351);
	ROUND(r0, C, D, E, r1, G, H, A, 31, 0x14292967);

	ROUND(r0, B, C, D, r1, F, G, H, 32, 0x27b70a85);
	ROUND(r0, A, B, C, r1, E, F, G, 33, 0x2e1b2138);
	ROUND(r0, H, A, B, r1, D, E, F, 34, 0x4d2c6dfc);
	ROUND(r0, G, H, A, r1, C, D, E, 35, 0x53380d13);
	ROUND(r0, F, G, H, r1, B, C, D, 36, 0x650a7354);
	ROUND(r0, E, F, G, r1, A, B, C, 37, 0x766a0abb);
	ROUND(r0, D, E, F, r1, H, A, B, 38, 0x81c2c92e);
	ROUND(r0, C, D, E, r1, G, H, A, 39, 0x92722c85);

	ROUND(r0, B, C, D, r1, F, G, H, 40, 0xa2bfe8a1);
	ROUND(r0, A, B, C, r1, E, F, G, 41, 0xa81a664b);
	ROUND(r0, H, A, B, r1, D, E, F, 42, 0xc24b8b70);
	ROUND(r0, G, H, A, r1, C, D, E, 43, 0xc76c51a3);
	ROUND(r0, F, G, H, r1, B, C, D, 44, 0xd192e819);
	ROUND(r0, E, F, G, r1, A, B, C, 45, 0xd6990624);
	ROUND(r0, D, E, F, r1, H, A, B, 46, 0xf40e3585);
	ROUND(r0, C, D, E, r1, G, H, A, 47, 0x106aa070);

	ROUND(r0, B, C, D, r1, F, G, H, 48, 0x19a4c116);
	ROUND(r0, A, B, C, r1, E, F, G, 49, 0x1e376c08);
	ROUND(r0, H, A, B, r1, D, E, F, 50, 0x2748774c);
	ROUND(r0, G, H, A, r1, C, D, E, 51, 0x34b0bcb5);
	ROUND(r0, F, G, H, r1, B, C, D, 52, 0x391c0cb3);
	ROUND(r0, E, F, G, r1, A, B, C, 53, 0x4ed8aa4a);
	ROUND(r0, D, E, F, r1, H, A, B, 54, 0x5b9cca4f);
	ROUND(r0, C, D, E, r1, G, H, A, 55, 0x682e6ff3);

	ROUND(r0, B, C, D, r1, F, G, H, 56, 0x748f82ee);
	ROUND(r0, A, B, C, r1, E, F, G, 57, 0x78a5636f);
	ROUND(r0, H, A, B, r1, D, E, F, 58, 0x84c87814);
	ROUND(r0, G, H, A, r1, C, D, E, 59, 0x8cc70208);
	ROUND(r0, F, G, H, r1, B, C, D, 60, 0x90befffa);
	ROUND(r0, E, F, G, r1, A, B, C, 61, 0xa4506ceb);
	ROUND(r0, D, E, F, r1, H, A, B, 62, 0xbef9a3f7);
	RND  (r0, C, D, E, r1, G, H, A, 63, 0xc67178f2);

	/* Update state from stack */
	movl	ARG_STATE, %ebp
	addl	r0, A(%ebp)		/* a from last round */
	addl	r1, E(%ebp)		/* e from last round */
	movl	B + STACK_W(%esp), r0
	movl	C + STACK_W(%esp), r1
	movl	D + STACK_W(%esp), r2
	movl	F + STACK_W(%esp), r3
	movl	G + STACK_W(%esp), r4
	movl	H + STACK_W(%esp), r5
	addl	r0, B(%ebp)
	addl	r1, C(%ebp)
	addl	r2, D(%ebp)
	addl	r3, F(%ebp)
	addl	r4, G(%ebp)
	addl	r5, H(%ebp)

	addl	$STACK_SIZE, %esp
	popl	%esi
	popl	%edi
	popl	%ebx
	popl	%ebp

	ret

#endif /* SILC_SHA256_X86 */
