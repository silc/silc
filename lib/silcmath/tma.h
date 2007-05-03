/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library was designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://math.libtomcrypt.com
 */
#ifndef TMA_H
#define TMA_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>

#include "tma_class.h"

/* Assure these -Pekka */
#undef MP_8BIT
#undef MP_16BIT
#undef CRYPT

#ifndef MIN
   #define MIN(x,y) ((x)<(y)?(x):(y))
#endif

#ifndef MAX
   #define MAX(x,y) ((x)>(y)?(x):(y))
#endif

#ifdef __cplusplus
extern "C" {

/* C++ compilers don't like assigning void * to tma_mp_digit * */
#define  OPT_CAST(x)  (x *)

#else

/* C on the other hand doesn't care */
#define  OPT_CAST(x)

#endif


/* detect 64-bit mode if possible */
#if defined(__x86_64__)
   #if !(defined(MP_64BIT) && defined(MP_16BIT) && defined(MP_8BIT))
      #define MP_64BIT
   #endif
#endif

/* some default configurations.
 *
 * A "tma_mp_digit" must be able to hold DIGIT_BIT + 1 bits
 * A "tma_mp_word" must be able to hold 2*DIGIT_BIT + 1 bits
 *
 * At the very least a tma_mp_digit must be able to hold 7 bits
 * [any size beyond that is ok provided it doesn't overflow the data type]
 */
#ifdef MP_8BIT
   typedef unsigned char      tma_mp_digit;
   typedef unsigned short     tma_mp_word;
#elif defined(MP_16BIT)
   typedef unsigned short     tma_mp_digit;
   typedef unsigned long      tma_mp_word;
#elif defined(MP_64BIT)
   /* for GCC only on supported platforms */
#ifndef CRYPT
   typedef unsigned long long ulong64;
   typedef signed long long   long64;
#endif

   typedef unsigned long      tma_mp_digit;
   typedef unsigned long      tma_mp_word __attribute__ ((mode(TI)));

   #define DIGIT_BIT          60
#else
   /* this is the default case, 28-bit digits */

   /* this is to make porting into LibTomCrypt easier :-) */
#ifndef CRYPT
   #if defined(_MSC_VER) || defined(__BORLANDC__)
      typedef unsigned __int64   ulong64;
      typedef signed __int64     long64;
   #else
      typedef unsigned long long ulong64;
      typedef signed long long   long64;
   #endif
#endif

   typedef unsigned long      tma_mp_digit;
   typedef ulong64            tma_mp_word;

#ifdef MP_31BIT
   /* this is an extension that uses 31-bit digits */
   #define DIGIT_BIT          31
#else
   /* default case is 28-bit digits, defines MP_28BIT as a handy macro to test */
   #define DIGIT_BIT          28
   #define MP_28BIT
#endif
#endif

/* define heap macros */
#ifndef CRYPT
   /* default to libc stuff */
   #ifndef XMALLOC
       #define XMALLOC  malloc
       #define XFREE    free
       #define XREALLOC realloc
       #define XCALLOC  calloc
   #else
      /* prototypes for our heap functions */
      extern void *XMALLOC(size_t n);
      extern void *XREALLOC(void *p, size_t n);
      extern void *XCALLOC(size_t n, size_t s);
      extern void XFREE(void *p);
   #endif
#endif


/* otherwise the bits per digit is calculated automatically from the size of a tma_mp_digit */
#ifndef DIGIT_BIT
   #define DIGIT_BIT     ((int)((CHAR_BIT * sizeof(tma_mp_digit) - 1)))  /* bits per digit */
#endif

#define MP_DIGIT_BIT     DIGIT_BIT
#define MP_MASK          ((((tma_mp_digit)1)<<((tma_mp_digit)DIGIT_BIT))-((tma_mp_digit)1))
#define MP_DIGIT_MAX     MP_MASK

/* equalities */
#define MP_LT        -1   /* less than */
#define MP_EQ         0   /* equal to */
#define MP_GT         1   /* greater than */

#define MP_ZPOS       0   /* positive integer */
#define MP_NEG        1   /* negative */

#define MP_OKAY       0   /* ok result */
#define MP_MEM        -2  /* out of mem */
#define MP_VAL        -3  /* invalid input */
#define MP_RANGE      MP_VAL

#define MP_YES        1   /* yes response */
#define MP_NO         0   /* no response */

/* Primality generation flags */
#define LTM_PRIME_BBS      0x0001 /* BBS style prime */
#define LTM_PRIME_SAFE     0x0002 /* Safe prime (p-1)/2 == prime */
#define LTM_PRIME_2MSB_ON  0x0008 /* force 2nd MSB to 1 */

typedef int           tma_mp_err;

/* you'll have to tune these... */
extern int KARATSUBA_MUL_CUTOFF,
           KARATSUBA_SQR_CUTOFF,
           TOOM_MUL_CUTOFF,
           TOOM_SQR_CUTOFF;

/* define this to use lower memory usage routines (exptmods mostly) */
/* #define MP_LOW_MEM */

/* default precision */
#ifndef MP_PREC
   #ifndef MP_LOW_MEM
      #define MP_PREC                 32     /* default digits of precision */
   #else
      #define MP_PREC                 8      /* default digits of precision */
   #endif
#endif

/* size of comba arrays, should be at least 2 * 2**(BITS_PER_WORD - BITS_PER_DIGIT*2) */
#define MP_WARRAY               (1 << (sizeof(tma_mp_word) * CHAR_BIT - 2 * DIGIT_BIT + 1))

/* the infamous tma_mp_int structure */
typedef struct  {
    int used, alloc, sign;
    tma_mp_digit *dp;
} tma_mp_int;

/* callback for tma_mp_prime_random, should fill dst with random bytes and return how many read [upto len] */
typedef int ltm_prime_callback(unsigned char *dst, int len, void *dat);


#define USED(m)    ((m)->used)
#define DIGIT(m,k) ((m)->dp[(k)])
#define SIGN(m)    ((m)->sign)

/* error code to char* string */
char *tma_mp_error_to_string(int code);

/* ---> init and deinit bignum functions <--- */
/* init a bignum */
int tma_mp_init(tma_mp_int *a);

/* free a bignum */
void tma_mp_clear(tma_mp_int *a);

/* init a null terminated series of arguments */
int tma_mp_init_multi(tma_mp_int *mp, ...);

/* clear a null terminated series of arguments */
void tma_mp_clear_multi(tma_mp_int *mp, ...);

/* exchange two ints */
void tma_mp_exch(tma_mp_int *a, tma_mp_int *b);

/* shrink ram required for a bignum */
int tma_mp_shrink(tma_mp_int *a);

/* grow an int to a given size */
int tma_mp_grow(tma_mp_int *a, int size);

/* init to a given number of digits */
int tma_mp_init_size(tma_mp_int *a, int size);

/* ---> Basic Manipulations <--- */
#define tma_mp_iszero(a) (((a)->used == 0) ? MP_YES : MP_NO)
#define tma_mp_iseven(a) (((a)->used > 0 && (((a)->dp[0] & 1) == 0)) ? MP_YES : MP_NO)
#define tma_mp_isodd(a)  (((a)->used > 0 && (((a)->dp[0] & 1) == 1)) ? MP_YES : MP_NO)

/* set to zero */
void tma_mp_zero(tma_mp_int *a);

/* set to a digit */
void tma_mp_set(tma_mp_int *a, tma_mp_digit b);

/* set a 32-bit const */
int tma_mp_set_int(tma_mp_int *a, unsigned long b);

/* get a 32-bit value */
unsigned long tma_mp_get_int(tma_mp_int * a);

/* initialize and set a digit */
int tma_mp_init_set (tma_mp_int * a, tma_mp_digit b);

/* initialize and set 32-bit value */
int tma_mp_init_set_int (tma_mp_int * a, unsigned long b);

/* copy, b = a */
int tma_mp_copy(tma_mp_int *a, tma_mp_int *b);

/* inits and copies, a = b */
int tma_mp_init_copy(tma_mp_int *a, tma_mp_int *b);

/* trim unused digits */
void tma_mp_clamp(tma_mp_int *a);

/* ---> digit manipulation <--- */

/* right shift by "b" digits */
void tma_mp_rshd(tma_mp_int *a, int b);

/* left shift by "b" digits */
int tma_mp_lshd(tma_mp_int *a, int b);

/* c = a / 2**b */
int tma_mp_div_2d(tma_mp_int *a, int b, tma_mp_int *c, tma_mp_int *d);

/* b = a/2 */
int tma_mp_div_2(tma_mp_int *a, tma_mp_int *b);

/* c = a * 2**b */
int tma_mp_mul_2d(tma_mp_int *a, int b, tma_mp_int *c);

/* b = a*2 */
int tma_mp_mul_2(tma_mp_int *a, tma_mp_int *b);

/* c = a mod 2**d */
int tma_mp_mod_2d(tma_mp_int *a, int b, tma_mp_int *c);

/* computes a = 2**b */
int tma_mp_2expt(tma_mp_int *a, int b);

/* Counts the number of lsbs which are zero before the first zero bit */
int tma_mp_cnt_lsb(tma_mp_int *a);

/* I Love Earth! */

/* makes a pseudo-random int of a given size */
int tma_mp_rand(tma_mp_int *a, int digits);

/* ---> binary operations <--- */
/* c = a XOR b  */
int tma_mp_xor(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* c = a OR b */
int tma_mp_or(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* c = a AND b */
int tma_mp_and(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* ---> Basic arithmetic <--- */

/* b = -a */
int tma_mp_neg(tma_mp_int *a, tma_mp_int *b);

/* b = |a| */
int tma_mp_abs(tma_mp_int *a, tma_mp_int *b);

/* compare a to b */
int tma_mp_cmp(tma_mp_int *a, tma_mp_int *b);

/* compare |a| to |b| */
int tma_mp_cmp_mag(tma_mp_int *a, tma_mp_int *b);

/* c = a + b */
int tma_mp_add(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* c = a - b */
int tma_mp_sub(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* c = a * b */
int tma_mp_mul(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* b = a*a  */
int tma_mp_sqr(tma_mp_int *a, tma_mp_int *b);

/* a/b => cb + d == a */
int tma_mp_div(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c, tma_mp_int *d);

/* c = a mod b, 0 <= c < b  */
int tma_mp_mod(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* ---> single digit functions <--- */

/* compare against a single digit */
int tma_mp_cmp_d(tma_mp_int *a, tma_mp_digit b);

/* c = a + b */
int tma_mp_add_d(tma_mp_int *a, tma_mp_digit b, tma_mp_int *c);

/* c = a - b */
int tma_mp_sub_d(tma_mp_int *a, tma_mp_digit b, tma_mp_int *c);

/* c = a * b */
int tma_mp_mul_d(tma_mp_int *a, tma_mp_digit b, tma_mp_int *c);

/* a/b => cb + d == a */
int tma_mp_div_d(tma_mp_int *a, tma_mp_digit b, tma_mp_int *c, tma_mp_digit *d);

/* a/3 => 3c + d == a */
int tma_mp_div_3(tma_mp_int *a, tma_mp_int *c, tma_mp_digit *d);

/* c = a**b */
int tma_mp_expt_d(tma_mp_int *a, tma_mp_digit b, tma_mp_int *c);

/* c = a mod b, 0 <= c < b  */
int tma_mp_mod_d(tma_mp_int *a, tma_mp_digit b, tma_mp_digit *c);

/* ---> number theory <--- */

/* d = a + b (mod c) */
int tma_mp_addmod(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c, tma_mp_int *d);

/* d = a - b (mod c) */
int tma_mp_submod(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c, tma_mp_int *d);

/* d = a * b (mod c) */
int tma_mp_mulmod(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c, tma_mp_int *d);

/* c = a * a (mod b) */
int tma_mp_sqrmod(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* c = 1/a (mod b) */
int tma_mp_invmod(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* c = (a, b) */
int tma_mp_gcd(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* produces value such that U1*a + U2*b = U3 */
int tma_mp_exteuclid(tma_mp_int *a, tma_mp_int *b, tma_mp_int *U1, tma_mp_int *U2, tma_mp_int *U3);

/* c = [a, b] or (a*b)/(a, b) */
int tma_mp_lcm(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* finds one of the b'th root of a, such that |c|**b <= |a|
 *
 * returns error if a < 0 and b is even
 */
int tma_mp_n_root(tma_mp_int *a, tma_mp_digit b, tma_mp_int *c);

/* special sqrt algo */
int tma_mp_sqrt(tma_mp_int *arg, tma_mp_int *ret);

/* is number a square? */
int tma_mp_is_square(tma_mp_int *arg, int *ret);

/* computes the jacobi c = (a | n) (or Legendre if b is prime)  */
int tma_mp_jacobi(tma_mp_int *a, tma_mp_int *n, int *c);

/* used to setup the Barrett reduction for a given modulus b */
int tma_mp_reduce_setup(tma_mp_int *a, tma_mp_int *b);

/* Barrett Reduction, computes a (mod b) with a precomputed value c
 *
 * Assumes that 0 < a <= b*b, note if 0 > a > -(b*b) then you can merely
 * compute the reduction as -1 * tma_mp_reduce(tma_mp_abs(a)) [pseudo code].
 */
int tma_mp_reduce(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);

/* setups the montgomery reduction */
int tma_mp_montgomery_setup(tma_mp_int *a, tma_mp_digit *mp);

/* computes a = B**n mod b without division or multiplication useful for
 * normalizing numbers in a Montgomery system.
 */
int tma_mp_montgomery_calc_normalization(tma_mp_int *a, tma_mp_int *b);

/* computes x/R == x (mod N) via Montgomery Reduction */
int tma_mp_montgomery_reduce(tma_mp_int *a, tma_mp_int *m, tma_mp_digit mp);

/* returns 1 if a is a valid DR modulus */
int tma_mp_dr_is_modulus(tma_mp_int *a);

/* sets the value of "d" required for tma_mp_dr_reduce */
void tma_mp_dr_setup(tma_mp_int *a, tma_mp_digit *d);

/* reduces a modulo b using the Diminished Radix method */
int tma_mp_dr_reduce(tma_mp_int *a, tma_mp_int *b, tma_mp_digit mp);

/* returns true if a can be reduced with tma_mp_reduce_2k */
int tma_mp_reduce_is_2k(tma_mp_int *a);

/* determines k value for 2k reduction */
int tma_mp_reduce_2k_setup(tma_mp_int *a, tma_mp_digit *d);

/* reduces a modulo b where b is of the form 2**p - k [0 <= a] */
int tma_mp_reduce_2k(tma_mp_int *a, tma_mp_int *n, tma_mp_digit d);

/* returns true if a can be reduced with tma_mp_reduce_2k_l */
int tma_mp_reduce_is_2k_l(tma_mp_int *a);

/* determines k value for 2k reduction */
int tma_mp_reduce_2k_setup_l(tma_mp_int *a, tma_mp_int *d);

/* reduces a modulo b where b is of the form 2**p - k [0 <= a] */
int tma_mp_reduce_2k_l(tma_mp_int *a, tma_mp_int *n, tma_mp_int *d);

/* d = a**b (mod c) */
int tma_mp_exptmod(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c, tma_mp_int *d);

/* ---> Primes <--- */

/* number of primes */
#ifdef MP_8BIT
   #define PRIME_SIZE      31
#else
   #define PRIME_SIZE      256
#endif

/* table of first PRIME_SIZE primes */
extern const tma_mp_digit ltm_prime_tab[];

/* result=1 if a is divisible by one of the first PRIME_SIZE primes */
int tma_mp_prime_is_divisible(tma_mp_int *a, int *result);

/* performs one Fermat test of "a" using base "b".
 * Sets result to 0 if composite or 1 if probable prime
 */
int tma_mp_prime_fermat(tma_mp_int *a, tma_mp_int *b, int *result);

/* performs one Miller-Rabin test of "a" using base "b".
 * Sets result to 0 if composite or 1 if probable prime
 */
int tma_mp_prime_miller_rabin(tma_mp_int *a, tma_mp_int *b, int *result);

/* This gives [for a given bit size] the number of trials required
 * such that Miller-Rabin gives a prob of failure lower than 2^-96
 */
int tma_mp_prime_rabin_miller_trials(int size);

/* performs t rounds of Miller-Rabin on "a" using the first
 * t prime bases.  Also performs an initial sieve of trial
 * division.  Determines if "a" is prime with probability
 * of error no more than (1/4)**t.
 *
 * Sets result to 1 if probably prime, 0 otherwise
 */
int tma_mp_prime_is_prime(tma_mp_int *a, int t, int *result);

/* finds the next prime after the number "a" using "t" trials
 * of Miller-Rabin.
 *
 * bbs_style = 1 means the prime must be congruent to 3 mod 4
 */
int tma_mp_prime_next_prime(tma_mp_int *a, int t, int bbs_style);

/* makes a truly random prime of a given size (bytes),
 * call with bbs = 1 if you want it to be congruent to 3 mod 4
 *
 * You have to supply a callback which fills in a buffer with random bytes.  "dat" is a parameter you can
 * have passed to the callback (e.g. a state or something).  This function doesn't use "dat" itself
 * so it can be NULL
 *
 * The prime generated will be larger than 2^(8*size).
 */
#define tma_mp_prime_random(a, t, size, bbs, cb, dat) tma_mp_prime_random_ex(a, t, ((size) * 8) + 1, (bbs==1)?LTM_PRIME_BBS:0, cb, dat)

/* makes a truly random prime of a given size (bits),
 *
 * Flags are as follows:
 *
 *   LTM_PRIME_BBS      - make prime congruent to 3 mod 4
 *   LTM_PRIME_SAFE     - make sure (p-1)/2 is prime as well (implies LTM_PRIME_BBS)
 *   LTM_PRIME_2MSB_OFF - make the 2nd highest bit zero
 *   LTM_PRIME_2MSB_ON  - make the 2nd highest bit one
 *
 * You have to supply a callback which fills in a buffer with random bytes.  "dat" is a parameter you can
 * have passed to the callback (e.g. a state or something).  This function doesn't use "dat" itself
 * so it can be NULL
 *
 */
int tma_mp_prime_random_ex(tma_mp_int *a, int t, int size, int flags, ltm_prime_callback cb, void *dat);

/* ---> radix conversion <--- */
int tma_mp_count_bits(tma_mp_int *a);

int tma_mp_unsigned_bin_size(tma_mp_int *a);
int tma_mp_read_unsigned_bin(tma_mp_int *a, const unsigned char *b, int c);
int tma_mp_to_unsigned_bin(tma_mp_int *a, unsigned char *b);
int tma_mp_to_unsigned_bin_n (tma_mp_int * a, unsigned char *b, unsigned long *outlen);

int tma_mp_signed_bin_size(tma_mp_int *a);
int tma_mp_read_signed_bin(tma_mp_int *a, const unsigned char *b, int c);
int tma_mp_to_signed_bin(tma_mp_int *a,  unsigned char *b);
int tma_mp_to_signed_bin_n (tma_mp_int * a, unsigned char *b, unsigned long *outlen);

int tma_mp_read_radix(tma_mp_int *a, const char *str, int radix);
int tma_mp_toradix(tma_mp_int *a, char *str, int radix);
int tma_mp_toradix_n(tma_mp_int * a, char *str, int radix, int maxlen);
int tma_mp_radix_size(tma_mp_int *a, int radix, int *size);

int tma_mp_fread(tma_mp_int *a, int radix, FILE *stream);
int tma_mp_fwrite(tma_mp_int *a, int radix, FILE *stream);

#define tma_mp_read_raw(mp, str, len) tma_mp_read_signed_bin((mp), (str), (len))
#define tma_mp_raw_size(mp)           tma_mp_signed_bin_size(mp)
#define tma_mp_toraw(mp, str)         tma_mp_to_signed_bin((mp), (str))
#define tma_mp_read_mag(mp, str, len) tma_mp_read_unsigned_bin((mp), (str), (len))
#define tma_mp_mag_size(mp)           tma_mp_unsigned_bin_size(mp)
#define tma_mp_tomag(mp, str)         tma_mp_to_unsigned_bin((mp), (str))

#define tma_mp_tobinary(M, S)  tma_mp_toradix((M), (S), 2)
#define tma_mp_tooctal(M, S)   tma_mp_toradix((M), (S), 8)
#define tma_mp_todecimal(M, S) tma_mp_toradix((M), (S), 10)
#define tma_mp_tohex(M, S)     tma_mp_toradix((M), (S), 16)

/* lowlevel functions, do not call! */
int s_tma_mp_add(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);
int s_tma_mp_sub(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);
#define s_tma_mp_mul(a, b, c) s_tma_mp_mul_digs(a, b, c, (a)->used + (b)->used + 1)
int fast_s_tma_mp_mul_digs(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c, int digs);
int s_tma_mp_mul_digs(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c, int digs);
int fast_s_tma_mp_mul_high_digs(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c, int digs);
int s_tma_mp_mul_high_digs(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c, int digs);
int fast_s_tma_mp_sqr(tma_mp_int *a, tma_mp_int *b);
int s_tma_mp_sqr(tma_mp_int *a, tma_mp_int *b);
int tma_mp_karatsuba_mul(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);
int tma_mp_toom_mul(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);
int tma_mp_karatsuba_sqr(tma_mp_int *a, tma_mp_int *b);
int tma_mp_toom_sqr(tma_mp_int *a, tma_mp_int *b);
int fast_tma_mp_invmod(tma_mp_int *a, tma_mp_int *b, tma_mp_int *c);
int tma_mp_invmod_slow (tma_mp_int * a, tma_mp_int * b, tma_mp_int * c);
int fast_tma_mp_montgomery_reduce(tma_mp_int *a, tma_mp_int *m, tma_mp_digit mp);
int tma_mp_exptmod_fast(tma_mp_int *G, tma_mp_int *X, tma_mp_int *P, tma_mp_int *Y, int mode);
int s_tma_mp_exptmod (tma_mp_int * G, tma_mp_int * X, tma_mp_int * P, tma_mp_int * Y, int mode);
void bn_reverse(unsigned char *s, int len);

extern const char *tma_mp_s_rmap;

#ifdef __cplusplus
   }
#endif

/* $Source$ */
/* $Revision$ */
/* $Date$ */
#endif /* TMA_H */
