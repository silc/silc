/*

  silcrng.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2003 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */
/*
 * Created: Sun Mar  9 00:09:18 1997
 *
 * The original RNG was based on Secure Shell's random number generator
 * by Tatu Ylönen and was used as reference when programming this RNG.
 * This RNG has been rewritten twice since the creation.
 */

#include "silcincludes.h"

#ifndef WIN32
#ifdef HAVE_GETSID
extern pid_t getsid (pid_t __pid);
#endif

#ifdef HAVE_GETPGID
extern pid_t getpgid (pid_t __pid);
#endif
#endif

#undef SILC_RNG_DEBUG
/*#define SILC_RNG_DEBUG*/

/* Number of states to fetch data from pool. */
#define SILC_RNG_STATE_NUM 4

/* Byte size of the random data pool. */
#define SILC_RNG_POOLSIZE (20 * 48)

static SilcUInt32 silc_rng_get_position(SilcRng rng);
static void silc_rng_stir_pool(SilcRng rng);
static void silc_rng_xor(SilcRng rng, SilcUInt32 val, unsigned int pos);
static void silc_rng_exec_command(SilcRng rng, char *command);
static void silc_rng_get_hard_noise(SilcRng rng);
static void silc_rng_get_medium_noise(SilcRng rng);
static void silc_rng_get_soft_noise(SilcRng rng);

/*
   SILC SilcRng State context.

   This object is used by the random number generator to provide
   variable points where the actual random number is fetched from
   the random pool. This provides that the data is not fetched always
   from the same point of the pool. Short description of the fields
   following.

   SilcUInt32 low
   SilcUInt32 pos

       The index for the random pool buffer. Lowest and current
       positions.

   SilcRngStateContext *next

       Pointer to the next state. If this is the last state this
       will point to the first state thus providing circular list.

*/
typedef struct SilcRngStateContext {
  SilcUInt32 low;
  SilcUInt32 pos;
  struct SilcRngStateContext *next;
} *SilcRngState;

/*
   SILC Random Number Generator object.

   This object holds random pool which is used to generate the random
   numbers used by various routines needing cryptographically strong
   random numbers. Following short descriptions of the fields.

   unsigned char pool[]

       The random pool. This buffer holds the random data. This is
       frequently stirred thus providing ever changing randomnes.

   unsigned char key[64]

       Key used in stirring the random pool. The pool is encrypted
       with SHA1 hash function in CFB (Cipher Feedback) mode.

   SilcSilcRngState state

       State object that is used to get the next position for the
       random pool. This position is used to fetch data from pool
       or to save the data to the pool. The state changes everytime
       SilcRng is used.

   SilcHash sha1

       Hash object (SHA1) used to make the CFB encryption to the
       random pool. This is allocated when RNG object is allocated and
       free'd when RNG object is free'd.

   SilcUInt8 threshold

       Threshold to indicate when it is required to acquire more
       noise from the environment.  More soft noise is acquired after
       64 bits of output and hard noise every 160 bits of output.

*/
struct SilcRngStruct {
  unsigned char pool[SILC_RNG_POOLSIZE];
  unsigned char key[64];
  SilcRngState state;
  SilcHash sha1;
  SilcUInt8 threshold;
  char *devrandom;
  int fd_devurandom;
};

/* Allocates new RNG object. */

SilcRng silc_rng_alloc(void)
{
  SilcRng new;

  SILC_LOG_DEBUG(("Allocating new RNG object"));

  new = silc_calloc(1, sizeof(*new));
  new->fd_devurandom = -1;

  memset(new->pool, 0, sizeof(new->pool));
  memset(new->key, 0, sizeof(new->key));
  new->state = NULL;
  if (!silc_hash_alloc("sha1", &new->sha1)) {
    silc_free(new);
    SILC_LOG_ERROR(("Could not allocate sha1 hash, probably not registered"));
    return NULL;
  }

  new->devrandom = strdup("/dev/random");

  return new;
}

/* Free's RNG object. */

void silc_rng_free(SilcRng rng)
{
  if (rng) {
    SilcRngState t, n;

    memset(rng->pool, 0, sizeof(rng->pool));
    memset(rng->key, 0, sizeof(rng->key));
    silc_hash_free(rng->sha1);
    silc_free(rng->devrandom);

    if (rng->fd_devurandom != -1)
      close(rng->fd_devurandom);

    for (t = rng->state->next; t != rng->state; ) {
      n = t->next;
      silc_free(t);
      t = n;
    }
    silc_free(rng->state);

    silc_free(rng);
  }
}

/* Initializes random number generator by getting noise from environment.
   The environmental noise is our so called seed. One should not call
   this function more than once. */

void silc_rng_init(SilcRng rng)
{
  int i;
  SilcRngState first, next;

  assert(rng != NULL);

  SILC_LOG_DEBUG(("Initializing RNG object"));

  /* Initialize the states for the RNG. */
  rng->state = silc_calloc(1, sizeof(*rng->state));
  rng->state->low = 0;
  rng->state->pos = 8;
  rng->state->next = NULL;
  first = rng->state;
  for (i = SILC_RNG_STATE_NUM - 1; i >= 1; i--) {
    next = silc_calloc(1, sizeof(*rng->state));
    next->low =
      (i * (sizeof(rng->pool) / SILC_RNG_STATE_NUM));
    next->pos =
      (i * (sizeof(rng->pool) / SILC_RNG_STATE_NUM)) + 8;
    next->next = rng->state;
    rng->state = next;
  }
  first->next = next;
  rng->state = first;

  memset(rng->pool, 0, sizeof(rng->pool));

  /* Get noise from various environmental sources */
  silc_rng_get_soft_noise(rng);
  silc_rng_get_medium_noise(rng);
  silc_rng_get_hard_noise(rng);
  silc_rng_get_soft_noise(rng);
  silc_free(rng->devrandom);
  rng->devrandom = strdup("/dev/urandom");
}

/* This function gets 'soft' noise from environment. */

static void silc_rng_get_soft_noise(SilcRng rng)
{
#ifndef SILC_WIN32
  struct tms ptime;
#endif
  SilcUInt32 pos;
#ifdef HAVE_GETRUSAGE
  struct rusage r;
#endif

  pos = silc_rng_get_position(rng);

  silc_rng_xor(rng, clock(), 0);
#ifndef SILC_WIN32
#ifdef HAVE_GETPID
  silc_rng_xor(rng, getpid(), 1);
#ifdef HAVE_GETPGID
  silc_rng_xor(rng, getpgid(getpid()) << 8, 2);
  silc_rng_xor(rng, getpgid(getpid()) << 8, 3);
#endif
  silc_rng_xor(rng, getgid(), 4);
#endif
#ifdef HAVE_GETPGRP
  silc_rng_xor(rng, getpgrp(), 5);
#endif
#ifdef HAVE_GETSID
  silc_rng_xor(rng, getsid(getpid()) << 16, 6);
#endif
  silc_rng_xor(rng, times(&ptime), 7);
  silc_rng_xor(rng, ptime.tms_utime, 8);
  silc_rng_xor(rng, (ptime.tms_utime + ptime.tms_stime), pos++);
  silc_rng_xor(rng, (ptime.tms_stime + ptime.tms_cutime), pos++);
  silc_rng_xor(rng, (ptime.tms_utime + ptime.tms_stime), pos++);
  silc_rng_xor(rng, (ptime.tms_cutime ^ ptime.tms_stime), pos++);
  silc_rng_xor(rng, (ptime.tms_cutime ^ ptime.tms_cstime), pos++);
  silc_rng_xor(rng, (ptime.tms_utime ^ ptime.tms_stime), pos++);
  silc_rng_xor(rng, (ptime.tms_stime ^ ptime.tms_cutime), pos++);
  silc_rng_xor(rng, (ptime.tms_cutime + ptime.tms_stime), pos++);
  silc_rng_xor(rng, (ptime.tms_stime << 8), pos++);
#endif
  silc_rng_xor(rng, clock() << 4, pos++);
#ifndef SILC_WIN32
#ifdef HAVE_GETPGID
  silc_rng_xor(rng, getpgid(getpid()) << 8, pos++);
#endif
#ifdef HAVE_GETPGRP
  silc_rng_xor(rng, getpgrp(), pos++);
#endif
#ifdef HAVE_SETSID
  silc_rng_xor(rng, getsid(getpid()) << 16, pos++);
#endif
  silc_rng_xor(rng, times(&ptime), pos++);
  silc_rng_xor(rng, ptime.tms_utime, pos++);
#ifdef HAVE_GETPGRP
  silc_rng_xor(rng, getpgrp(), pos++);
#endif
#endif
#ifdef HAVE_GETRUSAGE
  getrusage(RUSAGE_SELF, &r);
  silc_rng_xor(rng, (r.ru_utime.tv_sec + r.ru_utime.tv_usec), pos++);
  silc_rng_xor(rng, (r.ru_utime.tv_sec ^ r.ru_utime.tv_usec), pos++);
  silc_rng_xor(rng, (r.ru_stime.tv_sec + r.ru_stime.tv_usec), pos++);
  silc_rng_xor(rng, (r.ru_stime.tv_sec ^ r.ru_stime.tv_usec), pos++);
  silc_rng_xor(rng, (r.ru_maxrss + r.ru_ixrss), pos++);
  silc_rng_xor(rng, (r.ru_maxrss ^ r.ru_ixrss), pos++);
  silc_rng_xor(rng, (r.ru_idrss + r.ru_idrss), pos++);
  silc_rng_xor(rng, (r.ru_idrss ^ r.ru_idrss), pos++);
  silc_rng_xor(rng, (r.ru_idrss << 16), pos++);
  silc_rng_xor(rng, (r.ru_minflt + r.ru_majflt), pos++);
  silc_rng_xor(rng, (r.ru_minflt ^ r.ru_majflt), pos++);
  silc_rng_xor(rng, (r.ru_nswap + r.ru_oublock + r.ru_inblock), pos++);
  silc_rng_xor(rng, (r.ru_nswap << 8), pos++);
  silc_rng_xor(rng, (r.ru_inblock + r.ru_oublock), pos++);
  silc_rng_xor(rng, (r.ru_inblock ^ r.ru_oublock), pos++);
  silc_rng_xor(rng, (r.ru_msgsnd ^ r.ru_msgrcv), pos++);
  silc_rng_xor(rng, (r.ru_nsignals + r.ru_msgsnd + r.ru_msgrcv), pos++);
  silc_rng_xor(rng, (r.ru_nsignals << 16), pos++);
  silc_rng_xor(rng, (r.ru_nvcsw + r.ru_nivcsw), pos++);
  silc_rng_xor(rng, (r.ru_nvcsw ^ r.ru_nivcsw), pos++);
#endif
  
#ifdef SILC_RNG_DEBUG
  SILC_LOG_HEXDUMP(("pool"), rng->pool, sizeof(rng->pool));
#endif

  /* Stir random pool */
  silc_rng_stir_pool(rng);
}

/* This function gets noise from different commands */

static void silc_rng_get_medium_noise(SilcRng rng)
{
  /* If getrusage is available, there is no need for shell commands */
#ifdef HAVE_GETRUSAGE
  return;
#endif
  silc_rng_exec_command(rng, "ps -leaww 2> /dev/null");
  silc_rng_exec_command(rng, "ls -afiln ~ 2> /dev/null");
  silc_rng_exec_command(rng, "ls -afiln /proc 2> /dev/null");
  silc_rng_exec_command(rng, "ps -axww 2> /dev/null");

#ifdef SILC_RNG_DEBUG
  SILC_LOG_HEXDUMP(("pool"), rng->pool, sizeof(rng->pool));
#endif
}

/* This function gets 'hard' noise from environment. This tries to
   get the noise from /dev/random if available. */

static void silc_rng_get_hard_noise(SilcRng rng)
{
#ifndef SILC_WIN32
  unsigned char buf[32];
  int fd, len, i;

  /* Get noise from /dev/[u]random if available */
  fd = open(rng->devrandom, O_RDONLY);
  if (fd < 0)
    return;

  fcntl(fd, F_SETFL, O_NONBLOCK);

  for (i = 0; i < 2; i++) {
    len = read(fd, buf, sizeof(buf));
    if (len <= 0)
      goto out;
    silc_rng_add_noise(rng, buf, len);
  }

#ifdef SILC_RNG_DEBUG
  SILC_LOG_HEXDUMP(("pool"), rng->pool, sizeof(rng->pool));
#endif

 out:
  close(fd);
  memset(buf, 0, sizeof(buf));
#endif
}

/* Execs command and gets noise from its output */

static void silc_rng_exec_command(SilcRng rng, char *command)
{
#ifndef SILC_WIN32
  unsigned char buf[1024];
  FILE *fd;
  int i;
  int c;

  /* Open process */
  fd = popen(command, "r");
  if (!fd)
    return;

  /* Get data as much as we can get into the buffer */
  for (i = 0; i < sizeof(buf); i++) {
    c = fgetc(fd);
    if (c == EOF)
      break;
    buf[i] = c;
  }

  pclose(fd);

  if (i != 0) {
    /* Add the buffer into random pool */
    silc_rng_add_noise(rng, buf, i);
    memset(buf, 0, sizeof(buf));
  }
#endif
}

/* This function adds the contents of the buffer as noise into random
   pool. After adding the noise the pool is stirred. */

void silc_rng_add_noise(SilcRng rng, unsigned char *buffer, SilcUInt32 len)
{
  SilcUInt32 i, pos;

  pos = silc_rng_get_position(rng);

  /* Add the buffer one by one into the pool */
  for(i = 0; i < len; i++, buffer++) {
    if(pos >= SILC_RNG_POOLSIZE)
      break;
    rng->pool[pos++] ^= *buffer;
  }

  /* Stir random pool */
  silc_rng_stir_pool(rng);
}

/* XOR's data into the pool */

static void silc_rng_xor(SilcRng rng, SilcUInt32 val, unsigned int pos)
{
  SilcUInt32 tmp;

  SILC_GET32_MSB(tmp, &rng->pool[pos]);
  val ^= tmp + val;
  SILC_PUT32_MSB(val, &rng->pool[pos]);
}

/* This function stirs the random pool by encrypting buffer in CFB
   (cipher feedback) mode with SHA1 algorithm. */

static void silc_rng_stir_pool(SilcRng rng)
{
  int i;
  SilcUInt32 iv[5], tmp;

  /* Get the IV */
  SILC_GET32_MSB(iv[0], &rng->pool[16     ]);
  SILC_GET32_MSB(iv[1], &rng->pool[16 +  4]);
  SILC_GET32_MSB(iv[2], &rng->pool[16 +  8]);
  SILC_GET32_MSB(iv[3], &rng->pool[16 + 12]);
  SILC_GET32_MSB(iv[4], &rng->pool[16 + 16]);

  /* First CFB pass */
  for (i = 0; i < SILC_RNG_POOLSIZE; i += 20) {
    silc_hash_transform(rng->sha1, iv, rng->key);

    SILC_GET32_MSB(tmp, &rng->pool[i]);
    iv[0] ^= tmp;
    SILC_PUT32_MSB(iv[0], &rng->pool[i]);

    SILC_GET32_MSB(tmp, &rng->pool[i + 4]);
    iv[1] ^= tmp;
    SILC_PUT32_MSB(iv[1], &rng->pool[i + 4]);

    SILC_GET32_MSB(tmp, &rng->pool[i + 8]);
    iv[2] ^= tmp;
    SILC_PUT32_MSB(iv[2], &rng->pool[i + 8]);

    SILC_GET32_MSB(tmp, &rng->pool[i + 12]);
    iv[3] ^= tmp;
    SILC_PUT32_MSB(iv[3], &rng->pool[i + 12]);

    SILC_GET32_MSB(tmp, &rng->pool[i + 16]);
    iv[4] ^= tmp;
    SILC_PUT32_MSB(iv[4], &rng->pool[i + 16]);
  }

  /* Get new key */
  memcpy(rng->key, &rng->pool[silc_rng_get_position(rng)], sizeof(rng->key));

  /* Second CFB pass */
  for (i = 0; i < SILC_RNG_POOLSIZE; i += 20) {
    silc_hash_transform(rng->sha1, iv, rng->key);

    SILC_GET32_MSB(tmp, &rng->pool[i]);
    iv[0] ^= tmp;
    SILC_PUT32_MSB(iv[0], &rng->pool[i]);

    SILC_GET32_MSB(tmp, &rng->pool[i + 4]);
    iv[1] ^= tmp;
    SILC_PUT32_MSB(iv[1], &rng->pool[i + 4]);

    SILC_GET32_MSB(tmp, &rng->pool[i + 8]);
    iv[2] ^= tmp;
    SILC_PUT32_MSB(iv[2], &rng->pool[i + 8]);

    SILC_GET32_MSB(tmp, &rng->pool[i + 12]);
    iv[3] ^= tmp;
    SILC_PUT32_MSB(iv[3], &rng->pool[i + 12]);

    SILC_GET32_MSB(tmp, &rng->pool[i + 16]);
    iv[4] ^= tmp;
    SILC_PUT32_MSB(iv[4], &rng->pool[i + 16]);
  }

  memset(iv, 0, sizeof(iv));
}

/* Returns next position where data is fetched from the pool or
   put to the pool. */

static SilcUInt32 silc_rng_get_position(SilcRng rng)
{
  SilcRngState next;
  SilcUInt32 pos;

  next = rng->state->next;

  pos = rng->state->pos++;
  if ((next->low != 0 && pos >= next->low) || (pos >= SILC_RNG_POOLSIZE))
    rng->state->pos = rng->state->low;

#ifdef SILC_RNG_DEBUG
    fprintf(stderr, "state: %p: low: %lu, pos: %lu\n",
	    rng->state, rng->state->low, rng->state->pos);
#endif

  rng->state = next;

  return pos;
}

/* Returns random byte. */

SilcUInt8 silc_rng_get_byte(SilcRng rng)
{
  SilcUInt8 byte;

  rng->threshold++;

  /* Get more soft noise after 64 bits threshold */
  if (rng->threshold >= 8)
    silc_rng_get_soft_noise(rng);

  /* Get hard noise after 160 bits threshold, zero the threshold. */
  if (rng->threshold >= 20) {
    rng->threshold = 0;
    silc_rng_get_hard_noise(rng);
  }

  do byte = rng->pool[silc_rng_get_position(rng)]; while (byte == 0x00);
  return byte;
}

/* Return random byte as fast as possible. Reads from /dev/urandom if
   available. If not then return from normal RNG (not so fast). */

SilcUInt8 silc_rng_get_byte_fast(SilcRng rng)
{
#ifndef SILC_WIN32
  unsigned char buf[1];

  if (rng->fd_devurandom == -1) {
    rng->fd_devurandom = open("/dev/urandom", O_RDONLY);
    if (rng->fd_devurandom < 0)
      return silc_rng_get_byte(rng);
    fcntl(rng->fd_devurandom, F_SETFL, O_NONBLOCK);
  }

  if (read(rng->fd_devurandom, buf, sizeof(buf)) < 0)
    return silc_rng_get_byte(rng);

  return buf[0] != 0x00 ? buf[0] : silc_rng_get_byte(rng);
#else
  return silc_rng_get_byte(rng);
#endif
}

/* Returns 16 bit random number */

SilcUInt16 silc_rng_get_rn16(SilcRng rng)
{
  unsigned char rn[2];
  SilcUInt16 num;

  rn[0] = silc_rng_get_byte(rng);
  rn[1] = silc_rng_get_byte(rng);
  SILC_GET16_MSB(num, rn);

  return num;
}

/* Returns 32 bit random number */

SilcUInt32 silc_rng_get_rn32(SilcRng rng)
{
  unsigned char rn[4];
  SilcUInt32 num;

  rn[0] = silc_rng_get_byte(rng);
  rn[1] = silc_rng_get_byte(rng);
  rn[2] = silc_rng_get_byte(rng);
  rn[3] = silc_rng_get_byte(rng);
  SILC_GET32_MSB(num, rn);

  return num;
}

/* Returns non-zero random number string. Returned string is in HEX format. */

unsigned char *silc_rng_get_rn_string(SilcRng rng, SilcUInt32 len)
{
  int i;
  unsigned char *string;

  string = silc_calloc((len * 2 + 1), sizeof(unsigned char));

  for (i = 0; i < len; i++)
    sprintf(string + 2 * i, "%02x", silc_rng_get_byte(rng));

  return string;
}

/* Returns non-zero random number binary data. */

unsigned char *silc_rng_get_rn_data(SilcRng rng, SilcUInt32 len)
{
  int i;
  unsigned char *data;

  data = silc_calloc(len + 1, sizeof(*data));

  for (i = 0; i < len; i++)
    data[i] = silc_rng_get_byte(rng);

  return data;
}

/* Global RNG. This is global RNG that application can initialize so
   that any part of code anywhere can use RNG without having to allocate
   new RNG object everytime.  If this is not initialized then these routines
   will fail.  Note: currently in SILC applications always initialize this. */

SilcRng global_rng = NULL;

/* Initialize global RNG. If `rng' is provided it is set as the global
   RNG object (it can be allocated by the application for example). */

bool silc_rng_global_init(SilcRng rng)
{
  if (rng) {
    global_rng = rng;
    return TRUE;
  }

  global_rng = silc_rng_alloc();
  silc_rng_init(global_rng);

  return TRUE;
}

/* Uninitialize global RNG */

bool silc_rng_global_uninit(void)
{
  if (global_rng) {
    silc_rng_free(global_rng);
    global_rng = NULL;
  }

  return TRUE;
}

/* These are analogous to the functions above. */

SilcUInt8 silc_rng_global_get_byte(void)
{
  return global_rng ? silc_rng_get_byte(global_rng) : 0;
}

/* Return random byte as fast as possible. Reads from /dev/urandom if
   available. If not then return from normal RNG (not so fast). */

SilcUInt8 silc_rng_global_get_byte_fast(void)
{
  return global_rng ? silc_rng_get_byte_fast(global_rng) : 0;
}

SilcUInt16 silc_rng_global_get_rn16(void)
{
  return global_rng ? silc_rng_get_rn16(global_rng) : 0;
}

SilcUInt32 silc_rng_global_get_rn32(void)
{
  return global_rng ? silc_rng_get_rn32(global_rng) : 0;
}

unsigned char *silc_rng_global_get_rn_string(SilcUInt32 len)
{
  return global_rng ? silc_rng_get_rn_string(global_rng, len) : NULL;
}

unsigned char *silc_rng_global_get_rn_data(SilcUInt32 len)
{
  return global_rng ? silc_rng_get_rn_data(global_rng, len) : NULL;
}

void silc_rng_global_add_noise(unsigned char *buffer, SilcUInt32 len)
{
  if (global_rng)
    silc_rng_add_noise(global_rng, buffer, len);
}
