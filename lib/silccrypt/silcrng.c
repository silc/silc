/*

  silcrng.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * Created: Sun Mar  9 00:09:18 1997
 *
 * This RNG is based on Secure Shell's random number generator.
 */
/* XXX: Some operations block resulting slow initialization.
 * XXX: I have some pending changes to make this better. */
/*
 * $Id$
 * $Log$
 * Revision 1.2  2000/07/05 06:08:43  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"

#undef SILC_RNG_DEBUG
/* #define SILC_RNG_DEBUG */

/* 
   SILC SilcRng State context.

   This object is used by the random number generator to provide
   variable points where the actual random number is fetched from
   the random pool. This provides that the data is not fetched always
   from the same point of the pool. Short description of the fields
   following.

   unsigned int low
   unsigned int pos

       The index for the random pool buffer. Lowest and current
       positions.

   SilcRngStateContext *next

       Pointer to the next state. If this is the last state this
       will point to the first state thus providing circular list.

*/
typedef struct SilcRngStateContext {
  unsigned int low;
  unsigned int pos;
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

*/
typedef struct SilcRngObjectStruct {
  unsigned char pool[SILC_RNG_POOLSIZE];
  unsigned char key[64];
  SilcRngState state;
  SilcHash sha1;
} SilcRngObject;

/* Allocates new RNG object. */

SilcRng silc_rng_alloc()
{
  SilcRng new;

  SILC_LOG_DEBUG(("Allocating new RNG object"));

  new = silc_calloc(1, sizeof(*new));

  memset(new->pool, 0, sizeof(new->pool));
  memset(new->key, 0, sizeof(new->key));
  new->state = NULL;
  silc_hash_alloc("sha1", &new->sha1);

  return new;
}

/* Free's RNG object. */

void silc_rng_free(SilcRng rng)
{
  if (rng) {
    memset(rng->pool, 0, sizeof(rng->pool));
    memset(rng->key, 0, sizeof(rng->key));
    silc_free(rng->sha1);
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
#if 0
    next->pos = sizeof(rng->pool) - 
      ((i * (sizeof(rng->pool) / SILC_RNG_STATE_NUM))) + 8;
#endif
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
}

/* This function gets 'soft' noise from environment. */

void silc_rng_get_soft_noise(SilcRng rng)
{
  struct tms ptime;
  
  silc_rng_xor(rng, clock(), 0);
  silc_rng_xor(rng, getpid(), 1);
  silc_rng_xor(rng, getpgid(getpid() << 8), 2);
  silc_rng_xor(rng, getpgid(getpid() << 8), 3);
  silc_rng_xor(rng, getgid(), 4);
  silc_rng_xor(rng, getpgrp(), 5);
  silc_rng_xor(rng, getsid(getpid() << 16), 6);
  silc_rng_xor(rng, times(&ptime), 7);
  silc_rng_xor(rng, ptime.tms_utime, 8);
  silc_rng_xor(rng, (ptime.tms_utime + ptime.tms_stime), 9);
  silc_rng_xor(rng, (ptime.tms_stime + ptime.tms_cutime), 10);
  silc_rng_xor(rng, (ptime.tms_utime + ptime.tms_stime), 11);
  silc_rng_xor(rng, (ptime.tms_cutime ^ ptime.tms_stime), 12);
  silc_rng_xor(rng, (ptime.tms_cutime ^ ptime.tms_cstime), 13);
  silc_rng_xor(rng, (ptime.tms_utime ^ ptime.tms_stime), 14);
  silc_rng_xor(rng, (ptime.tms_stime ^ ptime.tms_cutime), 15);
  silc_rng_xor(rng, (ptime.tms_cutime + ptime.tms_stime), 16);
  silc_rng_xor(rng, (ptime.tms_stime << 8), 17);
  silc_rng_xor(rng, clock() << 4, 18);
  silc_rng_xor(rng, getpgid(getpid() << 8), 19);
  silc_rng_xor(rng, getpgrp(), 20);
  silc_rng_xor(rng, getsid(getpid() << 16), 21);
  silc_rng_xor(rng, times(&ptime), 22);
  silc_rng_xor(rng, ptime.tms_utime, 23);
  silc_rng_xor(rng, getpgrp(), 24);

  /* Stir random pool */
  silc_rng_stir_pool(rng);
}

/* This function gets noise from different commands */

void silc_rng_get_medium_noise(SilcRng rng)
{
  silc_rng_exec_command(rng, "ps -lefaww 2> /dev/null");
  silc_rng_exec_command(rng, "ls -afiln 2> /dev/null");
  silc_rng_exec_command(rng, "ps -asww 2> /dev/null");
  silc_rng_exec_command(rng, "ls -afiln /proc 2> /dev/null");
  /*
  silc_rng_exec_command(rng, "ps -ef 2> /dev/null");
  silc_rng_exec_command(rng, "ls -alin /dev 2> /dev/null");
  */
}

/* This function gets 'hard' noise from environment. This tries to
   get the noise from /dev/random if available. */

void silc_rng_get_hard_noise(SilcRng rng)
{
  char buf[32];
  int fd, len, i;
  
  /* Get noise from /dev/random if available */
  fd = open("/dev/random", O_RDONLY);
  if (fd < 0)
    return;

  fcntl(fd, F_SETFL, O_NONBLOCK);

  for (i = 0; i < 8; i++) {
    len = read(fd, buf, sizeof(buf));
    if (len <= 0)
      goto out;
    silc_rng_add_noise(rng, buf, len);
  }

 out:
  close(fd);
  memset(buf, 0, sizeof(buf));
}

/* Execs command and gets noise from its output */

void silc_rng_exec_command(SilcRng rng, char *command)
{
  char buf[2048];
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
    if (c == EOF) {
      if (!i)
	return;
      break; 
    }
    buf[i] = c;
  }
  
  pclose(fd);
  
  /* Add the buffer into random pool */
  silc_rng_add_noise(rng, buf, strlen(buf));
  memset(buf, 0, sizeof(buf));
}

/* This function adds the contents of the buffer as noise into random 
   pool. After adding the noise the pool is stirred. */

void silc_rng_add_noise(SilcRng rng, unsigned char *buffer, 
			unsigned int len)
{
  unsigned int i, pos;

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

void silc_rng_xor(SilcRng rng, unsigned int val, unsigned int pos)
{
  assert(rng != NULL);
  rng->pool[pos] ^= val + val;
}

/* This function stirs the random pool by encrypting buffer in CFB 
   (cipher feedback) mode with SHA1 algorithm. */

void silc_rng_stir_pool(SilcRng rng)
{
  int i;
  unsigned long iv[5];

  /* Get the IV */
  memcpy(iv, &rng->pool[SILC_RNG_POOLSIZE - 256], sizeof(iv));

  /* First CFB pass */
  for (i = 0; i < SILC_RNG_POOLSIZE; i += 5) {
    rng->sha1->hash->transform(iv, rng->key);
    iv[0] = rng->pool[i] ^= iv[0];
    iv[1] = rng->pool[i + 1] ^= iv[1];
    iv[2] = rng->pool[i + 2] ^= iv[2];
    iv[3] = rng->pool[i + 3] ^= iv[3];
    iv[4] = rng->pool[i + 4] ^= iv[4];
  }

  /* Get new key */
  memcpy(rng->key, &rng->pool[silc_rng_get_position(rng)], sizeof(rng->key));

  /* Second CFB pass */
  for (i = 0; i < SILC_RNG_POOLSIZE; i += 5) {
    rng->sha1->hash->transform(iv, rng->key);
    iv[0] = rng->pool[i] ^= iv[0];
    iv[1] = rng->pool[i + 1] ^= iv[1];
    iv[2] = rng->pool[i + 2] ^= iv[2];
    iv[3] = rng->pool[i + 3] ^= iv[3];
    iv[4] = rng->pool[i + 4] ^= iv[4];
  }

  memset(iv, 0, sizeof(iv));
}

/* Returns next position where data is fetched from the pool or
   put to the pool. */

unsigned int silc_rng_get_position(SilcRng rng)
{
  SilcRngState next;
  unsigned int pos;

  next = rng->state->next;

  pos = rng->state->pos++;
  if ((next->low != 0 && pos >= next->low) || (pos >= SILC_RNG_POOLSIZE))
    rng->state->pos = rng->state->low;

#ifdef SILC_RNG_DEBUG
    fprintf(stderr, "state: %p: low: %d, pos: %d\n", 
	    rng->state, rng->state->low, rng->state->pos);
#endif

  rng->state = next;

  return pos;
}

/* returns random byte. Every two byte is from pools low or high state. */

unsigned char silc_rng_get_byte(SilcRng rng)
{
  return rng->pool[silc_rng_get_position(rng)];
}

/* Returns 16 bit random number */

unsigned short silc_rng_get_rn16(SilcRng rng)
{
  unsigned char rn[2];
  unsigned short num;

  rn[0] = silc_rng_get_byte(rng);
  rn[1] = silc_rng_get_byte(rng);
  SILC_GET16_MSB(num, rn);

  return num;
}

/* Returns 32 bit random number */

unsigned int silc_rng_get_rn32(SilcRng rng)
{
  unsigned char rn[4];
  unsigned short num;

  rn[0] = silc_rng_get_byte(rng);
  rn[1] = silc_rng_get_byte(rng);
  rn[2] = silc_rng_get_byte(rng);
  rn[3] = silc_rng_get_byte(rng);
  SILC_GET32_MSB(num, rn);

  return num;
}

/* Returns random number string. Returned string is in HEX format. */

unsigned char *silc_rng_get_rn_string(SilcRng rng, unsigned int len)
{
  int i;
  unsigned char *string;

  string = silc_calloc((len * 2 + 1), sizeof(unsigned char));

  for (i = 0; i < len; i++)
    sprintf(string + 2 * i, "%02x", silc_rng_get_byte(rng));

  return string;
}
