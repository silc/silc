/*

  test_hash.c

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

#include "silc.h"

#define HASH_LEN 0x0002ffff	/* hash data len (at least) */
#define HASH_ROUND 256		/* hash rounds (at least) */
#define HASH_MIN_TIME 2.0       /* seconds to run the test (at least) */

SilcTimerStruct timer;
SilcHash hash;

int main(int argc, char **argv)
{
  SilcUInt64 sec;
  SilcUInt32 usec;
  double totsec;
  unsigned char *data;
  SilcUInt32 rounds;
  unsigned char digest[SILC_HASH_MAXLEN];
  int i, k;

  data = malloc(HASH_LEN * sizeof(*data));
  if (!data)
    exit(1);

  for (i = 0; i < HASH_LEN; i++)
    data[i] = i % 255;

  silc_timer_synchronize(&timer);

  for (i = 0; silc_default_hash[i].name; i++) {
    if (!silc_hash_alloc(silc_default_hash[i].name, &hash))
      exit(1);
    silc_hash_init(hash);

    rounds = HASH_ROUND;

  retry:
    silc_timer_start(&timer);
    for (k = 0; k < rounds; k++)
      silc_hash_update(hash, data, HASH_LEN);
    silc_timer_stop(&timer);
    silc_hash_final(hash, digest);

    silc_timer_value(&timer, &sec, &usec);
    totsec = (double)sec;
    totsec += ((double)usec / (double)(1000 * 1000));
    if (totsec < HASH_MIN_TIME) {
      rounds *= 2;
      goto retry;
    }

    printf("%s:\t%.2f KB (%.2f MB) / sec (total test time %.2f secs)\n",
	   silc_default_hash[i].name,
	   (((double)(HASH_LEN * rounds) / 1024.0) / totsec),
	   (((double)(HASH_LEN * rounds) / (1024.0 * 1024.0)) / totsec),
	   totsec);

    silc_hash_free(hash);
  }

  return 0;
}
