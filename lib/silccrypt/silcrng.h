/*

  silcrng.h
 
  COPYRIGHT
 
  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>
 
  Copyright (C) 1997 - 2001 Pekka Riikonen
 
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 
*/

/****h* silccrypt/SilcRNGAPI
 *
 * DESCRIPTION
 *
 * SILC Random Number Generator is cryptographically strong pseudo random
 * number generator. It is used to generate all the random numbers needed
 * in the SILC sessions. All key material and other sources needing random
 * numbers use this generator.
 *
 * The RNG has a random pool of 1024 bytes of size that provides the actual
 * random numbers for the application. The pool is initialized when the
 * RNG is allocated and initialized with silc_rng_alloc and silc_rng_init
 * functions, respectively. 
 *
 *
 * Random Pool Initialization
 *
 * The RNG's random pool is the source of all random output data. The pool is
 * initialized with silc_rng_init and application can reseed it at any time
 * by calling the silc_rng_add_noise function.
 *
 * The initializing phase attempts to set the random pool in a state that it
 * is impossible to learn the input data to the RNG or any random output
 * data. This is achieved by acquiring noise from various system sources. The
 * first source is called to provide "soft noise". This noise is various
 * data from system's processes. The second source is called to provide
 * "medium noise". This noise is various output data from executed commands.
 * Usually the commands are Unix `ps' and `ls' commands with various options.
 * The last source is called to provide "hard noise" and is noise from
 * system's /dev/random, if it exists.
 *
 *
 * Stirring the Random Pool
 *
 * Every time data is acquired from any source, the pool is stirred. The
 * stirring process performs an CFB (cipher feedback) encryption with SHA1
 * algorithm to the entire random pool. First it acquires an IV (Initial
 * Vector) from the constant (random) location of the pool and performs
 * the first CFB pass. Then it acquires a new encryption key from variable
 * location of the pool and performs the second CFB pass. The encryption
 * key thus is always acquired from unguessable data.
 *
 * The encryption process to the entire random pool assures that it is
 * impossible to learn the input data to the random pool without breaking the
 * encryption process. This would effectively mean breaking the SHA1 hash
 * function. The encryption process also assures that each random output from
 * the random pool is secured with cryptographically strong function, the
 * SHA1 in this case.
 *
 * The random pool can be restirred by the application at any point by
 * calling the silc_rng_add_noise function. This function adds new noise to
 * the pool and then stirs the entire pool.
 *
 *
 * Stirring Threshholds
 *
 * The random pool has two threshholds that controls when the random pool
 * needs more new noise and requires restirring. As previously mentioned, the
 * application may do this by calling the silc_rng_add_noise. However, the
 * RNG performs this also automatically.
 *
 * The first threshhold gets soft noise from system and stirs the random pool.
 * The threshhold is reached after 64 bits of random data has been fetched
 * from the RNG. After the 64 bits, the soft noise acquiring and restirring
 * process is performed every 8 bits of random output data until the second
 * threshhold is reached.
 *
 * The second threshhold gets hard noise from system and stirs the random
 * pool. The threshhold is reached after 160 bits of random output. After the
 * noise is acquired (from /dev/urandom) the random pool is stirred and the
 * threshholds are set to zero. The process is repeated again after 64 bits of
 * output for first threshhold and after 160 bits of output for the second
 * threshhold.
 *
 *
 * Internal State of the Random Pool
 *
 * The random pool has also internal state that provides several variable
 * distinct points to the random pool where the data is fetched. The state
 * changes every 8 bits of output data and it is guaranteed that the fetched
 * 8 bits of data is from distinct location compared to the previous 8 bits.
 * It is also guaranteed that the internal state never wraps before
 * restirring the entire random pool. The internal state means that the data
 * is not fetched linearly from the pool, eg. starting from zero and wrapping
 * at the end of the pool. The internal state is not dependent of any random
 * data in the pool. The internal states are initialized (by default the pool
 * is splitted to four different sections (states)) at the RNG
 * initialization phase. The state's current position is added linearly and
 * wraps at the the start of the next state. The states provides the distinct
 * locations.
 *
 *
 * Security Considerations
 *
 * The security of this random number generator, like of any other RNG's,
 * depends of the initial state of the RNG. The initial state of the random
 * number generators must be unknown to an adversary. This means that after
 * the RNG is initialized it is required that the input data to the RNG and
 * the output data to the application has no correlation of any kind that
 * could be used to compromise the acquired random numbers or any future
 * random numbers. 
 *
 * It is, however, clear that the correlation exists but it needs to be
 * hard to solve for an adversary. To accomplish this the input data to the
 * random number generator needs to be secret. Usually this is impossible to
 * achieve. That is why SILC's RNG acquires the noise from three different
 * sources and provides for the application an interface to add more noise at
 * any time. The first source ("soft noise") is known to the adversary but
 * requires exact timing to get all of the input data. However, getting only
 * partial data is easy. The second source ("medium noise") depends on the
 * place of execution of the application. Getting at least partial data is
 * easy but securing for example the user's home directory from outside access
 * makes it harder. The last source ("hard noise") is considered to be the
 * most secure source of data. An adversary is not considered to have any
 * access on this data. This of course greatly depends on the operating system.
 *
 * These three sources are considered to be adequate since the random pool is
 * relatively large and the output of each bit of the random pool is secured
 * by cryptographically secure function, the SHA1 in CFB mode encryption.
 * Furthermore the application may provide other random data, such as random
 * key strokes or mouse movement to the RNG. However, it is recommended that
 * the application would not be the single point of source for the RNG, in
 * either intializing or reseeding phases later in the session. Good solution
 * is probably to use both, the application's seeds and the RNG's own
 * sources, equally.
 *
 * The RNG must also assure that any old or future random numbers are not
 * compromised if an adversary would learn the initial input data (or any
 * input data for that matter). The SILC's RNG provides good protection for
 * this even if the some of the input bits would be compromised for old or
 * future random numbers. The RNG reinitalizes (reseeds) itself using the
 * threshholds after every 64 and 160 bits of output. This is considered to be
 * adequate even if some of the bits would get compromised. Also, the
 * applications that use the RNG usually fetches at least 256 bits from the
 * RNG. This means that everytime RNG is accessed both of the threshholds are
 * reached. This should mean that the RNG is never too long in an compromised
 * state and recovers as fast as possible.
 *
 * Currently the SILC's RNG does not use random seed files to store some
 * random data for future initializing. This is important and must be
 * implemented in the future.
 *
 * The caller must be cautios when using this RNG with native WIN32 system.
 * The RNG most likely is impossible to set in unguessable state just by
 * using the RNG's input data sources.  On WIN32 it is stronly suggested
 * that caller would add more random noise after the initialization of the
 * RNG using the silc_rng_add_noise function.  For example, random mouse
 * movements may be used.
 *
 ***/

#ifndef SILCRNG_H
#define SILCRNG_H

/* Forward declaration. Actual object is in source file. */
typedef struct SilcRngObjectStruct *SilcRng;

/* Prototypes */
SilcRng silc_rng_alloc();
void silc_rng_free(SilcRng rng);
void silc_rng_init(SilcRng rng);
unsigned char silc_rng_get_byte(SilcRng rng);
uint16 silc_rng_get_rn16(SilcRng rng);
uint32 silc_rng_get_rn32(SilcRng rng);
unsigned char *silc_rng_get_rn_string(SilcRng rng, uint32 len);
unsigned char *silc_rng_get_rn_data(SilcRng rng, uint32 len);
void silc_rng_add_noise(SilcRng rng, unsigned char *buffer, uint32 len);

int silc_rng_global_init(SilcRng rng);
int silc_rng_global_uninit();
unsigned char silc_rng_global_get_byte();
unsigned char silc_rng_global_get_byte_fast();
uint16 silc_rng_global_get_rn16();
uint32 silc_rng_global_get_rn32();
unsigned char *silc_rng_global_get_rn_string(uint32 len);
unsigned char *silc_rng_global_get_rn_data(uint32 len);
void silc_rng_global_add_noise(unsigned char *buffer, uint32 len);

#endif
