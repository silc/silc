/* Locking performance tests.  Gives locsk&unlocks/second. */
/* Version 1.0 */

#include "silc.h"

typedef struct {
  SilcThread thread;
  SilcInt64 time;
} Context;

#define MAX_ROUND 8
#define MAX_MUL 4
#define MAX_THREADS 4
#define MAX_LOCKS 471234567

SilcMutex mutex;
SilcUInt64 cpu_freq = 0;
int max_locks, max_locks2;

/* RDTSC */
#ifdef SILC_I486
static __inline__ unsigned long long rdtsc(void)
{
  unsigned long long int x;
  __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
  return x;
}

#elif SILC_X86_64
typedef unsigned long long int unsigned long long;
static __inline__ unsigned long long rdtsc(void)
{
  unsigned hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

#elif SILC_POWERPC
typedef unsigned long long int unsigned long long;
static __inline__ unsigned long long rdtsc(void)
{
  unsigned long long int result = 0;
  unsigned long int upper, lower,tmp;
  __asm__ volatile(
                "0:                  \n"
                "\tmftbu   %0           \n"
                "\tmftb    %1           \n"
                "\tmftbu   %2           \n"
                "\tcmpw    %2,%0        \n"
                "\tbne     0b         \n"
                : "=r"(upper),"=r"(lower),"=r"(tmp)
                );
  result = upper;
  result = result << 32;
  result = result | lower;

  return result;
}
#endif

void *mutex_thread(void *context)
{
  Context *c = context;
  SilcInt64 s;
  register int i;

  s = rdtsc();
  for (i = 0; i < max_locks; i++) {
    silc_mutex_lock(mutex);
    silc_mutex_unlock(mutex);
  }
  c->time = rdtsc() - s;
  c->time /= cpu_freq;

  return NULL;
}

SilcUInt64 hval;
SilcUInt64 hval2;
SilcUInt64 hval3;

void *mutex_thread_hold(void *context)
{
  Context *c = context;
  SilcInt64 s;
  register int i;

  s = rdtsc();
  for (i = 0; i < max_locks / 4; i++) {
    silc_mutex_lock(mutex);
    hval2 = i;
    hval3 = 0;
    hval++;
    hval3 = hval2 + i;
    hval += hval2;
    hval3 += hval;
    if (silc_unlikely(hval3 != hval2 + i + hval)) {
      fprintf(stderr, "MUTEX CORRUPT 1\n");
      exit(1);
    }
    if (silc_unlikely(hval2 != i)) {
      fprintf(stderr, "MUTEX CORRUPT 2 (%llu != %d)\n", hval2, i);
      exit(1);
    }
    silc_mutex_unlock(mutex);
  }
  c->time = rdtsc() - s;
  c->time /= cpu_freq;

  return NULL;
}

int main(int argc, char **argv)
{
  Context c[MAX_THREADS * MAX_MUL];
  SilcInt64 val;
  int k, i, j, o = 0;
  SilcBool success;

  if (argc <= 1) {
    fprintf(stderr, "Usage: ./test_silcmutex <cpu_freq_mhz>\n");
    fprintf(stderr, "Example: ./test_silcmutex 3000\n");
    exit(1);
  }
  cpu_freq = (SilcUInt64)atoi(argv[1]);
  cpu_freq *= 1000;	/* Will give us milliseconds */

  max_locks = MAX_LOCKS;

  fprintf(stderr, "lock/unlock per second\n");

  for (j = 0; j < MAX_ROUND; j++) {
    for (i = 0; i < 1; i++)
      c[i].thread = silc_thread_create(mutex_thread, &c[i], TRUE);

    val = 0;
    for (i = 0; i < 1; i++) {
      silc_thread_wait(c[i].thread, NULL);
      val += c[i].time;
    }
    fprintf(stderr, "%llu mutex lock/unlock per second (%d threads)\n",
		      (1000LL * max_locks * 1) / val, 1);

    if (o == 0) {
      /* If MAX_LOCKS is too large for this CPU, optimize.  We don't want to
	 wait a whole day for this test. */
      if ((SilcInt64)(max_locks / 10) >
	  (SilcInt64)((1000LL * max_locks) / val))
      	max_locks /= 10;
      o = 1;
    }
  }
  puts("");

  max_locks2 = max_locks;
  for (k = 0; k < MAX_MUL; k++) {
    sleep(16);
    max_locks = max_locks2 / (k + 1);
    for (j = 0; j < MAX_ROUND; j++) {
      for (i = 0; i < MAX_THREADS * (k + 1); i++)
	c[i].thread = silc_thread_create(mutex_thread, &c[i], TRUE);

      val = 0;
      for (i = 0; i < MAX_THREADS * (k + 1); i++) {
	silc_thread_wait(c[i].thread, NULL);
	val += c[i].time;
      }
      fprintf(stderr, "%llu mutex lock/unlock per second (%d threads)\n",
		      (1000LL * max_locks * (MAX_THREADS * (k + 1))) / val,
		      MAX_THREADS * (k + 1));
    }
    puts("");
  }
  max_locks = max_locks2;

  fprintf(stderr, "Spinning/holding lock, lock/unlock per second\n");

  max_locks /= 2;
  sleep(5);
  for (j = 0; j < MAX_ROUND / 2; j++) {
    for (i = 0; i < 1; i++)
      c[i].thread = silc_thread_create(mutex_thread_hold, &c[i], TRUE);

    val = 0;
    for (i = 0; i < 1; i++) {
      silc_thread_wait(c[i].thread, NULL);
      val += c[i].time;
    }
    fprintf(stderr, "%llu mutex lock/unlock per second (%d threads)\n",
                      (1000LL * (max_locks / 4) * 1) / val, 1);
  }
  puts("");

  max_locks2 = max_locks;
  max_locks2 /= 2;
  for (k = 0; k < MAX_MUL; k++) {
    sleep(2);
    max_locks = max_locks2 / (k + 1);
    for (j = 0; j < MAX_ROUND / 2; j++) {
      hval = hval2 = 1;
      for (i = 0; i < MAX_THREADS * (k + 1); i++)
        c[i].thread = silc_thread_create(mutex_thread_hold, &c[i], TRUE);

      val = 0;
      for (i = 0; i < MAX_THREADS * (k + 1); i++) {
        silc_thread_wait(c[i].thread, NULL);
        val += c[i].time;
      }
      fprintf(stderr, "%llu mutex lock/unlock per second (%d threads)\n",
                      (1000LL * (max_locks / 4) *
                       (MAX_THREADS * (k + 1))) / val,
                      MAX_THREADS * (k + 1));
    }
    puts("");
  }

  success = TRUE;

  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
