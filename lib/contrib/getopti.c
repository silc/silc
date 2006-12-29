/* Our own convenience getopt.  Public Domain. */
#include "silc.h"

#ifndef SILC_SYMBIAN
#if !defined(HAVE_GETOPT) && !defined(HAVE_GETOPT_H)
int	opterr = 1;
int	optind = 1;
int	optopt;
char	*optarg;

#define GETOPT_ERR(s, c)			\
do {						\
  if (opterr) {					\
    char errbuf[2];				\
    errbuf[0] = c;				\
    errbuf[1] = '\n';				\
    (void) write(2, argv[0], strlen(argv[0]));	\
    (void) write(2, s, strlen(s));		\
    (void) write(2, errbuf, 2);			\
  }						\
} while(0)

int getopt(int argc, char * const *argv, const char *optstring)
{
  static int sp = 1;
  register int c;
  register char *cp;

  if (sp == 1) {
    if (optind >= argc ||
	argv[optind][0] != '-' || argv[optind][1] == '\0') {
      return EOF;
    } else if (strcmp(argv[optind], "--") == 0) {
      optind++;
      return EOF;
    }
  }
  optopt = c = argv[optind][sp];

  if (c == ':' || (cp=strchr(optstring, c)) == NULL) {
    GETOPT_ERR(": illegal option -- ", c);
    if (argv[optind][++sp] == '\0') {
      optind++;
      sp = 1;
    }
    return '?';
  }

  if (*++cp == ':') {
    if (argv[optind][sp+1] != '\0')
      optarg = &argv[optind++][sp+1];
    else if (++optind >= argc) {
      GETOPT_ERR(": option requires an argument -- ", c);
      sp = 1;
      return '?';
    } else
      optarg = argv[optind++];
    sp = 1;
  } else {
    if (argv[optind][++sp] == '\0') {
      sp = 1;
      optind++;
    }
    optarg = NULL;
  }

  return c;
}
#endif /* !HAVE_GETOPT && !HAVE_GETOPT_H */
#endif /* !SILC_SYMBIAN */
