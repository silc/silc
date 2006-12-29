#ifndef GETOPTI_H
#define GETOPTI_H

#ifndef SILC_SYMBIAN
#if !defined(HAVE_GETOPT) && !defined(HAVE_GETOPT_H)
/* Our own convenience getopt. */
extern int opterr;
extern int optind;
extern int optopt;
extern char *optarg;
int getopt(int argc, char * const *argv, const char *optstring);
#endif /* !HAVE_GETOPT && !HAVE_GETOPT_H */
#endif /* !SILC_SYMBIAN */

#endif /* GETOPTI_H */
