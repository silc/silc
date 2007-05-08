/* includes/silcdefs.h.  Generated automatically by configure.  */
/* includes/silcdefs.h.in.  Generated automatically from configure.in by autoheader.  */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef gid_t */

/* Define as __inline if that's what the C compiler calls it.  */
/* #undef inline */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef mode_t */

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef pid_t */

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define to `unsigned' if <sys/types.h> doesn't define.  */
/* #undef size_t */

/* Define if the `S_IS*' macros in <sys/stat.h> do not work properly.  */
/* #undef STAT_MACROS_BROKEN */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef uid_t */

/* Debugging */
/* #undef SILC_DEBUG */

/* Default configuration file */
/* #undef SILC_SERVER_CONFIG_FILE */

/* Multi-thread support */
#define SILC_THREADS 1

/* Default paths */
#define SILC_ETCDIR "/etc/silc"
#define SILC_HELPDIR "help"
#define SILC_DOCDIR "doc"
#define SILC_MODULESDIR "modules"
#define SILC_LOGSDIR "logs"

/* SIM (SILC Module) support */
/* #undef SILC_SIM */
/* #undef HAVE_RTLD_NOW */
/* #undef HAVE_RTLD_LAZY */

/* Types */
/*
#define SILC_SIZEOF_LONG_LONG 8
#define SILC_SIZEOF_LONG 4
#define SILC_SIZEOF_INT 4
#define SILC_SIZEOF_SHORT 2
#define SILC_SIZEOF_CHAR 1
#define SILC_SIZEOF_VOID_P 4
*/

/* MP library */
/* #undef SILC_MP_GMP */
#define SILC_MP_SILCMATH 1

/* Redefs for SOCKS5 library */
/* macros/curses checks */
/* #undef HAS_CURSES */
/* #undef USE_SUNOS_CURSES */
/* #undef USE_BSD_CURSES */
/* #undef USE_SYSV_CURSES */
/* #undef USE_NCURSES */
/* #undef NO_COLOR_CURSES */
/* #undef SCO_FLAVOR */

/* #undef SOCKS */
/* #undef SOCKS5 */
/* #undef Rconnect */
/* #undef Rgetsockname */
/* #undef Rgetpeername */
/* #undef Rbind */
/* #undef Raccept */  
/* #undef Rlisten */
/* #undef Rselect */
/* #undef Rrecvfrom */
/* #undef Rsendto */
/* #undef Rrecv */
/* #undef Rsend */
/* #undef Rread */
/* #undef Rwrite */
/* #undef Rrresvport */
/* #undef Rshutdown */
/* #undef Rlisten */
/* #undef Rclose */
/* #undef Rdup */
/* #undef Rdup2 */
/* #undef Rfclose */
/* #undef Rgethostbyname */

/* Native WIN32 compilation (-mno-cygwin GCC option) under cygwin, though
   the code compiles with any native WIN32 compiler. */
#ifndef SILC_WIN32
#define SILC_WIN32 1
#endif

/* SILC distribution definitions (leave this at the end of file) */
#define SILC_DIST_TOOLKIT 1
/* #undef SILC_DIST_CLIENT */
/* #undef SILC_DIST_SERVER */
/* #undef SILC_DIST_WIN32DLL */

/* The number of bytes in a char.  */
#define SIZEOF_CHAR 1

/* The number of bytes in a int.  */
#define SIZEOF_INT 4

/* The number of bytes in a long.  */
#define SIZEOF_LONG 4

/* The number of bytes in a long long.  */
#define SIZEOF_LONG_LONG 8

/* The number of bytes in a short.  */
#define SIZEOF_SHORT 2

/* The number of bytes in a void *.  */
#define SIZEOF_VOID_P 4

/* Define if you have the bind function.  */
#define HAVE_BIND 1

/* Define if you have the chmod function.  */
#define HAVE_CHMOD 1

/* Define if you have the close function.  */
#define HAVE_CLOSE 1

/* Define if you have the connect function.  */
#define HAVE_CONNECT 1

/* Define if you have the ctime function.  */
#define HAVE_CTIME 1

/* Define if you have the fcntl function.  */
#define HAVE_FCNTL 1

/* Define if you have the fstat function.  */
#define HAVE_FSTAT 1

/* Define if you have the getenv function.  */
#define HAVE_GETENV 1

/* Define if you have the getgid function.  */
#define HAVE_GETGID 1

/* Define if you have the gethostbyaddr function.  */
#define HAVE_GETHOSTBYADDR 1

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have the getopt_long function.  */
#define HAVE_GETOPT_LONG 1

/* Define if you have the getpgid function.  */
#define HAVE_GETPGID 1

/* Define if you have the getpgrp function.  */
#define HAVE_GETPGRP 1

/* Define if you have the getpid function.  */
#define HAVE_GETPID 1

/* Define if you have the getservbyname function.  */
#define HAVE_GETSERVBYNAME 1

/* Define if you have the getservbyport function.  */
#define HAVE_GETSERVBYPORT 1

/* Define if you have the getsid function.  */
/* #undef HAVE_GETSID */

/* Define if you have the gettimeofday function.  */
#define HAVE_GETTIMEOFDAY 1

/* Define if you have the getuid function.  */
#define HAVE_GETUID 1

/* Define if you have the listen function.  */
#define HAVE_LISTEN 1

/* Define if you have the memcpy function.  */
#define HAVE_MEMCPY 1

/* Define if you have the memmove function.  */
#define HAVE_MEMMOVE 1

/* Define if you have the memset function.  */
#define HAVE_MEMSET 1

/* Define if you have the mlock function.  */
/* #undef HAVE_MLOCK */

/* Define if you have the munlock function.  */
/* #undef HAVE_MUNLOCK */

/* Define if you have the pthread_create function.  */
#define HAVE_PTHREAD_CREATE 1

/* Define if you have the putenv function.  */
#define HAVE_PUTENV 1

/* Define if you have the select function.  */
#define HAVE_SELECT 1

/* Define if you have the setsockopt function.  */
#define HAVE_SETSOCKOPT 1

/* Define if you have the shutdown function.  */
#define HAVE_SHUTDOWN 1

/* Define if you have the stat function.  */
#define HAVE_STAT 1

/* Define if you have the strchr function.  */
#define HAVE_STRCHR 1

/* Define if you have the strcpy function.  */
#define HAVE_STRCPY 1

/* Define if you have the strerror function.  */
#define HAVE_STRERROR 1

/* Define if you have the strncpy function.  */
#define HAVE_STRNCPY 1

/* Define if you have the strstr function.  */
#define HAVE_STRSTR 1

/* Define if you have the time function.  */
#define HAVE_TIME 1

/* Define if you have the <arpa/inet.h> header file.  */
#define HAVE_ARPA_INET_H 1

/* Define if you have the <assert.h> header file.  */
#define HAVE_ASSERT_H 1

/* Define if you have the <ctype.h> header file.  */
#define HAVE_CTYPE_H 1

/* Define if you have the <dlfcn.h> header file.  */
#define HAVE_DLFCN_H 1

/* Define if you have the <errno.h> header file.  */
#define HAVE_ERRNO_H 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <getopt.h> header file.  */
#define HAVE_GETOPT_H 1

/* Define if you have the <grp.h> header file.  */
#define HAVE_GRP_H 1

/* Define if you have the <limits.h> header file.  */
#define HAVE_LIMITS_H 1

/* Define if you have the <ncurses.h> header file.  */
#define HAVE_NCURSES_H 1

/* Define if you have the <netdb.h> header file.  */
#define HAVE_NETDB_H 1

/* Define if you have the <netinet/in.h> header file.  */
#define HAVE_NETINET_IN_H 1

/* Define if you have the <netinet/tcp.h> header file.  */
#define HAVE_NETINET_TCP_H 1

/* Define if you have the <paths.h> header file.  */
#define HAVE_PATHS_H 1

/* Define if you have the <pthread.h> header file.  */
#define HAVE_PTHREAD_H 1

/* Define if you have the <pwd.h> header file.  */
#define HAVE_PWD_H 1

/* Define if you have the <regex.h> header file.  */
#define HAVE_REGEX_H 1

/* Define if you have the <signal.h> header file.  */
#define HAVE_SIGNAL_H 1

/* Define if you have the <string.h> header file.  */
#define HAVE_STRING_H 1

/* Define if you have the <sys/mman.h> header file.  */
#define HAVE_SYS_MMAN_H 1

/* Define if you have the <sys/stat.h> header file.  */
#define HAVE_SYS_STAT_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <termcap.h> header file.  */
#define HAVE_TERMCAP_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1
