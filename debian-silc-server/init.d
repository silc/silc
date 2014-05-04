#! /bin/sh
### BEGIN INIT INFO
# Provides:          silcd
# Required-Start:    $local_fs $remote_fs $network
# Required-Stop:     $local_fs $remote_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SILC server
# Description:       A server for the Secure Live Internet Conferencing (SILC)
#                    protocol.
### END INIT INFO

# Author: Jérémy Bobbio <lunar@debian.org>

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="SILC server"
NAME=silcd
DAEMON=/usr/sbin/$NAME
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
CONFIGFILE=/etc/$NAME/$NAME.conf

# Exit if the package is not installed
[ -x "$DAEMON" ] || exit 0

# Exit if configuration file is not readable
[ -r "$CONFIGFILE" ] || exit 0

read_config() {
    PARAMETER="$1"
    sed -n -e "s/^[^#]*$PARAMETER  *=  *\"\([^\"]*\)\".*$/\1/p" "$CONFIGFILE"
}

PRIVATE_KEY="$(read_config PrivateKey)"

# Exit if private key is not readable
[ -r "$PRIVATE_KEY" ] || exit 0

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions

do_start()
{
    start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON \
        --test > /dev/null || return 1
    start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON \
        || return 2
}

do_stop()
{
    start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 \
        --pidfile $PIDFILE --name $NAME
    RETVAL="$?"
    [ "$RETVAL" = 2 ] && return 2
    start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 \
        --exec $DAEMON
    [ "$?" = 2 ] && return 2
    rm -f $PIDFILE
    return "$RETVAL"
}

do_reload() {
    start-stop-daemon --stop --signal 1 --quiet --pidfile $PIDFILE \
        --name $NAME
    return 0
}

case "$1" in
    start)
        [ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
        do_start
        case "$?" in
            0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
            2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
        esac
        ;;
    stop)
        [ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
        do_stop
        case "$?" in
            0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
            2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
        esac
        ;;
    reload|force-reload)
        log_daemon_msg "Reloading $DESC" "$NAME"
        do_reload
        log_end_msg $?
        ;;
    restart)
        log_daemon_msg "Restarting $DESC" "$NAME"
        do_stop
        case "$?" in
            0|1)
                do_start
                case "$?" in
                    0) log_end_msg 0 ;;
                    1) log_end_msg 1 ;; # Old process is still running
                    *) log_end_msg 1 ;; # Failed to start
                esac
                ;;
            *)
                # Failed to stop
                log_end_msg 1
                ;;
        esac
        ;;
    *)
        echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload}" >&2
        exit 3
        ;;
esac

:

#vim et sw=4
