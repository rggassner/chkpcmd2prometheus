#!/bin/bash
#Add this to run in cron every minute or so
LOCK_FD=200
LOCK_NAME="/yourdir/chkpcmd2prometheus/chkpcmd2prometheus.lock"
PYTHON_SCRIPT="/yourdir/chkpcmd2prometheus/chkpcmd2prometheus.py"
LOGFILE="/yourdir/chkpcmd2prometheus/chkpcmd2prometheus.log"

# Open the lock file and attach file descriptor 200 to it
exec {LOCK_FD}>$LOCK_NAME || exit 1

# Try to get the lock, exit if already locked
flock -n "$LOCK_FD" || {
    echo "[$(date)] Script already running. Exiting."
    exit 1
}

cd /yourdir/chkpcmd2prometheus/
# If we got the lock, run the script
"$PYTHON_SCRIPT" 

