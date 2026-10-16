#!/bin/sh
# Removes the LeakLock LaunchDaemon and lifts the block. Settings are kept in
# /Library/Application Support/LeakLock for a later reinstall.
set -u

LABEL=com.leaklock.daemon

/bin/launchctl bootout "system/$LABEL" 2>/dev/null || true
/bin/rm -f "/Library/LaunchDaemons/$LABEL.plist" "/Library/PrivilegedHelperTools/$LABEL" "/var/run/$LABEL.sock"
/sbin/pfctl -a "com.apple/050.LeakLock" -F rules 2>/dev/null || true
exit 0
