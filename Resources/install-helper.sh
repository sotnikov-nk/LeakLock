#!/bin/sh
# Installs or updates the LeakLock LaunchDaemon. Run as root with the app's
# Contents/Resources directory as the only argument.
set -eu

SRC="$1"
LABEL=com.leaklock.daemon
HELPER=/Library/PrivilegedHelperTools/$LABEL
PLIST=/Library/LaunchDaemons/$LABEL.plist

[ -f "$SRC/leaklockd" ] || { echo "leaklockd not found in $SRC" >&2; exit 1; }

# Migration from the earlier "VPN Guard" builds: keep the settings and learned
# routes, then remove the old daemon so two kill switches never fight over pf.
# The new daemon loads its own rules right after it starts.
OLD=com.vpnguard.daemon
OLD_DIR="/Library/Application Support/VPNGuard"
NEW_DIR="/Library/Application Support/LeakLock"
if [ -d "$OLD_DIR" ] && [ ! -d "$NEW_DIR" ]; then
    /bin/cp -R "$OLD_DIR" "$NEW_DIR"
fi
if [ -f "/Library/LaunchDaemons/$OLD.plist" ] || [ -f "/Library/PrivilegedHelperTools/$OLD" ]; then
    /bin/launchctl bootout "system/$OLD" 2>/dev/null || true
    /bin/rm -f "/Library/LaunchDaemons/$OLD.plist" "/Library/PrivilegedHelperTools/$OLD" "/var/run/$OLD.sock"
    /sbin/pfctl -a "com.apple/050.VPNGuard" -F rules 2>/dev/null || true
fi

# pf rules stay loaded while the daemon is replaced, so there is no unprotected gap.
/bin/launchctl bootout "system/$LABEL" 2>/dev/null || true

/bin/mkdir -p /Library/PrivilegedHelperTools
/bin/cp "$SRC/leaklockd" "$HELPER.new"
/usr/bin/xattr -c "$HELPER.new" 2>/dev/null || true
/usr/sbin/chown root:wheel "$HELPER.new"
/bin/chmod 755 "$HELPER.new"
/bin/mv -f "$HELPER.new" "$HELPER"

/bin/cp "$SRC/$LABEL.plist" "$PLIST"
/usr/bin/xattr -c "$PLIST" 2>/dev/null || true
/usr/sbin/chown root:wheel "$PLIST"
/bin/chmod 644 "$PLIST"

# bootstrap can fail briefly while the old instance is still being torn down.
for _ in 1 2 3 4 5; do
    if /bin/launchctl bootstrap system "$PLIST" 2>/dev/null; then
        exit 0
    fi
    sleep 1
done
/bin/launchctl bootstrap system "$PLIST"
