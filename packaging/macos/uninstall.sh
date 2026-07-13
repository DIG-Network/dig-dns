#!/bin/sh
# dig-dns macOS uninstaller (dig_ecosystem #530).
#
# A .pkg has no built-in uninstaller, so the package ships this script at
# /usr/local/share/dig-dns/uninstall.sh. Run it as root to fully remove dig-dns:
#   sudo /usr/local/share/dig-dns/uninstall.sh
#
# Order matters — reverse the OS resolver wiring FIRST, while /usr/local/bin/dig-dns still exists
# (`unconfigure-os` removes the lo0 alias + its boot LaunchDaemon, /etc/resolver/dig, and flushes
# the DNS cache — SPEC §15), THEN bootout the service daemon and delete the payload.
set -e

if [ "$(id -u)" != "0" ]; then
    echo "dig-dns uninstall: must run as root (re-run with sudo)" >&2
    exit 1
fi

# 1) Reverse the OS-level *.dig resolver wiring (best-effort) while the binary still exists.
if [ -x /usr/local/bin/dig-dns ]; then
    /usr/local/bin/dig-dns unconfigure-os || true
fi

# 2) Stop + deregister the service LaunchDaemon.
/bin/launchctl bootout system/net.dignetwork.dig-dns 2>/dev/null || true

# 3) Remove the payload + machine-wide state.
rm -f /Library/LaunchDaemons/net.dignetwork.dig-dns.plist
rm -f /usr/local/bin/dig-dns
rm -rf "/Library/Application Support/DigDns"
rm -rf /Library/Logs/DigDns
rm -rf /usr/local/share/dig-dns

echo "dig-dns uninstalled."
exit 0
