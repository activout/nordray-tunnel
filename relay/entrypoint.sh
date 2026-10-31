#!/bin/sh
# Refuse to start without a strong tunnel token: frps would otherwise accept
# any agent presenting an empty token. Values are only checked here, never
# interpolated into configuration (frps renders them itself).
set -eu
token="${NORDRAY_TUNNEL_TOKEN:-}"
if [ "${#token}" -lt 32 ]; then
	echo "NORDRAY_TUNNEL_TOKEN must be set to at least 32 characters" >&2
	exit 64
fi
exec /usr/bin/frps -c /etc/frp/frps.toml
