#!/bin/sh
# Validates the environment, writes optional TLS material to files and execs
# frps. Values are never interpolated into configuration: frps renders them.
set -eu
token="${NORDRAY_TUNNEL_TOKEN:-}"
if [ "${#token}" -lt 32 ]; then
	echo "NORDRAY_TUNNEL_TOKEN must be set to at least 32 characters" >&2
	exit 64
fi

# Optional certificate for direct (Anycast) agents, passed as PEM text.
cert="${NORDRAY_TLS_CERT:-}"
key="${NORDRAY_TLS_KEY:-}"
if [ -n "$cert" ] || [ -n "$key" ]; then
	if [ -z "$cert" ] || [ -z "$key" ]; then
		echo "NORDRAY_TLS_CERT and NORDRAY_TLS_KEY must be set together" >&2
		exit 64
	fi
	umask 077
	dir="$(mktemp -d)"
	printf '%s\n' "$cert" >"$dir/tls.crt"
	printf '%s\n' "$key" >"$dir/tls.key"
	export NORDRAY_TLS_CERT_FILE="$dir/tls.crt" NORDRAY_TLS_KEY_FILE="$dir/tls.key"
fi
unset NORDRAY_TLS_KEY

case "${NORDRAY_TLS_FORCE:-false}" in
true)
	if [ -z "${NORDRAY_TLS_CERT_FILE:-}" ]; then
		echo "NORDRAY_TLS_FORCE=true requires NORDRAY_TLS_CERT and NORDRAY_TLS_KEY" >&2
		exit 64
	fi
	;;
false) ;;
*)
	echo "NORDRAY_TLS_FORCE must be true or false" >&2
	exit 64
	;;
esac
export NORDRAY_TLS_FORCE="${NORDRAY_TLS_FORCE:-false}"

exec /usr/bin/frps -c /etc/frp/frps.toml
