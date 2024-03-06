#!/usr/bin/env bash
LC_ALL=C
LANG=C

. log.sh

host="localhost"
port=22

if ! exec {sock}<>"/dev/tcp/$host/$port"; then
    fatal "couldn't connect to %s on port %d" "$host" "$port"
fi

printf "SSH-2.0-bassh\r\n" >&$sock

while IFS= read -r -u $sock line; do
    case "$line" in
    SSH-*)
        server_version="${line%$'\r'}"
        sanitize "$server_version"
        info "server version string: %s" "$sanitized"
        break;;
    *)
        sanitize "$line"
        info "server says: %s" "$sanitized"
    esac
done

if [ -z "${server_version+x}" ]; then
    fatal "server disconnected before sending a version string"
fi

#   Server implementations MAY support a configurable compatibility flag
#   that enables compatibility with old versions.  When this flag is on,
#   the server SHOULD identify its 'protoversion' as "1.99".  Clients
#   using protocol 2.0 MUST be able to identify this as identical to
#   "2.0".
#                   ~ RFC4253, 5.1. Old Client, New Server
case "$server_version" in
SSH-2.0-* | SSH-1.99) ;;
*) fatal "unknown protocol version (expected 2.0)" ;;
esac


