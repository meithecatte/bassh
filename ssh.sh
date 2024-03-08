#!/usr/bin/env bash
LC_ALL=C
LANG=C
PATH=

SSH_MSG_KEXINIT=20

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

#   Note that the length of the concatenation of 'packet_length',
#   'padding_length', 'payload', and 'random padding' MUST be a multiple
#   of the cipher block size or 8, whichever is larger.
#
#                   ~ RFC4253, 6. Binary Packet Protocol
block_size=8

encrypt_noop() {
    ciphertext+=("${plaintext[@]}")
    plaintext=()
}

decrypt_noop() {
    plaintext+=("${ciphertext[@]}")
    ciphertext=()
}

encrypt_packet=encrypt_noop
decrypt_packet=decrypt_noop

read_bytes() {
    local -i len=$1 fd=$2 i
    local s=''
    received=()

    while (( ${#received[@]} < len )); do
        if ! IFS= read -r -u $fd -d '' -n $((len - ${#received[@]})) s; then
            fatal "connection closed unexpectedly"
        fi

        for (( i=0; i < ${#s}; i++ )); do
            printf -v received[${#received[@]}] "%d" "'${s:i:1}"
        done

        # if read returned before we got to $len, we must've encountered
        # a null byte
        if (( ${#received[@]} < len )); then
            received[${#received[@]}]=0
        fi
    done
}

# uint32_from buf offset outvar
uint32_from() {
    local -n buf=$1
    local -i offset=$2
    local -n num_out=$3
    (( num_out = (buf[offset + 0] << 24) | (buf[offset + 1] << 16) \
               | (buf[offset + 2] << 8)  |  buf[offset + 3] ))
}

# uint32_from buf offsetvar outvar
string_from() {
    local -n buf=$1
    local -n offset=$2
    local -n string_out=$3
    local -i len
    uint32_from $1 $offset len
    (( offset += 4 ))
    local hexed
    printf -v hexed '\\x%02x' ${buf[@]:offset:len}
    printf -v string_out "$hexed"
    (( offset += len ))
}

receive_packet() {
    local -ai ciphertext plaintext
    local -n received=ciphertext
    read_bytes $block_size $sock
    $decrypt_packet
    local -i packet_length
    uint32_from plaintext 0 packet_length

    read_bytes $((packet_length - block_size + 4)) $sock
    $decrypt_packet
    local -i padding_length=${plaintext[4]}

    # TODO: handle MAC

    local -i len=$((packet_length - padding_length - 1))
    packet_data=(${plaintext[@]:5:len})

    info "received packet with %d-byte payload" $len
}

receive_packet
if (( packet_data[0] != SSH_MSG_KEXINIT )); then
    fatal "unexpected packet type (expected SSH_MSG_KEXINIT, got %d)" ${packet_data[0]}
fi

declare -i pos=17
string_from packet_data pos kex_algorithms
string_from packet_data pos server_host_key_algorithms
string_from packet_data pos encryption_algorithms_client_to_server
string_from packet_data pos encryption_algorithms_server_to_client
string_from packet_data pos mac_algorithms_client_to_server
string_from packet_data pos mac_algorithms_server_to_client
string_from packet_data pos compression_algorithms_client_to_server
string_from packet_data pos compression_algorithms_server_to_client
string_from packet_data pos languages_client_to_server
string_from packet_data pos languages_server_to_client
first_kex_packet_follows=${packet_data[pos]}

declare -p pos
declare -p kex_algorithms
declare -p server_host_key_algorithms
declare -p encryption_algorithms_client_to_server
declare -p encryption_algorithms_server_to_client
declare -p mac_algorithms_client_to_server
declare -p mac_algorithms_server_to_client
declare -p compression_algorithms_client_to_server
declare -p compression_algorithms_server_to_client
declare -p languages_client_to_server
declare -p languages_server_to_client
declare -p first_kex_packet_follows
