#!/usr/bin/env bash
set -u
LC_ALL=C
LANG=C
PATH=

# == Protocol constants ==
SSH_MSG_DEBUG=4
SSH_MSG_KEXINIT=20

. log.sh

# == Configuration (TODO: argument parsing) ==
host="localhost"
port=22

if ! exec {urandom}<>/dev/urandom; then
    fatal "couldn't open /dev/urandom"
fi

# == RFC4253, 4. Connection Setup
if ! exec {sock}<>"/dev/tcp/$host/$port"; then
    fatal "couldn't connect to %s on port %d" "$host" "$port"
fi

# == RFC4253, 4.2. Protocol Version Exchange
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

# == RFC4253, 6. Binary Packet Protocol

#   Note that the length of the concatenation of 'packet_length',
#   'padding_length', 'payload', and 'random padding' MUST be a multiple
#   of the cipher block size or 8, whichever is larger.
#
#                   ~ RFC4253, 6. Binary Packet Protocol
encrypt_block_size=8
decrypt_block_size=8

# the encrypt/decrypt hooks will always be called with a multiple of
# block_size bytes
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

# uint32_to buf value
uint32_to() {
    local -n buf=$1
    local -i value=$2
    buf+=($((value >> 24 & 0xff)))
    buf+=($((value >> 16 & 0xff)))
    buf+=($((value >> 8 & 0xff)))
    buf+=($((value & 0xff)))
}

# string_from buf offsetvar outvar
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

# string_to buf value
string_to() {
    local -n buf=$1
    local value="$2"
    local -i byte
    uint32_to $1 ${#value}
    for (( i = 0; i < ${#value}; i++ )); do
        printf -v byte '%d' "'${value:i:1}"
        buf+=($byte)
    done
}

# namelist_from buf offsetvar outvar
namelist_from() {
    local str
    string_from "$1" "$2" str
    local -n namelist_out="$3"
    local IFS=,
    namelist_out=($str)
}

# namelist_to buf arr
namelist_to() {
    local -n arr=$2
    local str
    printf -v str "%s," "${arr[@]}"
    string_to $1 "${str%,}"
}

receive_packet() {
    local -ai ciphertext plaintext
    local -n received=ciphertext
    read_bytes $decrypt_block_size $sock
    $decrypt_packet
    local -i packet_length
    uint32_from plaintext 0 packet_length

    read_bytes $((packet_length - decrypt_block_size + 4)) $sock
    $decrypt_packet
    local -i padding_length=${plaintext[4]}

    # TODO: handle MAC

    local -i len=$((packet_length - padding_length - 1))
    packet_data=(${plaintext[@]:5:len})

    local -a padding=(${plaintext[@]:5+len:padding_length})
    declare -p padding

    info "received packet with %d-byte payload" $len
}

send_packet() {
    local -ai ciphertext=() plaintext=()
    local -i len padding_length i
    #   Arbitrary-length padding, such that the total length of
    #   (packet_length || padding_length || payload || random padding)
    #   is a multiple of the cipher block size or 8, whichever is
    #   larger.  There MUST be at least four bytes of padding.  The
    #
    #               ~ RFC4253, 6. Binary Packet Protocol
    # 
    # We calculate the amount of padding as block_size - len % block_size,
    # which will range from 1 to block_size. Therefore we add 3 bytes
    # outside of that, to always reach the minimum of 4 bytes.

    # 4 bytes for packet_length
    # 1 byte for padding_length
    # 3 additional padding bytes
    # ====
    # 8 bytes total
    (( len = ${#packet_data[@]} + 8 ))
    (( padding_length = encrypt_block_size - len % encrypt_block_size + 3 ))

    uint32_to plaintext $((1 + ${#packet_data[@]} + padding_length))
    plaintext+=(padding_length)
    plaintext+=(${packet_data[@]})
    for (( i = 0; i < padding_length; i++ )); do
        plaintext+=(0)
    done

    $encrypt_packet

    # TODO: handle MAC

    local hexed
    printf -v hexed '\\x%02x' "${ciphertext[@]}"
    printf "$hexed" >&$sock
}

# == RFC4253, 11.3. Debug Message
send_debug_message() {
    local -ai packet_data=()
    packet_data[0]=SSH_MSG_DEBUG
    packet_data[1]=1 # always_display
    string_to packet_data "$1"
    string_to packet_data "en"
}

# == RFC4253, 7.1. Algorithm Negotiation
declare -a supported_kex supported_host_key supported_encryption supported_mac
supported_kex+=("curve25519-sha256" "curve25519-sha256@libssh.org")
supported_host_key+=("ssh-ed25519")
supported_encryption+=("aes128-ctr" "aes192-ctr" "aes256-ctr")
supported_mac+=("hmac-sha2-256")

parse_kexinit() {
    if (( packet_data[0] != SSH_MSG_KEXINIT )); then
        fatal "unexpected packet type (expected SSH_MSG_KEXINIT, got %d)" ${packet_data[0]}
    fi

    # 16 byte cookie goes here
    declare -i pos=17
    namelist_from packet_data pos kex_algorithms
    namelist_from packet_data pos server_host_key_algorithms
    namelist_from packet_data pos encryption_algorithms_client_to_server
    namelist_from packet_data pos encryption_algorithms_server_to_client
    namelist_from packet_data pos mac_algorithms_client_to_server
    namelist_from packet_data pos mac_algorithms_server_to_client
    namelist_from packet_data pos compression_algorithms_client_to_server
    namelist_from packet_data pos compression_algorithms_server_to_client
    namelist_from packet_data pos languages_client_to_server
    namelist_from packet_data pos languages_server_to_client
    first_kex_packet_follows=${packet_data[pos]}
    # 4 reserved bytes go here

    if (( pos + 5 != ${#packet_data[@]} )); then
        fatal "malformed SSH_MSG_KEXINIT (excess bytes)"
    fi
}

send_kexinit() {
    local -ai cookie=()
    local -n received=cookie
    read_bytes 16 $urandom

    local -ai packet_data=()
    packet_data[0]=SSH_MSG_KEXINIT
    packet_data+=("${cookie[@]}")
    namelist_to packet_data supported_kex
    namelist_to packet_data supported_host_key
    namelist_to packet_data supported_encryption # client to server
    namelist_to packet_data supported_encryption # server to client
    namelist_to packet_data supported_mac # client to server
    namelist_to packet_data supported_mac # server to client

    local compression=("none")
    namelist_to packet_data compression # client to server
    namelist_to packet_data compression # server to client

    local languages=()
    namelist_to packet_data languages # client to server
    namelist_to packet_data languages # server to client

    # first_kex_packet_follows
    packet_data+=(0)

    # reserved
    packet_data+=(0 0 0 0)
    send_packet
}

# choose_common client_arr server_arr out
choose_common() {
    local -n client_knows=$1 server_knows=$2 out=$3
    local -A server_known
    for server_alg in "${server_knows[@]}"; do
        server_known["$server_alg"]=yes
    done

    for client_alg in "${client_knows[@]}"; do
        if [ -n "${server_known["$client_alg"]+x}" ]; then
            out="$client_alg"
            info "%s = %s" "$3" "$client_alg"
            return
        fi
    done

    error "couldn't find common %s" $3
    sanitize "${server_knows[*]}"
    info "server supports: %s" $sanitized
    info "we support: %s" ${client_knows[*]}
    fatal "negotiation failed"
}

# array_contains arr value
array_contains() {
    local -n arr=$1
    local a
    for a in "${arr[@]}"; do
        if [ "$a" == "$2" ]; then
            return 0
        fi
    done

    return 1
}

send_kexinit
receive_packet
parse_kexinit

# NOTE: The RFC says the following about key exchange negotiation:
#
#   The following algorithm MUST be used to choose a key
#   exchange method: Iterate over client's kex algorithms, one at a
#   time.  Choose the first algorithm that satisfies the following
#   conditions:
#
#   +  the server also supports the algorithm,
#
#   +  if the algorithm requires an encryption-capable host key,
#      there is an encryption-capable algorithm on the server's
#      server_host_key_algorithms that is also supported by the
#      client, and
#
#   +  if the algorithm requires a signature-capable host key,
#      there is a signature-capable algorithm on the server's
#      server_host_key_algorithms that is also supported by the
#      client.
#
#                   ~ RFC4253, 7.1. Algorithm Negotiation
#
# We do this by simply implementing only kex algorithms that require
# a signature-capable host key, and only signature-capable host key
# algorithms.

choose_common supported_kex kex_algorithms kex_algorithm
choose_common supported_host_key server_host_key_algorithms host_key_algorithm
choose_common supported_encryption encryption_algorithms_client_to_server encrypt_algorithm
choose_common supported_encryption encryption_algorithms_server_to_client decrypt_algorithm
choose_common supported_mac mac_algorithms_client_to_server send_mac_algorithm
choose_common supported_mac mac_algorithms_server_to_client recv_mac_algorithm

if ! array_contains compression_algorithms_client_to_server none || \
   ! array_contains compression_algorithms_server_to_client none
then
    fatal "server insists on compression, which we do not support"
fi
