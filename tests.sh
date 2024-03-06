fromhex() {
    local input="$1"
    local -i i
    for (( i=0; i < ${#input}; i+=2 )); do
        echo -n "$((0x${input:i:2})) "
    done
}

tohex() {
    for c in "$@"; do
        printf "%02x" $c
    done
}

assert_eq() {
    if [ "$1" != "$2" ]; then
        echo "assertion error:" >&2
        echo " left: $1" >&2
        echo "right: $2" >&2
        exit 1
    fi
}
