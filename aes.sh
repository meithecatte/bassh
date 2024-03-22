declare -ai aes_sbox=(
    0x63 0x7c 0x77 0x7b 0xf2 0x6b 0x6f 0xc5
    0x30 0x01 0x67 0x2b 0xfe 0xd7 0xab 0x76
    0xca 0x82 0xc9 0x7d 0xfa 0x59 0x47 0xf0
    0xad 0xd4 0xa2 0xaf 0x9c 0xa4 0x72 0xc0
    0xb7 0xfd 0x93 0x26 0x36 0x3f 0xf7 0xcc
    0x34 0xa5 0xe5 0xf1 0x71 0xd8 0x31 0x15
    0x04 0xc7 0x23 0xc3 0x18 0x96 0x05 0x9a
    0x07 0x12 0x80 0xe2 0xeb 0x27 0xb2 0x75
    0x09 0x83 0x2c 0x1a 0x1b 0x6e 0x5a 0xa0
    0x52 0x3b 0xd6 0xb3 0x29 0xe3 0x2f 0x84
    0x53 0xd1 0x00 0xed 0x20 0xfc 0xb1 0x5b
    0x6a 0xcb 0xbe 0x39 0x4a 0x4c 0x58 0xcf
    0xd0 0xef 0xaa 0xfb 0x43 0x4d 0x33 0x85
    0x45 0xf9 0x02 0x7f 0x50 0x3c 0x9f 0xa8
    0x51 0xa3 0x40 0x8f 0x92 0x9d 0x38 0xf5
    0xbc 0xb6 0xda 0x21 0x10 0xff 0xf3 0xd2
    0xcd 0x0c 0x13 0xec 0x5f 0x97 0x44 0x17
    0xc4 0xa7 0x7e 0x3d 0x64 0x5d 0x19 0x73
    0x60 0x81 0x4f 0xdc 0x22 0x2a 0x90 0x88
    0x46 0xee 0xb8 0x14 0xde 0x5e 0x0b 0xdb
    0xe0 0x32 0x3a 0x0a 0x49 0x06 0x24 0x5c
    0xc2 0xd3 0xac 0x62 0x91 0x95 0xe4 0x79
    0xe7 0xc8 0x37 0x6d 0x8d 0xd5 0x4e 0xa9
    0x6c 0x56 0xf4 0xea 0x65 0x7a 0xae 0x08
    0xba 0x78 0x25 0x2e 0x1c 0xa6 0xb4 0xc6
    0xe8 0xdd 0x74 0x1f 0x4b 0xbd 0x8b 0x8a
    0x70 0x3e 0xb5 0x66 0x48 0x03 0xf6 0x0e
    0x61 0x35 0x57 0xb9 0x86 0xc1 0x1d 0x9e
    0xe1 0xf8 0x98 0x11 0x69 0xd9 0x8e 0x94
    0x9b 0x1e 0x87 0xe9 0xce 0x55 0x28 0xdf
    0x8c 0xa1 0x89 0x0d 0xbf 0xe6 0x42 0x68
    0x41 0x99 0x2d 0x0f 0xb0 0x54 0xbb 0x16 
)

# input:
# aes_key - array of 16, 24, or 32 bytes
#
# output:
# aes_rounds, aes_keysched
aes_expand_key() {
    local -i N=${#aes_key[@]}
    case $N in
    16) aes_rounds=11;;
    24) aes_rounds=13;;
    32) aes_rounds=15;;
    *)
        echo "error: unknown AES key size $N" >&2
        exit 1;;
    esac

    local -i rcon=1
    while (( ${#aes_key[@]} < 16*aes_rounds )); do
        local -i i=${#aes_key[@]}
        if (( i % N == 0 )); then
            (( aes_key[i]   = aes_key[i-N]   ^ aes_sbox[aes_key[i-3]] ^ rcon ))
            (( aes_key[i+1] = aes_key[i-N+1] ^ aes_sbox[aes_key[i-2]] ))
            (( aes_key[i+2] = aes_key[i-N+2] ^ aes_sbox[aes_key[i-1]] ))
            (( aes_key[i+3] = aes_key[i-N+3] ^ aes_sbox[aes_key[i-4]] ))
            (( rcon = ((rcon >> 7) * 0x1b) ^ (rcon << 1) & 0xff ))
        elif (( N == 32 && i % N == 16 )); then
            (( aes_key[i]   = aes_key[i-N]   ^ aes_sbox[aes_key[i-4]] ))
            (( aes_key[i+1] = aes_key[i-N+1] ^ aes_sbox[aes_key[i-3]] ))
            (( aes_key[i+2] = aes_key[i-N+2] ^ aes_sbox[aes_key[i-2]] ))
            (( aes_key[i+3] = aes_key[i-N+3] ^ aes_sbox[aes_key[i-1]] ))
        else
            (( aes_key[i]   = aes_key[i-N]   ^ aes_key[i-4] ))
            (( aes_key[i+1] = aes_key[i-N+1] ^ aes_key[i-3] ))
            (( aes_key[i+2] = aes_key[i-N+2] ^ aes_key[i-2] ))
            (( aes_key[i+3] = aes_key[i-N+3] ^ aes_key[i-1] ))
        fi
    done

    for (( i=0; i < 16*aes_rounds; i += 16 )); do
        (( aes_keysched[i/4] = $(aes_row "aes_key[i]" "aes_key[i + 4]" "aes_key[i + 8]" "aes_key[i + 12]") ))
        (( aes_keysched[i/4 + 1] = $(aes_row "aes_key[i + 1]" "aes_key[i + 5]" "aes_key[i + 9]" "aes_key[i + 13]") ))
        (( aes_keysched[i/4 + 2] = $(aes_row "aes_key[i + 2]" "aes_key[i + 6]" "aes_key[i + 10]" "aes_key[i + 14]") ))
        (( aes_keysched[i/4 + 3] = $(aes_row "aes_key[i + 3]" "aes_key[i + 7]" "aes_key[i + 11]" "aes_key[i + 15]") ))
    done
}

aes_row() {
    echo "$1 | $2 << 8 | $3 << 16 | $4 << 24"
}

aes_get() {
    echo "(row$(($1 % 4)) >> $(($1 / 4 * 8)) & 0xff)"
}

aes_sub() {
    echo "aes_sbox[$(aes_get $1)]"
}

aes_subbed() {
    aes_row "$(aes_sub $1)" "$(aes_sub $2)" "$(aes_sub $3)" "$(aes_sub $4)"
}

aes_sub_shift() {
    echo "row0 = $(aes_subbed  0  4  8 12),"
    echo "row1 = $(aes_subbed  5  9 13  1),"
    echo "row2 = $(aes_subbed 10 14  2  6),"
    echo "row3 = $(aes_subbed 15  3  7 11),"
}

aes_mix_columns_add_key() {
    local -i r
    for (( r=0; r < 4; r++ )); do
        # This strategy is inspired by the Wikipedia article
        # "Rijndael MixColumns"
        #
        # a contains the input coefficients
        # b contains each coefficient multiplied by x (in GF(2**8), that is)

        # NOTE: multiplication just selects between 0x00 and 0x1b here
        echo "a$r=row$r,"
        echo "h = (a$r & 0x80808080) >> 7,"
        echo "b$r = h ^ h << 1 ^ h << 3 ^ h << 4 ^ (a$r & 0x7f7f7f7f) << 1,"
    done

    echo "row0 = b0 ^ b1 ^ a1 ^ a2 ^ a3 ^ aes_keysched[4*i],"
    echo "row1 = a0 ^ b1 ^ b2 ^ a2 ^ a3 ^ aes_keysched[4*i + 1],"
    echo "row2 = a0 ^ a1 ^ b2 ^ b3 ^ a3 ^ aes_keysched[4*i + 2],"
    echo "row3 = b0 ^ a0 ^ a1 ^ a2 ^ b3 ^ aes_keysched[4*i + 3],"
}

aes_add_round_key() {
    local -i k
    for (( k=0; k < 4; k++ )); do
        echo "row$k ^= aes_keysched[4*i + $k],"
    done
}

aes_pack() {
    local -i r
    for r in {0..3}; do
        echo "row$r = $(aes_row "aes_block[$r]" "aes_block[$((r+4))]" "aes_block[$((r+8))]" "aes_block[$((r+12))]"),"
    done
}

aes_unpack() {
    local -i k
    for k in {0..15}; do
        echo "aes_block[$k] = row$((k % 4)) >> $((k / 4 * 8)) & 0xff,"
    done
}

# Like it or not, this is what performant bash code looks like :3
eval "
aes_encrypt_block() {
    local -i i=0
    local -i a0 a1 a2 a3 b0 b1 b2 b3 row0 row1 row2 row3 h
    ((
    $(aes_pack)
    $(aes_add_round_key)
    0))
    for (( i=1; i < aes_rounds-1; i++ )); do
        ((
        $(aes_sub_shift)
        $(aes_mix_columns_add_key)
        0))
    done
    ((
    $(aes_sub_shift)
    $(aes_add_round_key)
    $(aes_unpack)
    0))
}
"

benchmark() {
    local -i i
    for i in {1..1000}; do
        aes_encrypt_block
    done
}

if [ -n "${RUN_TESTS+x}" ]; then
    # Test vectors from NIST FIPS 197, Appendix C
    . tests.sh
    echo Testing AES...

    declare -i aes_keysched

    echo "AES-128 (x1000)"
    declare -i aes_key=($(fromhex 000102030405060708090a0b0c0d0e0f))
    aes_expand_key
    assert_eq $aes_rounds 11
    assert_eq $(tohex "${aes_key[@]}") 000102030405060708090a0b0c0d0e0fd6aa74fdd2af72fadaa678f1d6ab76feb692cf0b643dbdf1be9bc5006830b3feb6ff744ed2c2c9bf6c590cbf0469bf4147f7f7bc95353e03f96c32bcfd058dfd3caaa3e8a99f9deb50f3af57adf622aa5e390f7df7a69296a7553dc10aa31f6b14f9701ae35fe28c440adf4d4ea9c02647438735a41c65b9e016baf4aebf7ad2549932d1f08557681093ed9cbe2c974e13111d7fe3944a17f307a78b4d2b30c5
    declare -i aes_block=($(fromhex 00112233445566778899aabbccddeeff))
    aes_encrypt_block
    assert_eq $(tohex "${aes_block[@]}") 69c4e0d86a7b0430d8cdb78070b4c55a
    time benchmark

    echo "AES-192 (x1000)"
    declare -i aes_key=($(fromhex 000102030405060708090a0b0c0d0e0f1011121314151617))
    aes_expand_key
    declare -i aes_block=($(fromhex 00112233445566778899aabbccddeeff))
    aes_encrypt_block
    assert_eq $(tohex "${aes_block[@]}") dda97ca4864cdfe06eaf70a0ec0d7191
    time benchmark

    echo "AES-256 (x1000)"
    declare -i aes_key=($(fromhex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f))
    aes_expand_key
    declare -i aes_block=($(fromhex 00112233445566778899aabbccddeeff))
    aes_encrypt_block
    assert_eq $(tohex "${aes_block[@]}") 8ea2b7ca516745bfeafc49904b496089
    time benchmark
fi
