aes_sbox=(
    99 124 119 123 242 107 111 197 48 1 103 43 254 215 171 118
    202 130 201 125 250 89 71 240 173 212 162 175 156 164 114 192
    183 253 147 38 54 63 247 204 52 165 229 241 113 216 49 21
    4 199 35 195 24 150 5 154 7 18 128 226 235 39 178 117
    9 131 44 26 27 110 90 160 82 59 214 179 41 227 47 132
    83 209 0 237 32 252 177 91 106 203 190 57 74 76 88 207
    208 239 170 251 67 77 51 133 69 249 2 127 80 60 159 168
    81 163 64 143 146 157 56 245 188 182 218 33 16 255 243 210
    205 12 19 236 95 151 68 23 196 167 126 61 100 93 25 115
    96 129 79 220 34 42 144 136 70 238 184 20 222 94 11 219
    224 50 58 10 73 6 36 92 194 211 172 98 145 149 228 121
    231 200 55 109 141 213 78 169 108 86 244 234 101 122 174 8
    186 120 37 46 28 166 180 198 232 221 116 31 75 189 139 138
    112 62 181 102 72 3 246 14 97 53 87 185 134 193 29 158
    225 248 152 17 105 217 142 148 155 30 135 233 206 85 40 223
    140 161 137 13 191 230 66 104 65 153 45 15 176 84 187 22
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
