set -u
LC_ALL=C
LANG=C

declare -ai sha256_k=(
   0x428a2f98 0x71374491 0xb5c0fbcf 0xe9b5dba5
   0x3956c25b 0x59f111f1 0x923f82a4 0xab1c5ed5
   0xd807aa98 0x12835b01 0x243185be 0x550c7dc3
   0x72be5d74 0x80deb1fe 0x9bdc06a7 0xc19bf174
   0xe49b69c1 0xefbe4786 0x0fc19dc6 0x240ca1cc
   0x2de92c6f 0x4a7484aa 0x5cb0a9dc 0x76f988da
   0x983e5152 0xa831c66d 0xb00327c8 0xbf597fc7
   0xc6e00bf3 0xd5a79147 0x06ca6351 0x14292967
   0x27b70a85 0x2e1b2138 0x4d2c6dfc 0x53380d13
   0x650a7354 0x766a0abb 0x81c2c92e 0x92722c85
   0xa2bfe8a1 0xa81a664b 0xc24b8b70 0xc76c51a3
   0xd192e819 0xd6990624 0xf40e3585 0x106aa070
   0x19a4c116 0x1e376c08 0x2748774c 0x34b0bcb5
   0x391c0cb3 0x4ed8aa4a 0x5b9cca4f 0x682e6ff3
   0x748f82ee 0x78a5636f 0x84c87814 0x8cc70208
   0x90befffa 0xa4506ceb 0xbef9a3f7 0xc67178f2
)

ror32() {
    echo "($1 >> $2 | $1 << $((32 - $2)) & $((2**32 - 1)))"
}

declare -ai sha256_h
declare -ai sha256_unhashed
declare -i sha256_length

sha256_init() {
    sha256_h=(
        0x6a09e667 0xbb67ae85 0x3c6ef372 0xa54ff53a
        0x510e527f 0x9b05688c 0x1f83d9ab 0x5be0cd19
    )

    sha256_unhashed=()
    sha256_length=0
}

sha256_update() {
    local -i k
    (( sha256_length += $# ))
    while (( ${#sha256_unhashed[@]} + $# >= 64 )); do
        (( k = 64 - ${#sha256_unhashed[@]} ))
        sha256_unhashed+=(${@:1:k}); shift $k
        sha256_compress
    done
    sha256_unhashed+=($@)
}

eval "
sha256_compress() {
    local -i i s0 s1 a b c d e f g h ch t1 t2 maj
    local -ai w=()
    for i in {0..15}; do
        (( w[i] = sha256_unhashed[4*i] << 24 |
                  sha256_unhashed[4*i + 1] << 16 |
                  sha256_unhashed[4*i + 2] << 8 |
                  sha256_unhashed[4*i + 3] ))
    done
    for i in {16..63}; do
        ((
            s0 = $(ror32 w[i-15] 7) ^ $(ror32 w[i-15] 18) ^ (w[i-15] >> 3),
            s1 = $(ror32 w[i-2] 17) ^ $(ror32 w[i-2] 19) ^ (w[i-2] >> 10),
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & $((2**32 - 1))
        ))
    done
    (( a = sha256_h[0], b = sha256_h[1], c = sha256_h[2], d = sha256_h[3],
       e = sha256_h[4], f = sha256_h[5], g = sha256_h[6], h = sha256_h[7] ))
    for i in {0..63}; do
        ((
            s1 = $(ror32 e 6) ^ $(ror32 e 11) ^ $(ror32 e 25),
            ch = (e & f) ^ (~e & g),
            t1 = h + s1 + ch + sha256_k[i] + w[i],
            s0 = $(ror32 a 2) ^ $(ror32 a 13) ^ $(ror32 a 22),
            maj = (a & b) ^ (a & c) ^ (b & c),
            t2 = s0 + maj,

            h = g,
            g = f,
            f = e,
            e = (d + t1) & $((2**32 - 1)),
            d = c,
            c = b,
            b = a,
            a = (t1 + t2) & $((2**32 - 1))
        ))
    done

    ((
        sha256_h[0] += a, sha256_h[0] &= $((2**32 - 1)),
        sha256_h[1] += b, sha256_h[1] &= $((2**32 - 1)),
        sha256_h[2] += c, sha256_h[2] &= $((2**32 - 1)),
        sha256_h[3] += d, sha256_h[3] &= $((2**32 - 1)),
        sha256_h[4] += e, sha256_h[4] &= $((2**32 - 1)),
        sha256_h[5] += f, sha256_h[5] &= $((2**32 - 1)),
        sha256_h[6] += g, sha256_h[6] &= $((2**32 - 1)),
        sha256_h[7] += h, sha256_h[7] &= $((2**32 - 1))
    ))

    sha256_unhashed=()
}
"

sha256_finish() {
    local -i L=sha256_length K i pad
    (( K = 64 - (L + 8) % 64 ))
    (( L *= 8 ))
    local -ai padding=(0x80)
    for (( i = 1; i < K; i++ )); do
        padding+=(0)
    done
    for (( i = 7; i >= 0; i-- )); do
        (( pad = (L >> 8 * i) & 0xff ))
        padding+=(pad)
    done
    sha256_update "${padding[@]}"

    sha256_out=()
    for i in {0..7}; do
        ((
            sha256_out[4*i] = (sha256_h[i] >> 24) & 0xff,
            sha256_out[4*i + 1] = (sha256_h[i] >> 16) & 0xff,
            sha256_out[4*i + 2] = (sha256_h[i] >> 8) & 0xff,
            sha256_out[4*i + 3] = sha256_h[i] & 0xff
        ))
    done
}

sha256_string() {
    local input="$1"
    local -ai bytes=()
    local -i i
    for (( i = 0; i < ${#input}; i++ )); do
        printf -v bytes[i] '%d' "'${input:i:1}"
    done

    sha256_init
    sha256_update "${bytes[@]}"
    sha256_finish
}

if [ -n "${RUN_TESTS+x}" ]; then
    . tests.sh
    echo Testing SHA-256...

    sha256_test() {
        sha256_string "$1"
        expected="$(echo -n "$1" | sha256sum - | awk '{print $1}')"
        assert_eq "$(tohex "${sha256_out[@]}")" "$expected"
    }

    sha256_test ""
    sha256_test "abc"
    sha256_test "abcdefgh"
    sha256_test "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    sha256_test "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    sha256_test "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

    # small chunks
    declare -ai data=()
    for _ in {1..10}; do
        data+=(0x61)
    done
    sha256_init
    for _ in {1..1000}; do
        sha256_update "${data[@]}"
    done
    sha256_finish
    assert_eq $(tohex "${sha256_out[@]}") 27dd1f61b867b6a0f6e9d8a41c43231de52107e53ae424de8f847b821db4b711

    # big chungus
    declare -ai data=()
    for _ in {1..1000}; do
        data+=(0x61)
    done
    sha256_init
    for _ in {1..10}; do
        sha256_update "${data[@]}"
    done
    sha256_finish
    assert_eq $(tohex "${sha256_out[@]}") 27dd1f61b867b6a0f6e9d8a41c43231de52107e53ae424de8f847b821db4b711
fi
