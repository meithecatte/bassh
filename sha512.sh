set -u
LC_ALL=C
LANG=C

declare -ai sha512_k=(
    0x428a2f98d728ae22 0x7137449123ef65cd 0xb5c0fbcfec4d3b2f 0xe9b5dba58189dbbc
    0x3956c25bf348b538 0x59f111f1b605d019 0x923f82a4af194f9b 0xab1c5ed5da6d8118
    0xd807aa98a3030242 0x12835b0145706fbe 0x243185be4ee4b28c 0x550c7dc3d5ffb4e2
    0x72be5d74f27b896f 0x80deb1fe3b1696b1 0x9bdc06a725c71235 0xc19bf174cf692694
    0xe49b69c19ef14ad2 0xefbe4786384f25e3 0x0fc19dc68b8cd5b5 0x240ca1cc77ac9c65
    0x2de92c6f592b0275 0x4a7484aa6ea6e483 0x5cb0a9dcbd41fbd4 0x76f988da831153b5
    0x983e5152ee66dfab 0xa831c66d2db43210 0xb00327c898fb213f 0xbf597fc7beef0ee4
    0xc6e00bf33da88fc2 0xd5a79147930aa725 0x06ca6351e003826f 0x142929670a0e6e70
    0x27b70a8546d22ffc 0x2e1b21385c26c926 0x4d2c6dfc5ac42aed 0x53380d139d95b3df
    0x650a73548baf63de 0x766a0abb3c77b2a8 0x81c2c92e47edaee6 0x92722c851482353b
    0xa2bfe8a14cf10364 0xa81a664bbc423001 0xc24b8b70d0f89791 0xc76c51a30654be30
    0xd192e819d6ef5218 0xd69906245565a910 0xf40e35855771202a 0x106aa07032bbd1b8
    0x19a4c116b8d2d0c8 0x1e376c085141ab53 0x2748774cdf8eeb99 0x34b0bcb5e19b48a8
    0x391c0cb3c5c95a63 0x4ed8aa4ae3418acb 0x5b9cca4f7763e373 0x682e6ff3d6b2b8a3
    0x748f82ee5defb2fc 0x78a5636f43172f60 0x84c87814a1f0ab72 0x8cc702081a6439ec
    0x90befffa23631e28 0xa4506cebde82bde9 0xbef9a3f7b2c67915 0xc67178f2e372532b
    0xca273eceea26619c 0xd186b8c721c0c207 0xeada7dd6cde0eb1e 0xf57d4f7fee6ed178
    0x06f067aa72176fba 0x0a637dc5a2c898a6 0x113f9804bef90dae 0x1b710b35131c471b
    0x28db77f523047d84 0x32caab7b40c72493 0x3c9ebe0a15c9bebc 0x431d67c49c100d4c
    0x4cc5d4becb3e42b6 0x597f299cfc657e2a 0x5fcb6fab3ad6faec 0x6c44198c4a475817
)

shr64() {
    echo "($1 >> $2 & $((2 ** (64 - $2) - 1)))"
}

ror64() {
    echo "($(shr64 $1 $2) | $1 << $((64 - $2)))"
}

declare -ai sha512_h
declare -ai sha512_unhashed
declare -i sha512_length

sha512_init() {
    sha512_h=(
        0x6a09e667f3bcc908 0xbb67ae8584caa73b
        0x3c6ef372fe94f82b 0xa54ff53a5f1d36f1
        0x510e527fade682d1 0x9b05688c2b3e6c1f
        0x1f83d9abfb41bd6b 0x5be0cd19137e2179
    )

    sha512_unhashed=()
    sha512_length=0
}

sha512_update() {
    local -i k
    (( sha512_length += $# ))
    while (( ${#sha512_unhashed[@]} + $# >= 128 )); do
        (( k = 128 - ${#sha512_unhashed[@]} ))
        sha512_unhashed+=(${@:1:k}); shift $k
        sha512_compress
    done
    sha512_unhashed+=($@)
}

eval "
sha512_compress() {
    local -i i s0 s1 a b c d e f g h ch t1 t2 maj
    local -ai w=()
    for i in {0..15}; do
        (( w[i] = sha512_unhashed[8*i] << 56 |
                  sha512_unhashed[8*i + 1] << 48 |
                  sha512_unhashed[8*i + 2] << 40 |
                  sha512_unhashed[8*i + 3] << 32 |
                  sha512_unhashed[8*i + 4] << 24 |
                  sha512_unhashed[8*i + 5] << 16 |
                  sha512_unhashed[8*i + 6] << 8 |
                  sha512_unhashed[8*i + 7] ))
    done
    for i in {16..79}; do
        ((
            s0 = $(ror64 w[i-15] 1) ^ $(ror64 w[i-15] 8) ^ $(shr64 w[i-15] 7),
            s1 = $(ror64 w[i-2] 19) ^ $(ror64 w[i-2] 61) ^ $(shr64 w[i-2] 6),
            w[i] = (w[i-16] + s0 + w[i-7] + s1)
        ))
    done
    (( a = sha512_h[0], b = sha512_h[1], c = sha512_h[2], d = sha512_h[3],
       e = sha512_h[4], f = sha512_h[5], g = sha512_h[6], h = sha512_h[7] ))
    for i in {0..79}; do
        ((
            s1 = $(ror64 e 14) ^ $(ror64 e 18) ^ $(ror64 e 41),
            ch = (e & f) ^ (~e & g),
            t1 = h + s1 + ch + sha512_k[i] + w[i],
            s0 = $(ror64 a 28) ^ $(ror64 a 34) ^ $(ror64 a 39),
            maj = (a & b) ^ (a & c) ^ (b & c),
            t2 = s0 + maj,

            h = g,
            g = f,
            f = e,
            e = (d + t1),
            d = c,
            c = b,
            b = a,
            a = (t1 + t2)
        ))

        #printf 't=%2d: %016x %016x %016x %016x\n' \$i \$a \$b \$c \$d
        #printf '      %016x %016x %016x %016x\n' \$e \$f \$g \$h
    done

    ((
        sha512_h[0] += a,
        sha512_h[1] += b,
        sha512_h[2] += c,
        sha512_h[3] += d,
        sha512_h[4] += e,
        sha512_h[5] += f,
        sha512_h[6] += g,
        sha512_h[7] += h
    ))

    sha512_unhashed=()
}
"

sha512_finish() {
    local -i L=sha512_length K i pad
    (( K = 128 - (L + 16) % 128 + 8 ))
    (( L *= 8 ))
    local -ai padding=(0x80)
    for (( i = 1; i < K; i++ )); do
        padding+=(0)
    done
    for (( i = 7; i >= 0; i-- )); do
        (( pad = (L >> 8 * i) & 0xff ))
        padding+=(pad)
    done
    sha512_update "${padding[@]}"

    sha512_out=()
    for i in {0..7}; do
        ((
            sha512_out[8*i] = (sha512_h[i] >> 56) & 0xff,
            sha512_out[8*i + 1] = (sha512_h[i] >> 48) & 0xff,
            sha512_out[8*i + 2] = (sha512_h[i] >> 40) & 0xff,
            sha512_out[8*i + 3] = (sha512_h[i] >> 32) & 0xff,
            sha512_out[8*i + 4] = (sha512_h[i] >> 24) & 0xff,
            sha512_out[8*i + 5] = (sha512_h[i] >> 16) & 0xff,
            sha512_out[8*i + 6] = (sha512_h[i] >> 8) & 0xff,
            sha512_out[8*i + 7] = sha512_h[i] & 0xff
        ))
    done
}

sha512_string() {
    local input="$1"
    local -ai bytes=()
    local -i i
    for (( i = 0; i < ${#input}; i++ )); do
        printf -v bytes[i] '%d' "'${input:i:1}"
    done

    sha512_init
    sha512_update "${bytes[@]}"
    sha512_finish
}

if [ -n "${RUN_TESTS+x}" ]; then
    . tests.sh
    echo Testing SHA-512...

    sha512_test() {
        sha512_string "$1"
        expected="$(echo -n "$1" | sha512sum - | awk '{print $1}')"
        assert_eq "$(tohex "${sha512_out[@]}")" "$expected"
    }

    sha512_test ""
    sha512_test "abc"
    sha512_test "abcdefgh"
    sha512_test "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    sha512_test "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    sha512_test "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

    # small chunks
    declare -ai data=()
    for _ in {1..10}; do
        data+=(0x61)
    done
    sha512_init
    for _ in {1..1000}; do
        sha512_update "${data[@]}"
    done
    sha512_finish
    assert_eq $(tohex "${sha512_out[@]}") 0593036f4f479d2eb8078ca26b1d59321a86bdfcb04cb40043694f1eb0301b8acd20b936db3c916ebcc1b609400ffcf3fa8d569d7e39293855668645094baf0e

    # big chungus
    declare -ai data=()
    for _ in {1..1000}; do
        data+=(0x61)
    done
    sha512_init
    for _ in {1..10}; do
        sha512_update "${data[@]}"
    done
    sha512_finish
    assert_eq $(tohex "${sha512_out[@]}") 0593036f4f479d2eb8078ca26b1d59321a86bdfcb04cb40043694f1eb0301b8acd20b936db3c916ebcc1b609400ffcf3fa8d569d7e39293855668645094baf0e
fi
