. field25519.sh

swap() {
    local i a=$1 b=$2
    for (( i = 0; i < 10; i++ )); do
        echo "tmp = $a$i, $a$i = $b$i, $b$i = tmp,"
    done
}

copy() {
    local i a=$1 b=$2
    echo "(("
    for (( i = 0; i < 10; i++ )); do
        echo "$b$i = $a$i,"
    done
    echo "0))"
}

# RFC7748, 5. The X25519 and X448 Functions
#
# input:
# x25519_u - 32-byte array, u-coordinate
# x25519_k - 32-byte array, scalar (secret key)
#
# output:
# x25519_out - 32-byte array
eval "
x25519() {
    local -i x25519_k=(\${x25519_k[@]})
    (( x25519_k[0] &= 248 ))
    (( x25519_k[31] = x25519_k[31] & 127 | 64 ))
    $(declwide 19 t_)
    $(declwide x1_ x2_ z2_ x3_ z3_ A AA B BB E C D DA CB)
    local -i swap=0 x2_0=1 z3_0=1 k_t t tmp
    $(f25519_unpack x25519_u x1_)
    $(copy x1_ x3_)
    for (( t = 254; t >= 0; t-- )); do
        (( k_t = x25519_k[t / 8] >> (t % 8) & 1, swap ^= k_t ))
        if (( swap )); then
            ((
            $(swap x2_ x3_)
            $(swap z2_ z3_)
            0))
        fi
        (( swap = k_t ))

        $(f25519_add x2_ z2_ A)
        $(f25519_square A AA)
        $(f25519_sub x2_ z2_ B)
        $(f25519_square B BB)
        $(f25519_sub AA BB E)
        $(f25519_add x3_ z3_ C)
        $(f25519_sub x3_ z3_ D)
        $(f25519_mul D A DA)
        $(f25519_mul C B CB)
        $(f25519_add DA CB x3_)
        $(f25519_square x3_ x3_)
        $(f25519_sub DA CB z3_)
        $(f25519_square z3_ z3_)
        $(f25519_mul x1_ z3_ z3_)
        $(f25519_mul AA BB x2_)
        $(f25519_muls E 121665 z2_)
        $(f25519_add AA z2_ z2_)
        $(f25519_mul E z2_ z2_)
    done

    if (( swap )); then
        ((
        $(swap x2_ x3_)
        $(swap z2_ z3_)
        0))
    fi

    $(f25519_invert z2_ z2_)
    $(f25519_mul z2_ x2_ x2_)
    $(f25519_pack x2_ x25519_out)
}
"

if [ -n "${RUN_TESTS+x}" ]; then
    # RFC7748, 5.2. Test Vectors
    . tests.sh
    echo Testing X25519...

    declare -i x25519_k=($(fromhex a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4))
    declare -i x25519_u=($(fromhex e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c))
    time x25519
    assert_eq $(tohex "${x25519_out[@]}") c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552

    x25519_k=($(fromhex 4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d))
    x25519_u=($(fromhex e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493))
    x25519
    assert_eq $(tohex "${x25519_out[@]}") 95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957

    if [ -n "${EXPENSIVE_TESTS+x}" ]; then
        iterated_x25519() {
            x25519_k=($(fromhex 0900000000000000000000000000000000000000000000000000000000000000))
            x25519_u=(${x25519_k[@]})
            for (( i = 0; i < $1; i++ )); do
                x25519
                x25519_u=(${x25519_k[@]})
                x25519_k=(${x25519_out[@]})
            done
        }

        time iterated_x25519 1
        assert_eq $(tohex "${x25519_out[@]}") 422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079
        time iterated_x25519 1000
        assert_eq $(tohex "${x25519_out[@]}") 684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51
    fi
fi
