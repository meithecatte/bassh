# Like djb's library, we use 10 limbs of 25.5 bits for a field element.
# This means that
#
# - all the even-numbered limbs, including the least-significant one,
#   are 26 bits, and
# - all the odd-numbered limbs are 25 bits.
#
# In its reduced representation, each limb is an integer between
# -2**25 and 2**25. While multiplication returns its output in a reduced
# form, it can handle inputs where each limb ranges between -2**26 and 2**26.

declwide() {
    local i k v
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        k=$1
        shift
    else
        k=10
    fi

    for v in "$@"; do
        for (( i = 0; i < k; i++ )); do
            echo "local -i $v$i=0"
        done
    done
}

f25519_carry_at() {
    local a=$1 k=$2
    local -i bits bias
    (( bits = k % 2 ? 25 : 26 ))
    (( bias = 1 << (bits - 1) ))
    echo "$a$((k + 1)) += ($a$k + $bias) >> $bits,"
    echo "$a$k = (($a$k + $bias) & $(((1 << bits) - 1))) - $bias,"
}

f25519_carry_wrap() {
    local a=$1 k=9
    local -i bits bias
    (( bits = k % 2 ? 25 : 26 ))
    (( bias = 1 << (bits - 1) ))
    echo "${a}0 += 19 * (($a$k + $bias) >> $bits),"
    echo "$a$k = (($a$k + $bias) & $(((1 << bits) - 1))) - $bias,"
}

f25519_reduce_at() {
    local a=$1 to=$2
    local from=$((to + 10))
    echo "$a$to += $a$from * 19,"
}

f25519_add() {
    local a=$1 b=$2 out=$3 i
    echo "(("
    for i in {0..9}; do
        echo "$out$i = $a$i + $b$i,"
    done
    echo "0))"
}

f25519_sub() {
    local a=$1 b=$2 out=$3 i
    echo "(("
    for i in {0..9}; do
        echo "$out$i = $a$i - $b$i,"
    done
    echo "0))"
}

# NOTE: apart from making sure that all outputs are within [-2**25; 2**25],
# mul also ensures that out9 is within [-2**24; 2**24 + 2**16].
f25519_mul() {
    local a=$1 b=$2 out=$3 tmp=_t
    local i j
    local -a multsums
    for i in {0..9}; do
        for j in {0..9}; do
            if (( i % 2 && j % 2 )); then
                multsums[i+j]+=" + 2*$a$i*$b$j"
            else
                multsums[i+j]+=" + $a$i*$b$j"
            fi
        done
    done

    echo "(("
    for i in {0..18}; do
        echo "$tmp$i = ${multsums[i]# + },"
    done

    f25519_reduce_at $tmp 8
    f25519_carry_at $tmp 8 # tmp8 is now within [-2**25; 2**25]
    f25519_carry_at $tmp 9 # tmp9 is now within [-2**24; 2**24]

    for i in {0..7}; do
        f25519_reduce_at $tmp $i
    done

    for i in {0..8}; do
        f25519_carry_at $tmp $i
    done
    echo "0))"

    for i in {0..9}; do
        echo "$out$i=\$$tmp$i"
    done
}

f25519_muls() {
    local a=$1 k=$2 out=$3 i
    echo "(("
    for i in {0..9}; do
        echo "$out$i = $a$i * $k,"
    done

    f25519_carry_at $out 8
    f25519_carry_wrap $out
    for i in {0..8}; do
        f25519_carry_at $out $i
    done
    echo "0))"
}

#   When receiving [a field element], implementations of X25519 (but not X448)
#   MUST mask the most significant bit in the final byte.
#
#                   ~ RFC7748, 5. The X25519 and X448 Functions

#   A curve point (x,y), with coordinates in the range 0 <= x,y < p, is
#   coded as follows.  First, encode the y-coordinate as a little-endian
#   string of 32 octets.  The most significant bit of the final octet is
#   always zero.  To form the encoding of the point, copy the least
#   significant bit of the x-coordinate to the most significant bit of
#   the final octet.
#
#                   ~ RFC8032, 5.1.2. Encoding
f25519_unpack() {
    local from=$1 to=$2
    local -i i width lsb byte bit handled

    echo "(("
    for i in {0..9}; do
        (( width = i % 2 ? 25 : 26 ))
        (( lsb = (51 * i + 1) / 2 ))

        local chunk=""
        handled=0
        while (( width >= 8 )); do
            (( byte = lsb / 8 ))
            (( bit = lsb % 8 ))
            local part=""
            if (( bit )); then
                part="$from[$byte] >> $bit"
            else
                part="$from[$byte]"
            fi

            if (( handled )); then
                chunk+=" | $part << $handled"
            else
                chunk+=" | $part"
            fi
            (( handled += (8 - bit) ))
            (( width -= (8 - bit) ))
            (( lsb += (8 - bit) ))
        done

        if (( width )); then
            (( byte = lsb / 8 ))
            # lsb must be divisible by 8 by now
            chunk+=" | ($from[$byte] & $(((1 << width) - 1))) << $handled"
        fi
        echo "$to$i = ${chunk# | },"
    done

    # odd indices are at most 2**25 - 1. even with carry into them, which is at
    # most 1 in this situation, they fit in the reduced range. thus we only
    # need to carry from the even indices.
    f25519_carry_at $to 0
    f25519_carry_at $to 2
    f25519_carry_at $to 4
    f25519_carry_at $to 6
    f25519_carry_at $to 8
    echo "0))"
}

f25519_pack() {
    local from=$1 to=$2 tmp=_t acc=_t16
    echo "(( $acc = ${from}0 + (${from}1 << 26) ))"
    echo "(( ${tmp}0 = $acc & $((2**32 - 1)) ))"
    echo "(( $acc >>= 32 ))"
    local -i acc_bits=19 next=2 k
    for (( k = 1; k < 8; k++ )); do
        local terms=""
        while (( next < 10 && acc_bits < 32 )); do
            terms+=" + ($from$next << $acc_bits)"
            (( acc_bits += next % 2 ? 25 : 26 ))
            (( next++ ))
        done
        echo "(( $acc += ${terms# + } ))"
        echo "(( $tmp$k = $acc & $((2**32 - 1)) ))"
        echo "(( $acc >>= 32 ))"
        (( acc_bits -= 32 ))
    done

    # XXX: This is not constant-time... just like everything else, because bash
    # stringifies and unstringifies all the integers all the time.
    echo "if (( $acc < 0 )); then"
    # This would be += 2**31 if not for the previous & (2**32 - 1)
    echo "  (( ${tmp}7 -= $((2**31)) ))"
    echo "  (( ${tmp}0 -= 19 ))"
    for k in {0..6}; do
        echo "  (( $tmp$((k+1)) += $tmp$k >> 32 ))"
    done
    echo "fi"

    for k in {0..31}; do
        if (( k % 4 )); then
            echo "(( $to[$k] = $tmp$((k / 4)) >> $((k % 4 * 8)) & 255 ))"
        else
            echo "(( $to[$k] = $tmp$((k / 4)) & 255 ))"
        fi
    done
}

# Currently a trivial wrapper, but there is room for optimisation
f25519_square() {
    local x=$1 out=$2
    f25519_mul $x $x $out
}

f25519_expshift() {
    local a=$1 k=$2 out=$3 i
    f25519_square $a $out
    echo "for _ in {2..$k}; do"
        f25519_square $out $out
    echo "done"
}

# Computes x^{-1} = x^{p - 2}
f25519_invert() {
    local x=$1 out=$2
    declwide e2_ e9_ e11_ eb5_ eb10_ eb20_ eb50_ eb100_
    f25519_square $x e2_      # e2_ = x^2
    f25519_square e2_ e9_    # e9_ = x^4
    f25519_square e9_ e9_    # e9_ = x^8
    f25519_mul $x e9_ e9_     # e9_ = x^9
    f25519_mul e2_ e9_ e11_  # e11_ = x^11
    f25519_square e11_ eb5_  # eb5_ = x^22
    f25519_mul e9_ eb5_ eb5_ # eb5_ = x^31
    f25519_expshift eb5_ 5 eb10_    # eb10_ = x^{2^10 - 2^5}
    f25519_mul eb5_ eb10_ eb10_     # eb10_ = x^{2^10 - 1}
    f25519_expshift eb10_ 10 eb20_
    f25519_mul eb10_ eb20_ eb20_    # eb20_ = x^{2^20 - 1}
    f25519_expshift eb20_ 20 eb50_
    f25519_mul eb20_ eb50_ eb50_    # eb50_ = x^{2^40 - 1}
    f25519_expshift eb50_ 10 eb50_
    f25519_mul eb10_ eb50_ eb50_    # eb50_ = x^{2^50 - 1}
    f25519_expshift eb50_ 50 eb100_
    f25519_mul eb50_ eb100_ eb100_  # eb100_ = x^{2^100 - 1}
    f25519_expshift eb100_ 100 $out
    f25519_mul eb100_ $out $out     # out = x^{2^200 - 1}
    f25519_expshift $out 50 $out
    f25519_mul eb50_ $out $out      # out = x^{2^250 - 1}
    f25519_expshift $out 5 $out
    f25519_mul e11_ $out $out       # out = x^{2^255 - 2^5 + 11 = 2^255 - 21}
}

if [ -n "${RUN_TESTS+x}" ]; then
    # Test vectors generated by comparing with Python's big int implementation
    . tests.sh
    declare -i input output
    echo Testing f25519_mul...

    input=($(fromhex 00907895389c3ee61e36aa5e2f57b4b39c20f711ea807da67e5928d1223c137d))
    eval "$(f25519_unpack input a)"
    input=($(fromhex c5451e5f063eefd3643e5b8fb0adeee77a8816fdc6394860e0f8b6b2c9d34fba))
    eval "$(f25519_unpack input b)"
    eval "$(f25519_mul a b c)"
    eval "$(f25519_pack c output)"
    assert_eq $(tohex "${output[@]}") ef8edf394ebb1d431f416029c34a234dcaa5b50cb1a6d715bab1c40af8bfe830

    input=($(fromhex 9fcb31e5f69ecf775340f577317ff9ea908a6c284e0594e832c2b3ec37ea795f))
    eval "$(f25519_unpack input a)"
    input=($(fromhex 7cf7fbe3797133c4685d8c8b787f0e71dcec2374527d39e2ef9116b9ed74407d))
    eval "$(f25519_unpack input b)"
    eval "$(f25519_mul a b c)"
    eval "$(f25519_pack c output)"
    assert_eq $(tohex "${output[@]}") 2f2ee78885450bbf254b4aca572a907212de29607d99d5dee45048593711b61e

    input=($(fromhex 9497e80e1ca054d5f8b4440fbb03b9f6c0a64784be75a6103f9a1dc697cd9891))
    eval "$(f25519_unpack input a)"
    input=($(fromhex 0ae5cd0c29e6d59f1b11abf1ddd7e946e0ab31a9f3b988c0a7c152c983f2d4ce))
    eval "$(f25519_unpack input b)"
    eval "$(f25519_mul a b c)"
    eval "$(f25519_pack c output)"
    assert_eq $(tohex "${output[@]}") f297bd36e825dbd0d58228beb1ae5369a369c31c621dd5016816fed7bf3ed675

    echo Testing f25519_invert...

    eval "
    invert() {
        $(f25519_invert a a)
    }
    "

    input=($(fromhex 766be74fd3110fe2c6d3294c3a86e0007d10b0113c2b282e66de28e5385ee4d5))
    eval "$(f25519_unpack input a)"
    invert
    eval "$(f25519_pack a output)"
    assert_eq $(tohex "${output[@]}") 8a2ac87e16241430df94a4ed0bdb1f0df83c85d09e182b7334549b39ea9b4e6b

    echo "Benchmarking f25519_invert (x10)..."

    time for i in {1..10}; do invert; done
fi
