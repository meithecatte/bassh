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
    local v=$1 k=${2:-10} i
    for (( i = 0; i < k; i++ )); do
        echo "local -i $v$i"
    done
}

f25519_carry_at() {
    local a=$1 k=$2
    local -i bits bias
    (( bits = k % 2 ? 25 : 26 ))
    (( bias = 1 << (bits - 1) ))
    echo "(( $a$k += $bias ))"
    echo "(( $a$((k + 1)) += $a$k >> $bits ))"
    echo "(( $a$k = ($a$k & $(((1 << bits) - 1))) - $bias ))"
}

f25519_carry_wrap() {
    local a=$1 k=9
    local -i bits bias
    (( bits = k % 2 ? 25 : 26 ))
    (( bias = 1 << (bits - 1) ))
    echo "(( $a$k += $bias ))"
    echo "(( ${a}0 += 19 * ($a$k >> $bits) ))"
    echo "(( $a$k = ($a$k & $(((1 << bits) - 1))) - $bias ))"
}

f25519_reduce_at() {
    local a=$1 to=$2
    local from=$((to + 10))
    echo "(( $a$to += $a$from * 19 ))"
}

f25519_add() {
    local a=$1 b=$2 out=$3 i
    for i in {0..9}; do
        echo "(( $out$i = $a$i + $b$i ))"
    done
}

f25519_sub() {
    local a=$1 b=$2 out=$3 i
    for i in {0..9}; do
        echo "(( $out$i = $a$i - $b$i ))"
    done
}

# NOTE: apart from making sure that all outputs are within [-2**25; 2**25],
# mul also ensures that out9 is within [-2**24; 2**24 + 2**16].
f25519_mul() {
    local a=$1 b=$2 out=$3 tmp=_t
    local i j
    local -a multsums
    #local -ai multcount
    for i in {0..9}; do
        for j in {0..9}; do
            if (( i % 2 && j % 2 )); then
                multsums[i+j]+=" + 2*$a$i*$b$j"
                #multcount[i+j]+=2
            else
                multsums[i+j]+=" + $a$i*$b$j"
                #multcount[i+j]+=1
            fi
        done
    done

    for i in {0..18}; do
        echo "(( $tmp$i = ${multsums[i]# + } ))"
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

    for i in {0..9}; do
        echo "$out$i=\$$tmp$i"
    done
}

f25519_unpack() {
    local from=$1 to=$2
    local -i i width lsb byte bit handled

    for i in {0..9}; do
        (( width = i % 2 ? 25 : 26 ))
        (( lsb = (51 * i + 1) / 2 ))

        # don't trim out the most significant bit
        if (( i == 9 )); then
            width=26
        fi

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
        echo "(( $to$i = ${chunk# | } ))"
    done

    # odd indices are at most 2**25 - 1. even with carry into them, which is at
    # most 1 in this situation, they fit in the reduced range. thus we only
    # need to carry from the even indices (and 9, due to the special case above)
    f25519_carry_at $to 8
    f25519_carry_wrap $to
    f25519_carry_at $to 0
    f25519_carry_at $to 2
    f25519_carry_at $to 4
    f25519_carry_at $to 6
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

# Computes x^{-1} = x^{p - 2}
f25519_invert() {
    local x=$1 out=$2
    declwide e2_
    declwide e4_
    declwide e8_
    declwide e16_
    declwide e32_
    declwide e64_
    f25519_square x e2_   # e2_ = x^2
    f25519_mul x e2_ e2_  # e2_ = x^3 (2 ones)

    f25519_square e2_ e4_  # e4_ = x^6
    f25519_square e4_ e4_  # e4_ = x^12
    f25519_mul e2_ e4_ e4_ # e4_ = x^15 (4 ones)

    local -i k
    for (( k=8; k <= 64; k *= 2 )); do
        f25519_square e$((k/2))_ e${k}_
        echo "for i in {1..$((k/2 - 1))}; do"
            f25519_square e${k}_ e${k}_
        echo "done"
        f25519_mul e$((k/2))_ e${k}_ e${k}_ # e${k}_ = x^0xff...ff (k ones)
    done

    f25519_square e64_ $out
    echo "for i in {1..63}; do"
        f25519_square $out $out
    echo "done"
    f25519_mul e64_ $out $out # out = x^0xff...ff (128 ones)

    echo "for i in {1..64}; do"
        f25519_square $out $out
    echo "done"
    f25519_mul e64_ $out $out # out = x^0xff...ff (192 ones)

    echo "for i in {1..32}; do"
        f25519_square $out $out
    echo "done"
    f25519_mul e32_ $out $out # out = x^0xff...ff (224 ones)

    echo "for i in {1..16}; do"
        f25519_square $out $out
    echo "done"
    f25519_mul e16_ $out $out # out = x^0xff...ff (240 ones)
}

if [ -n "${RUN_TESTS+x}" ]; then
    # Test vectors generated by comparing with Python's big int implementation
    . tests.sh
    declare -i input output
    echo Testing f25519_mul...

    input=($(fromhex 00907895389c3ee61e36aa5e2f57b4b39c20f711ea807da67e5928d1223c137d))
    eval "$(f25519_unpack input a)"
    input=($(fromhex b2451e5f063eefd3643e5b8fb0adeee77a8816fdc6394860e0f8b6b2c9d34fba))
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

    input=($(fromhex 8197e80e1ca054d5f8b4440fbb03b9f6c0a64784be75a6103f9a1dc697cd9891))
    eval "$(f25519_unpack input a)"
    input=($(fromhex f7e4cd0c29e6d59f1b11abf1ddd7e946e0ab31a9f3b988c0a7c152c983f2d4ce))
    eval "$(f25519_unpack input b)"
    eval "$(f25519_mul a b c)"
    eval "$(f25519_pack c output)"
    assert_eq $(tohex "${output[@]}") f297bd36e825dbd0d58228beb1ae5369a369c31c621dd5016816fed7bf3ed675

    echo Benchmarking f25519_square...

    eval "
    sqra() {
        $(f25519_square a a)
    }
    "

    time for i in {1..1000}; do sqra; done
fi
