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

#f25519_mul a b c
. tests.sh
declare -i input=($(fromhex 00907895389c3ee61e36aa5e2f57b4b39c20f711ea807da67e5928d1223c13fd))
eval "$(f25519_unpack input a)"
echo $a0 $a1 $a2 $a3 $a4 $a5 $a6 $a7 $a8 $a9
