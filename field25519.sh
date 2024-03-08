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

f25519_reduce_at() {
    local a=$1 k=$2
    local -i bits bias
    (( bits = k % 2 ? 25 : 26 ))
    (( bias = 1 << (bits - 1) ))
    echo "(( $a$k += $bias ))"
    echo "(( $a$((k + 1)) += $a$k >> $bits ))"
    echo "(( $a$k = ($a$k & $(((1 << bits) - 1))) - $bias ))"
}

f25519_mul() {
    local a=$1 b=$2 out=$3 tmp=_t
    local -i i j
    local -a multsums
    local -ai multcount
    for i in {0..9}; do
        for j in {0..9}; do
            if (( i % 2 && j % 2 )); then
                multsums[i+j]+=" + 2*$a$i*$b$j"
                multcount[i+j]+=2
            else
                multsums[i+j]+=" + $a$i*$b$j"
                multcount[i+j]+=1
            fi
        done
    done

    for i in {0..18}; do
        echo "(( $tmp$i = ${multsums[i]# + } ))"
    done

    f25519_reduce_at $tmp 8
    f25519_reduce_at $tmp 9
}

f25519_mul a b c
