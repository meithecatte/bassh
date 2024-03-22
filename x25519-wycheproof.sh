set -u
. x25519.sh
. tests.sh

JQ_CODE='.testGroups[].tests[] | "\(.tcId) \(.private) \(.public) \(.shared)"'
TEST_FILE=wycheproof/testvectors/x25519_test.json
jq -r "$JQ_CODE" "$TEST_FILE" | while read -r tcId private public shared; do
    declare -i x25519_k=($(fromhex "$private"))
    declare -i x25519_u=($(fromhex "$public"))
    x25519
    assert_eq "$(tohex "${x25519_out[@]}")" "$shared"
    printf '\r%d' $tcId
done

printf '\n'
