#!/bin/bash

FILE=fixtures
if [ -d "$FILE" ]; then
   echo "$FILE directory already fetched; delete to refetch."
   exit
fi

mkdir -p fixtures

urlPrefix="https://raw.githubusercontent.com/decentralized-identity/bbs-signature/vasilis/draft03-fixtures/tooling/fixtures/fixture_data/"
# TODO: revert back after spec PR 273 is merged
#urlPrefix="https://raw.githubusercontent.com/decentralized-identity/bbs-signature/main/tooling/fixtures/fixture_data/"

fetch_file() {
   local suite=$1
   local file=$2
   local url="$urlPrefix/$suite/$file"
   echo "Fetching $url"
   wget -q -O "fixtures/$suite/$file" "$url"
}
suites=("bls12-381-sha-256" "bls12-381-shake-256")
for suite in "${suites[@]}"; do
   echo "Fetching $suite fixtures"
   mkdir -p fixtures/$suite
   files=(
      "generators.json"
      "MapMessageToScalarAsHash.json"
      "h2s.json"
      "keypair.json"
      "mockedRng.json"
   )

   for file in "${files[@]}"; do
      fetch_file "$suite" "$file"
   done

   for ((i = 1; i <= 9; i++)); do
      mkdir -p fixtures/$suite/signature
      fetch_file "$suite" "signature/signature$(printf "%.3d" "$i").json"
   done

   for ((i = 1; i <= 13; i++)); do
      mkdir -p fixtures/$suite/proof
      fetch_file "$suite" "proof/proof$(printf "%.3d" "$i").json"
   done
done
