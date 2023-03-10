#!/bin/bash

FILE=fixtures
if [ -d "$FILE" ]; then
    echo "$FILE directory already fetched; delete to refetch."
    exit
fi

urlPrefix=https://raw.githubusercontent.com/decentralized-identity/bbs-signature/main/tooling/fixtures/fixture_data/bls12-381-sha-256/
mkdir -p fixtures
mkdir -p fixtures/bls12-381-sha-256
mkdir -p fixtures/bls12-381-sha-256/signature
mkdir -p fixtures/bls12-381-sha-256/proof

# fetch generators.json
file=$(printf "%s%s" "generators" ".json")
url=$(printf "%s%s" $urlPrefix $file)
echo fetching $url
cmd=$(printf "%s%s%s%s%s%s" "wget -q -O " "fixtures/bls12-381-sha-256/" $file " " $url)
$cmd

# fetch MapMessageToScalarAsHash.json
file=$(printf "%s%s" "MapMessageToScalarAsHash" ".json")
url=$(printf "%s%s" $urlPrefix $file)
echo fetching $url
cmd=$(printf "%s%s%s%s%s%s" "wget -q -O " "fixtures/bls12-381-sha-256/" $file " " $url)
$cmd

# fetch h2s.json
file=$(printf "%s%s" "h2s" ".json")
url=$(printf "%s%s" $urlPrefix $file)
echo fetching $url
cmd=$(printf "%s%s%s%s%s%s" "wget -q -O " "fixtures/bls12-381-sha-256/" $file " " $url)
$cmd

# fetch mockedRng.json
file=$(printf "%s%s" "mockedRng" ".json")
url=$(printf "%s%s" $urlPrefix $file)
echo fetching $url
cmd=$(printf "%s%s%s%s%s%s" "wget -q -O " "fixtures/bls12-381-sha-256/" $file " " $url)
$cmd

# fetch signatures
for i in {1..9}
do
   file=$(printf "%s%.3d%s" "signature/signature" $i ".json")
   url=$(printf "%s%s" $urlPrefix $file)
   echo fetching $url
   cmd=$(printf "%s%s%s%s%s%s" "wget -q -O " "fixtures/bls12-381-sha-256/" $file " " $url)
   $cmd
done

# fetch proofs
for i in {1..13}
do
   file=$(printf "%s%.3d%s" "proof/proof" $i ".json")
   url=$(printf "%s%s" $urlPrefix $file)
   echo fetching $url
   cmd=$(printf "%s%s%s%s%s%s" "wget -q -O " "fixtures/bls12-381-sha-256/" $file " " $url)
   $cmd
done

