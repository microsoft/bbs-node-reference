#!/bin/bash

FILE=fixtures
if [ -d "$FILE" ]; then
    echo "$FILE directory already fetched; delete to refetch."
    exit
fi

# TODO: update once fixtures are merged in the spec's main
urlPrefix=https://raw.githubusercontent.com/BasileiosKal/bbs-signature/fixtures-update/tooling/fixtures/fixture_data/bls12-381-sha-256/
mkdir -p fixtures
mkdir -p fixtures/bls12-381-sha-256
mkdir -p fixtures/bls12-381-sha-256/h2s
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

# fetch h2s
for i in {1..2}
do
   file=$(printf "%s%.3d%s" "h2s/h2s" $i ".json")
   url=$(printf "%s%s" $urlPrefix $file)
   echo fetching $url
   cmd=$(printf "%s%s%s%s%s%s" "wget -q -O " "fixtures/bls12-381-sha-256/" $file " " $url)
   $cmd
done

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

