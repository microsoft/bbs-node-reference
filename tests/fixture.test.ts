// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// test fixtures

import * as fs from 'fs';
import {BBS, modR} from '../src/bbs';
import { os2ip } from '../src/utils';
import { bytesToHex, bytesToNumberBE, hexToBytes } from '../src/utils';
import generatorFixture from '../fixtures/bls12-381-sha-256/generators.json';
import h2s from '../fixtures/bls12-381-sha-256/h2s.json';
import mmtsah from '../fixtures/bls12-381-sha-256/MapMessageToScalarAsHash.json';
import mockedRng from '../fixtures/bls12-381-sha-256/mockedRng.json';

interface Signature {
    caseName: string;
    signerKeyPair: {
      secretKey: string;
      publicKey: string;
    };
    header: string;
    messages: string[];
    signature: string;
    result: {
      valid: boolean;
      reason?: string;
    };
}
const fixturePath = "fixtures/bls12-381-sha-256";
const sigFiles = fs.readdirSync(`${fixturePath}/signature`);
const signatures = sigFiles.filter(f => f.endsWith('.json')).map(f => require(`../${fixturePath}/signature/${f}`) as Signature);

interface Proof {
    caseName: string;
    signerPublicKey: string;
    header: string;
    presentationHeader: string;
    revealedMessages: Record<string, string>;
    proof: string;
    result: {
      valid: boolean;
      reason: string;
    };
}  
const proofFiles = fs.readdirSync(`${fixturePath}/proof`);
const proofs = proofFiles.filter(f => f.endsWith('.json')).map(f => require(`../${fixturePath}/proof/${f}`) as Proof);

// create the BBS instance
const bbs = new BBS();

// common generators
const HGenerators = generatorFixture.MsgGenerators.map(v => bbs.cs.octets_to_point_g1(hexToBytes(v)));

// mock random number generator (for proof generation)
const MOCK_RNG_SEED = "332e313431353932363533353839373933323338343632363433333833323739"; // from spec
const seeded_random_scalars = (SEED: Uint8Array, count: number): bigint[] => {
    const dst = Buffer.from(bbs.cs.Ciphersuite_ID + "MOCK_RANDOM_SCALARS_DST_", "utf8");
    const out_len = bbs.cs.expand_len * count;
    const v = bbs.cs.expand_message(SEED, dst, out_len);
    const r: bigint[] = [];
    for (let i=0; i<count; i++) {
        const start_idx = i * bbs.cs.expand_len;
        const end_idx = (i+1) * bbs.cs.expand_len;
        r.push(modR(os2ip(v.slice(start_idx, end_idx))));
    }
    return r;
}

test("mocked_calculate_random_scalars", async () => {
    const expected = mockedRng.mockedScalars.map(v => BigInt('0x' + v));
    const actual = seeded_random_scalars(hexToBytes(MOCK_RNG_SEED), expected.length);
    expect(actual).toEqual(expected);
});

test("hash_to_scalar", async () => {
    const dst = hexToBytes(h2s.dst);
    const scalar = bbs.hash_to_scalar(hexToBytes(h2s.message), dst);
    const expected = BigInt('0x' + h2s.scalar);
    expect(scalar).toBe(expected);
});

test("MapMessageToScalarAsHash", async () => {
    const dst = hexToBytes(mmtsah.dst);
    for (let i=0; i<mmtsah.cases.length; i++) {
        const scalar = bbs.MapMessageToScalarAsHash(hexToBytes(mmtsah.cases[i].message), dst);
        const expected = BigInt('0x' + mmtsah.cases[i].scalar);
        expect(scalar).toBe(expected);
    }
});

for (let i=0; i<signatures.length; i++) {
    test(`signature${String(i+1).padStart(3, '0')}: ${signatures[i].caseName}`, async () => {

        const PK = hexToBytes(signatures[i].signerKeyPair.publicKey);
        const msg = signatures[i].messages.map(v => bbs.MapMessageToScalarAsHash(hexToBytes(v)));
        const generators = {
            Q1: bbs.cs.octets_to_point_g1(hexToBytes(generatorFixture.Q1)),
            Q2: bbs.cs.octets_to_point_g1(hexToBytes(generatorFixture.Q2)),
            H: HGenerators.slice(0,signatures[i].messages.length)
        }
        if (signatures[i].result.valid) {
            // recreate the signature
            const SK = bytesToNumberBE(hexToBytes(signatures[i].signerKeyPair.secretKey));

            const actualGenerators = await bbs.create_generators(10);
            if (!generators.Q1.equals(actualGenerators.Q1)) { throw `invalid Q1 generator; expected: ${generators.Q1}, actual: ${actualGenerators.Q1}`; }
            if (!generators.Q2.equals(actualGenerators.Q2)) { throw `invalid Q2 generator; expected: ${generators.Q2}, actual: ${actualGenerators.Q2}`; }
            generators.H.forEach((H, idx, a) => {
                if (!H.equals(actualGenerators.H[idx])) { throw `invalid H${idx} generator for signature ${i}; expected: ${H}, actual: ${actualGenerators.H[idx]}`; }
            })

            const signature = bbs.Sign(SK, PK, hexToBytes(signatures[i].header), msg, generators);
            const actualSignature = bytesToHex(signature);
            if (actualSignature != signatures[i].signature) {
                throw `invalid signature ${i}; expected: ${signatures[i].signature}, actual: ${actualSignature}`; 
            }

            bbs.Verify(PK, hexToBytes(signatures[i].signature), hexToBytes(signatures[i].header), msg, generators);
        } else {
            // validation of the non-valid signature should fail
            let failed = false;
            try {
                bbs.Verify(PK, hexToBytes(signatures[i].signature), hexToBytes(signatures[i].header), msg, generators);
            } catch (e) {
                failed = true;
            }
            if (!failed) throw `signature ${i} should be invalid`;
        }
    })   
};

const generators = {
    Q1: bbs.cs.octets_to_point_g1(hexToBytes(generatorFixture.Q1)),
    Q2: bbs.cs.octets_to_point_g1(hexToBytes(generatorFixture.Q2)),
    H: HGenerators
}
for (let i=0; i<proofs.length; i++) {
    test(`proof${String(i+1).padStart(3, '0')}: ${proofs[i].caseName}`, async () => {
        const disclosed_indexes = Object.keys(proofs[i].revealedMessages).map(v => parseInt(v) + 1); 
        const disclosed_messages = Object.values(proofs[i].revealedMessages).map(v => bbs.MapMessageToScalarAsHash(hexToBytes(v)));

        let failed = false;
        try {
            // TODO: implement the proof generation too, now that we have mockup random values
            bbs.ProofVerify(
                hexToBytes(proofs[i].signerPublicKey),
                hexToBytes(proofs[i].proof),
                hexToBytes(proofs[i].header),
                hexToBytes(proofs[i].presentationHeader),
                disclosed_messages,
                generators,
                disclosed_indexes);
        } catch (e) {
            failed = true;
        }
        if (proofs[i].result.valid && failed) throw `proof ${i+1} should have been valid`; // proof files suffix are 1-based
    })
};