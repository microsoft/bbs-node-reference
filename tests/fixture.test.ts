// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as fs from 'fs';
import {BBS} from '../src/bbs';
import { bytesToHex, bytesToNumberBE, hexToBytes } from '../src/utils';
import generatorFixture from '../fixtures/bls12-381-sha-256/generators.json';
import h2s from '../fixtures/bls12-381-sha-256/h2s.json';
import mmtsah from '../fixtures/bls12-381-sha-256/MapMessageToScalarAsHash.json'
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

// import signature001 from '../fixtures/bls12-381-sha-256/signature/signature001.json';
// import signature002 from '../fixtures/bls12-381-sha-256/signature/signature002.json';
// import signature003 from '../fixtures/bls12-381-sha-256/signature/signature003.json';
// import signature004 from '../fixtures/bls12-381-sha-256/signature/signature004.json';
// import signature005 from '../fixtures/bls12-381-sha-256/signature/signature005.json';
// import signature006 from '../fixtures/bls12-381-sha-256/signature/signature006.json';
// import signature007 from '../fixtures/bls12-381-sha-256/signature/signature007.json';
// import signature008 from '../fixtures/bls12-381-sha-256/signature/signature008.json';
// import signature009 from '../fixtures/bls12-381-sha-256/signature/signature009.json';
// import proof001 from '../fixtures/bls12-381-sha-256/proof/proof001.json';
// import proof002 from '../fixtures/bls12-381-sha-256/proof/proof002.json';
// import proof003 from '../fixtures/bls12-381-sha-256/proof/proof003.json';
// import proof004 from '../fixtures/bls12-381-sha-256/proof/proof004.json';
// import proof005 from '../fixtures/bls12-381-sha-256/proof/proof005.json';
// import proof006 from '../fixtures/bls12-381-sha-256/proof/proof006.json';
// import proof007 from '../fixtures/bls12-381-sha-256/proof/proof007.json';
// import proof008 from '../fixtures/bls12-381-sha-256/proof/proof008.json';
// import proof009 from '../fixtures/bls12-381-sha-256/proof/proof009.json';
// import proof010 from '../fixtures/bls12-381-sha-256/proof/proof010.json';
// import proof011 from '../fixtures/bls12-381-sha-256/proof/proof011.json';
// import proof012 from '../fixtures/bls12-381-sha-256/proof/proof012.json';
// import proof013 from '../fixtures/bls12-381-sha-256/proof/proof013.json';
// TODO: read the test vectors from the json files dynamically, like:
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

// test fixtures

const bbs = new BBS();

// common generators
const HGenerators = generatorFixture.MsgGenerators.map(v => bbs.cs.octets_to_point_g1(hexToBytes(v)));

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

// const signatures = [signature001, signature002, signature003, signature004, signature005, signature006, signature007, signature008, signature009];
for (let i=0; i<signatures.length; i++) {
    test(signatures[i].caseName, async () => {

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