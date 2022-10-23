// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// TODO: temp file for fixture debugging; the tests/fixture.test.ts will contain the final version

import {BBS} from './bbs';
import generatorFixture from '../fixtures/bls12-381-sha-256/generators.json';
import h2s001 from '../fixtures/bls12-381-sha-256/h2s/h2s001.json'
import h2s002 from '../fixtures/bls12-381-sha-256/h2s/h2s002.json'
import mmtsah from '../fixtures/bls12-381-sha-256/MapMessageToScalarAsHash.json'
import signature001 from '../fixtures/bls12-381-sha-256/signature/signature001.json';
import signature002 from '../fixtures/bls12-381-sha-256/signature/signature002.json';
import signature003 from '../fixtures/bls12-381-sha-256/signature/signature003.json';
import signature004 from '../fixtures/bls12-381-sha-256/signature/signature004.json';
import signature005 from '../fixtures/bls12-381-sha-256/signature/signature005.json';
import signature006 from '../fixtures/bls12-381-sha-256/signature/signature006.json';
import signature007 from '../fixtures/bls12-381-sha-256/signature/signature007.json';
import signature008 from '../fixtures/bls12-381-sha-256/signature/signature008.json';
import signature009 from '../fixtures/bls12-381-sha-256/signature/signature009.json';
import proof001 from '../fixtures/bls12-381-sha-256/proof/proof001.json';
import proof002 from '../fixtures/bls12-381-sha-256/proof/proof002.json';
import proof003 from '../fixtures/bls12-381-sha-256/proof/proof003.json';
import proof004 from '../fixtures/bls12-381-sha-256/proof/proof004.json';
import proof005 from '../fixtures/bls12-381-sha-256/proof/proof005.json';
import proof006 from '../fixtures/bls12-381-sha-256/proof/proof006.json';
import proof007 from '../fixtures/bls12-381-sha-256/proof/proof007.json';
import proof008 from '../fixtures/bls12-381-sha-256/proof/proof008.json';
import proof009 from '../fixtures/bls12-381-sha-256/proof/proof009.json';
import proof010 from '../fixtures/bls12-381-sha-256/proof/proof010.json';
import proof011 from '../fixtures/bls12-381-sha-256/proof/proof011.json';
import proof012 from '../fixtures/bls12-381-sha-256/proof/proof012.json';
import proof013 from '../fixtures/bls12-381-sha-256/proof/proof013.json';
import { bytesToHex, hexToBytes } from './utils';


try {
    const bbs = new BBS();

    // test map messages to scalar as hash
    for (let i=0; i<mmtsah.cases.length; i++) {
        const dst = hexToBytes(mmtsah.dst); // TODO: do once
        const scalar = bbs.MapMessageToScalarAsHash(hexToBytes(mmtsah.cases[i].message), dst);
        const expected = BigInt('0x' + mmtsah.cases[i].scalar);
        if (scalar != expected) {
            throw `invalid map message to scalar value; expected: ${expected}, actual: ${scalar}`
        }
    }

    // test hash to scalar
    const h2s = [h2s001, h2s002];
    for (let i=0; i<h2s.length; i++) {
        const dst = hexToBytes(h2s[i].dst);
        const scalars = bbs.hash_to_scalar(hexToBytes(h2s[i].message), h2s[i].count, dst);
        for (let j=0; j<h2s[i].count; j++) {
            const expected = BigInt('0x' + h2s[i].scalars[j]);
            if (scalars[j] != expected) {
                throw `invalid hash-to-scalar value; expected: ${expected}, actual: ${scalars[j]}`; 
            }
        }
    }

    const H10 = generatorFixture.MsgGenerators.map(v => bbs.cs.octets_to_point_g1(hexToBytes(v)));

    // test signatures
    const signatures = [signature001, signature002, signature003, signature004, signature005, signature006, signature007, signature008, signature009];
    for (let i=0; i<signatures.length; i++) {
        const PK = hexToBytes(signatures[i].signerKeyPair.publicKey);
        const msg = signatures[i].messages.map(v => bbs.MapMessageToScalarAsHash(hexToBytes(v)));
        const generators = {
            Q1: bbs.cs.octets_to_point_g1(hexToBytes(generatorFixture.Q1)),
            Q2: bbs.cs.octets_to_point_g1(hexToBytes(generatorFixture.Q2)),
            H: H10.slice(0,signatures[i].messages.length)
        }
        if (signatures[i].result.valid) {
            // recreate the signature

            const SK = hexToBytes(signatures[i].signerKeyPair.secretKey);

            const actualGenerators = bbs.CreateGenerators(10);
            if (!generators.Q1.equals(actualGenerators.Q1)) { throw `invalid Q1 generator; expected: ${generators.Q1}, actual: ${actualGenerators.Q1}`; }
            if (!generators.Q2.equals(actualGenerators.Q2)) { throw `invalid Q2 generator; expected: ${generators.Q2}, actual: ${actualGenerators.Q2}`; }
            generators.H.forEach((H, idx, a) => {
                if (!H.equals(actualGenerators.H[idx])) { throw `invalid H${idx} generator for signature ${i}; expected: ${H}, actual: ${actualGenerators.H[idx]}`; }
            })

            const signature = bbs.Sign(SK, PK, hexToBytes(signatures[i].header), msg, generators);
            const actualSignature = bytesToHex(signature);
            if (signatures[i].result.valid && actualSignature != signatures[i].signature) {
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
    }


    // test proofs
    const proofs = [proof001, proof002, proof003, proof004, proof005, proof006, proof007, proof008, proof009, proof010, proof011, proof012, proof013];
    for (let i=0; i<proofs.length; i++) {
        const generators = {
            Q1: bbs.cs.octets_to_point_g1(hexToBytes(generatorFixture.Q1)),
            Q2: bbs.cs.octets_to_point_g1(hexToBytes(generatorFixture.Q2)),
            H: H10.slice(0,proofs[i].totalMessageCount)
        }
        const disclosed_indexes = Object.keys(proofs[i].revealedMessages).map(v => parseInt(v) + 1); // parse 
        const disclosed_messages = Object.values(proofs[i].revealedMessages).map(v => bbs.MapMessageToScalarAsHash(hexToBytes(v)));

        let failed = false;
        try {
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
        if (proofs[i].result.valid && failed) throw `proof ${i} should have been valid`;
    }
}
catch (e) {
    console.log(e);
}