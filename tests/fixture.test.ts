// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// test fixtures

import * as fs from 'fs';
import { BBS } from '../src/bbs';
import { os2ip } from '../src/utils';
import { bytesToHex, hexToBytes } from '../src/utils';
import generatorFixture from '../fixtures/bls12-381-sha-256/generators.json';
import h2s from '../fixtures/bls12-381-sha-256/h2s.json';
import keypair from '../fixtures/bls12-381-sha-256/keypair.json';
import mmtsah from '../fixtures/bls12-381-sha-256/MapMessageToScalarAsHash.json';
import mockedRng from '../fixtures/bls12-381-sha-256/mockedRng.json';
import { FrScalar, G1Point } from '../src/math';

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
const HGenerators = generatorFixture.MsgGenerators.map(v => G1Point.fromOctets(hexToBytes(v)));
const generators = {
    Q1: G1Point.fromOctets(hexToBytes(generatorFixture.Q1)),
    H: HGenerators
}

// mock random number generator (for proof generation)
const MOCK_RNG_SEED = mockedRng.seed;
const seeded_random_scalars = (SEED: Uint8Array, count: number): FrScalar[] => {
    const dst = Buffer.from(bbs.cs.ciphersuite_id + "MOCK_RANDOM_SCALARS_DST_", "utf8");
    const out_len = bbs.cs.expand_len * count;
    const v = bbs.cs.expand_message(SEED, dst, out_len);
    const r: FrScalar[] = [];
    for (let i = 0; i < count; i++) {
        const start_idx = i * bbs.cs.expand_len;
        const end_idx = (i + 1) * bbs.cs.expand_len;
        r.push(os2ip(v.slice(start_idx, end_idx)));
    }
    return r;
}

test("mocked_calculate_random_scalars", async () => {
    const expected = mockedRng.mockedScalars.map(v => FrScalar.create(BigInt('0x' + v)));
    const actual = seeded_random_scalars(hexToBytes(MOCK_RNG_SEED), expected.length);
    expect(expected.length).toBe(actual.length);
    for (let i = 0; i < expected.length; i++) {
        expect(expected[i].equals(actual[i])).toBe(true);
    };
});

test("hash_to_scalar", async () => {
    const dst = hexToBytes(h2s.dst);
    const scalar = bbs.hash_to_scalar(hexToBytes(h2s.message), dst);
    const expected = FrScalar.create(BigInt('0x' + h2s.scalar));
    expect(scalar.equals(expected)).toBe(true);
});

test("MapMessageToScalarAsHash", async () => {
    const dst = hexToBytes(mmtsah.dst);
    for (let i = 0; i < mmtsah.cases.length; i++) {
        const scalar = bbs.MapMessageToScalarAsHash(hexToBytes(mmtsah.cases[i].message), dst);
        const expected = FrScalar.create(BigInt('0x' + mmtsah.cases[i].scalar));
        expect(scalar.equals(expected)).toBe(true);

    }
});

test("create_generators", async () => {
    const actualGenerators = await bbs.create_generators(generatorFixture.MsgGenerators.length);
    if (!generators.Q1.equals(actualGenerators.Q1)) { throw `invalid Q1 generator; expected: ${generators.Q1}, actual: ${actualGenerators.Q1}`; }
    generators.H.forEach((H, idx, a) => {
        if (!H.equals(actualGenerators.H[idx])) { throw `invalid H${idx} generator; expected: ${H}, actual: ${actualGenerators.H[idx]}`; }
    })
    // check base point
    const BP = G1Point.fromOctets(hexToBytes(generatorFixture.BP));
    if (!BP.equals(bbs.cs.P1)) { throw `invalid base point; expected: ${BP}, actual: ${bbs.cs.P1}`; }
});

test("keypair", async () => {
    const SK = bbs.KeyGen(hexToBytes(keypair.keyMaterial), hexToBytes(keypair.keyInfo));
    const expected = FrScalar.create(BigInt('0x' + keypair.keyPair.secretKey));
    expect(SK.equals(expected)).toBe(true);
    const PK = bbs.SkToPk(SK);
    const pkOctets = PK.toOctets();
    const expectedPK = hexToBytes(keypair.keyPair.publicKey);
    expect(pkOctets).toEqual(expectedPK);
});

for (let i = 0; i < signatures.length; i++) {
    test(`signature${String(i + 1).padStart(3, '0')}: ${signatures[i].caseName}`, async () => {

        const PK = bbs.octets_to_pubkey(hexToBytes(signatures[i].signerKeyPair.publicKey));
        const header = hexToBytes(signatures[i].header);
        const msg = signatures[i].messages.map(v => bbs.MapMessageToScalarAsHash(hexToBytes(v)));
        const generators = {
            Q1: G1Point.fromOctets(hexToBytes(generatorFixture.Q1)),
            H: HGenerators.slice(0, signatures[i].messages.length)
        }
        if (signatures[i].result.valid) {
            // recreate the signature
            const SK = FrScalar.create(BigInt('0x' + signatures[i].signerKeyPair.secretKey));
            const signature = bbs.Sign(SK, PK, header, msg, generators);
            const actualSignature = bytesToHex(signature);
            if (actualSignature != signatures[i].signature) {
                throw `invalid signature ${i}; expected: ${signatures[i].signature}, actual: ${actualSignature}`;
            }

            bbs.Verify(PK, hexToBytes(signatures[i].signature), header, msg, generators);
        } else {
            // validation of the non-valid signature should fail
            let failed = false;
            try {
                bbs.Verify(PK, hexToBytes(signatures[i].signature), header, msg, generators);
            } catch (e) {
                failed = true;
            }
            if (!failed) throw `signature ${i} should be invalid`;
        }
    })
};

for (let i = 0; i < proofs.length; i++) {
    test(`proof${String(i + 1).padStart(3, '0')}: ${proofs[i].caseName}`, async () => {
        const disclosed_indexes = Object.keys(proofs[i].revealedMessages).map(v => parseInt(v) + 1);
        const disclosed_messages = Object.values(proofs[i].revealedMessages).map(v => bbs.MapMessageToScalarAsHash(hexToBytes(v)));

        let failed = false;
        try {
            // TODO: implement the proof generation too, now that we have mockup random values
            bbs.ProofVerify(
                bbs.octets_to_pubkey(hexToBytes(proofs[i].signerPublicKey)),
                hexToBytes(proofs[i].proof),
                hexToBytes(proofs[i].header),
                hexToBytes(proofs[i].presentationHeader),
                disclosed_messages,
                generators,
                disclosed_indexes);
        } catch (e) {
            failed = true;
        }
        if (proofs[i].result.valid && failed) throw `proof ${i + 1} should have been valid`; // proof files suffix are 1-based
    })
};
