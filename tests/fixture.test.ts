// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// test fixtures

import * as fs from 'fs';
import { BBS } from '../src/bbs';
import { os2ip } from '../src/utils';
import { bytesToHex, hexToBytes } from '../src/utils';
import { FrScalar, G1Point } from '../src/math';
import { BLS12_381_SHA256_Ciphersuite, BLS12_381_SHAKE_256_Ciphersuite } from '../src/ciphersuite';

interface Generators {
    P1: string;
    Q1: string;
    MsgGenerators: string[];
}

interface MockedRng {
    seed: string;
    dst: string;
    mockedScalars: string[];
}

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

interface Proof {
    caseName: string;
    signerPublicKey: string;
    header: string;
    presentationHeader: string;
    messages: string[];
    disclosedIndexes: number[];
    proof: string;
    result: {
        valid: boolean;
        reason: string;
    };
}

const ciphersuites = ["bls12-381-sha-256", "bls12-381-shake-256"];
ciphersuites.forEach(cs => {
    // load fixtures
    const fixturePath = "fixtures/" + cs;

    const generatorFixture = require(`../${fixturePath}/generators.json`) as Generators;
    const h2sFixture = require(`../${fixturePath}/h2s.json`);
    const keypairFixture = require(`../${fixturePath}/keypair.json`);
    const mmtsahFixture = require(`../${fixturePath}/MapMessageToScalarAsHash.json`);
    const mockedRngFixture = require(`../${fixturePath}/mockedRng.json`) as MockedRng;

    const sigFiles = fs.readdirSync(`${fixturePath}/signature`);
    const signaturesFixture = sigFiles.filter(f => f.endsWith('.json')).map(f => require(`../${fixturePath}/signature/${f}`) as Signature);

    const proofFiles = fs.readdirSync(`${fixturePath}/proof`);
    const proofsFixture = proofFiles.filter(f => f.endsWith('.json')).map(f => require(`../${fixturePath}/proof/${f}`) as Proof);

    // create the BBS instance
    const bbs = new BBS(cs.includes("shake") ? BLS12_381_SHAKE_256_Ciphersuite : BLS12_381_SHA256_Ciphersuite);

    // common generators
    const HGenerators = generatorFixture.MsgGenerators.map(v => G1Point.fromOctets(hexToBytes(v)));
    const generators = {
        Q1: G1Point.fromOctets(hexToBytes(generatorFixture.Q1)),
        H: HGenerators
    }

    // mock random number generator (for proof generation)
    const MOCK_RNG_SEED = mockedRngFixture.seed;
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

    test(`mocked_calculate_random_scalars (${cs})`, async () => {
        const expected = mockedRngFixture.mockedScalars.map(v => FrScalar.create(BigInt('0x' + v)));
        const actual = seeded_random_scalars(hexToBytes(MOCK_RNG_SEED), expected.length);
        expect(expected.length).toBe(actual.length);
        for (let i = 0; i < expected.length; i++) {
            expect(expected[i].equals(actual[i])).toBe(true);
        };
    });

    test(`hash_to_scalar (${cs})`, async () => {
        const dst = hexToBytes(h2sFixture.dst);
        const scalar = bbs.hash_to_scalar(hexToBytes(h2sFixture.message), dst);
        const expected = FrScalar.create(BigInt('0x' + h2sFixture.scalar));
        expect(scalar.equals(expected)).toBe(true);
    });

    test(`MapMessageToScalarAsHash (${cs})`, async () => {
        const dst = hexToBytes(mmtsahFixture.dst);
        for (let i = 0; i < mmtsahFixture.cases.length; i++) {
            const scalar = bbs.MapMessageToScalarAsHash(hexToBytes(mmtsahFixture.cases[i].message), dst);
            const expected = FrScalar.create(BigInt('0x' + mmtsahFixture.cases[i].scalar));
            expect(scalar.equals(expected)).toBe(true);
        }
    });

    test(`create_generators (${cs})`, async () => {
        const actualGenerators = await bbs.create_generators(generatorFixture.MsgGenerators.length);
        if (!generators.Q1.equals(actualGenerators.Q1)) { throw `invalid Q1 generator; expected: ${generators.Q1}, actual: ${actualGenerators.Q1}`; }
        generators.H.forEach((H, idx, a) => {
            if (!H.equals(actualGenerators.H[idx])) { throw `invalid H${idx} generator; expected: ${H}, actual: ${actualGenerators.H[idx]}`; }
        })
        // check base point
        const P1 = G1Point.fromOctets(hexToBytes(generatorFixture.P1));
        if (!P1.equals(bbs.cs.P1)) { throw `invalid base point; expected: ${P1}, actual: ${bbs.cs.P1}`; }
    });

    test(`keypair (${cs})`, async () => {
        const SK = bbs.KeyGen(hexToBytes(keypairFixture.keyMaterial), hexToBytes(keypairFixture.keyInfo));
        const expected = FrScalar.create(BigInt('0x' + keypairFixture.keyPair.secretKey));
        expect(SK.equals(expected)).toBe(true);
        const PK = bbs.SkToPk(SK);
        const pkOctets = PK.toOctets();
        const expectedPK = hexToBytes(keypairFixture.keyPair.publicKey);
        expect(pkOctets).toEqual(expectedPK);
    });

    for (let i = 0; i < signaturesFixture.length; i++) {
        test(`signature${String(i + 1).padStart(3, '0')}: ${signaturesFixture[i].caseName} (${cs})`, async () => {

            const PK = bbs.octets_to_pubkey(hexToBytes(signaturesFixture[i].signerKeyPair.publicKey));
            const header = hexToBytes(signaturesFixture[i].header);
            const msg = signaturesFixture[i].messages.map(v => bbs.MapMessageToScalarAsHash(hexToBytes(v)));
            const generators = {
                Q1: G1Point.fromOctets(hexToBytes(generatorFixture.Q1)),
                H: HGenerators.slice(0, signaturesFixture[i].messages.length)
            }
            if (signaturesFixture[i].result.valid) {
                // recreate the signature
                const SK = FrScalar.create(BigInt('0x' + signaturesFixture[i].signerKeyPair.secretKey));
                const signature = bbs.Sign(SK, PK, header, msg, generators);
                const actualSignature = bytesToHex(signature);
                if (actualSignature != signaturesFixture[i].signature) {
                    throw `invalid signature ${i}; expected: ${signaturesFixture[i].signature}, actual: ${actualSignature}`;
                }

                bbs.Verify(PK, hexToBytes(signaturesFixture[i].signature), header, msg, generators);
            } else {
                // validation of the non-valid signature should fail
                let failed = false;
                try {
                    bbs.Verify(PK, hexToBytes(signaturesFixture[i].signature), header, msg, generators);
                } catch (e) {
                    failed = true;
                }
                if (!failed) throw `signature ${i} should be invalid`;
            }
        })
    };

    for (let i = 0; i < proofsFixture.length; i++) {
        test(`proof${String(i + 1).padStart(3, '0')}: ${proofsFixture[i].caseName} (${cs})`, async () => {
            const disclosed_indexes = proofsFixture[i].disclosedIndexes;
            const disclosed_messages = proofsFixture[i].messages.filter((v,i,a) => disclosed_indexes.includes(i)).map(v => bbs.MapMessageToScalarAsHash(hexToBytes(v)));

            let failed = false;
            try {
                // TODO: implement the proof generation too, now that we have mockup random values
                bbs.ProofVerify(
                    bbs.octets_to_pubkey(hexToBytes(proofsFixture[i].signerPublicKey)),
                    hexToBytes(proofsFixture[i].proof),
                    hexToBytes(proofsFixture[i].header),
                    hexToBytes(proofsFixture[i].presentationHeader),
                    disclosed_messages,
                    generators,
                    disclosed_indexes);
            } catch (e) {
                failed = true;
            }
            if (proofsFixture[i].result.valid && failed) throw `proof ${i + 1} should have been valid`; // proof files suffix are 1-based
        })
    };
});