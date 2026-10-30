// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { BBS } from '../src/bbs';
import * as crypto from 'crypto';
import * as utils from '../src/utils';
import { BLS12_381_SHA256_Ciphersuite, BLS12_381_SHAKE_256_Ciphersuite } from '../src/ciphersuite';

const ciphersuites = [BLS12_381_SHAKE_256_Ciphersuite, BLS12_381_SHA256_Ciphersuite];

ciphersuites.forEach(cs => {
    test("End-to-end test: " + cs.ciphersuite_id, async () => {
        const bbs = new BBS(cs);

        // generate random issuer keys
        const SK = bbs.KeyGen(crypto.randomBytes(32));
        const PK = bbs.SkToPk(SK);

        // create the generators
        const length = 5;
        const generators = await bbs.create_generators(length);

        // create random messages
        let msg = Array(length).fill(null).map(v => bbs.MapMessageToScalarAsHash(crypto.randomBytes(20)));

        // create the signature
        const header = Buffer.from("HEADER", "utf-8");
        const signature = bbs.Sign(SK, PK, header, msg, generators);

        // validate the signature
        bbs.Verify(PK, signature, header, msg, generators);

        // randomly disclose each message
        const disclosed_indexes = Array(length).fill(0).map((v, i, a) => i ).filter(v => { return Math.random() > 0.5; }); // random coin flip for each message
        const ph = Buffer.from("PRESENTATION HEADER", "utf-8");

        const proof = bbs.ProofGen(PK, signature, header, ph, msg, generators, disclosed_indexes);
        const disclosed_msg = utils.filterDisclosedMessages(msg, disclosed_indexes);

        bbs.ProofVerify(PK, proof, header, ph, disclosed_msg, generators, disclosed_indexes);
    });

    test("Header-only signature (zero messages): " + cs.ciphersuite_id, async () => {
        const bbs = new BBS(cs);
        const SK = bbs.KeyGen(crypto.randomBytes(32));
        const PK = bbs.SkToPk(SK);
        const generators = await bbs.create_generators(0);
        const header = Buffer.from("HEADER", "utf-8");
        const signature = bbs.Sign(SK, PK, header, [], generators);
        bbs.Verify(PK, signature, header, [], generators);

        const ph = Buffer.from("PRESENTATION HEADER", "utf-8");
        const proof = bbs.ProofGen(PK, signature, header, ph, [], generators, []);
        bbs.ProofVerify(PK, proof, header, ph, [], generators, []);

        // the signature is bound to the header
        expect(() => bbs.Verify(PK, signature, Buffer.from("OTHER", "utf-8"), [], generators)).toThrow();
        expect(() => bbs.ProofVerify(PK, proof, Buffer.from("OTHER", "utf-8"), ph, [], generators, [])).toThrow();
    });

    test("Invalid disclosed indexes are rejected: " + cs.ciphersuite_id, async () => {
        const bbs = new BBS(cs);
        const SK = bbs.KeyGen(crypto.randomBytes(32));
        const PK = bbs.SkToPk(SK);
        const length = 5;
        const generators = await bbs.create_generators(length);
        const msg = Array(length).fill(null).map(v => bbs.MapMessageToScalarAsHash(crypto.randomBytes(20)));
        const header = Buffer.from("HEADER", "utf-8");
        const ph = Buffer.from("PRESENTATION HEADER", "utf-8");
        const signature = bbs.Sign(SK, PK, header, msg, generators);

        const invalid_indexes = [
            [0, 5],             // out of range
            [-1],               // negative
            [1.5],              // not an integer
            [1, 1],             // duplicate
            [3, 1],             // not ascending
            [0, 1, 2, 3, 4, 4], // more indexes than messages
        ];
        invalid_indexes.forEach(idx => {
            expect(() => bbs.ProofGen(PK, signature, header, ph, msg, generators, idx)).toThrow();
        });

        const disclosed_indexes = [1, 3];
        const proof = bbs.ProofGen(PK, signature, header, ph, msg, generators, disclosed_indexes);
        const disclosed_msg = utils.filterDisclosedMessages(msg, disclosed_indexes);
        bbs.ProofVerify(PK, proof, header, ph, disclosed_msg, generators, disclosed_indexes);
        expect(() => bbs.ProofVerify(PK, proof, header, ph, disclosed_msg, generators, [3, 1])).toThrow("ascending");
        expect(() => bbs.ProofVerify(PK, proof, header, ph, disclosed_msg, generators, [1, 5])).toThrow("out of range");
        expect(() => bbs.ProofVerify(PK, proof, header, ph, disclosed_msg, generators, [1, 1])).toThrow("ascending");
        expect(() => bbs.ProofVerify(PK, proof, header, ph, disclosed_msg.slice(1), generators, disclosed_indexes)).toThrow("same length");

        // extra generators are accepted and trimmed
        const more_generators = await bbs.create_generators(length + 3);
        bbs.ProofVerify(PK, proof, header, ph, disclosed_msg, more_generators, disclosed_indexes);
    });

    test("multi_exponentiation_g1 rejects mismatched or empty inputs: " + cs.ciphersuite_id, () => {
        const bbs = new BBS(cs);
        const s = bbs.MapMessageToScalarAsHash(crypto.randomBytes(20));
        expect(() => bbs.multi_exponentiation_g1([], [])).toThrow();
        expect(() => bbs.multi_exponentiation_g1([cs.P1], [s, s])).toThrow();
        expect(bbs.multi_exponentiation_g1([cs.P1, cs.P1], [s, s]).equals(cs.P1.mul(s.add(s)))).toBe(true);
    });
});


