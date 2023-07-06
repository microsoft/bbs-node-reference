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
        const disclosed_indexes = Array(length).fill(0).map((v, i, a) => i + 1).filter(v => { return Math.random() > 0.5; }); // random coin flip for each message
        const ph = Buffer.from("PRESENTATION HEADER", "utf-8");

        const proof = bbs.ProofGen(PK, signature, header, ph, msg, generators, disclosed_indexes);
        const disclosed_msg = utils.filterDisclosedMessages(msg, disclosed_indexes);

        bbs.ProofVerify(PK, proof, header, ph, disclosed_msg, generators, disclosed_indexes);
    });
});


