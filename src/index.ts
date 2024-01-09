// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { BBS } from './bbs';
import * as crypto from 'crypto';
import * as utils from './utils';

void (async () => {
    try {
        const bbs = new BBS();

        // generate issuer keys
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
        const disclosed_indexes = Array(length).fill(0).map((v, i, a) => i).filter(v => { return Math.random() > 0.5; }); // random coin flip for each message
        const ph = Buffer.from("PRESENTATION HEADER", "utf-8");

        const proof = bbs.ProofGen(PK, signature, header, ph, msg, generators, disclosed_indexes);
        const disclosed_msg = utils.filterDisclosedMessages(msg, disclosed_indexes);

        bbs.ProofVerify(PK, proof, header, ph, disclosed_msg, generators, disclosed_indexes);

        console.log("Success");
    }
    catch (e) {
        console.log(e);
    }
})();