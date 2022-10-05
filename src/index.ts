import { BBS } from './bbs';
import * as crypto from 'crypto';
import * as utils from './utils';

try {
    const bbs = new BBS();

    // generate issuer keys
    const SK = bbs.KeyGen(crypto.randomBytes(32));
    const PK = bbs.SkToPk(SK);
    console.log("PK: " + PK);

    // create the generators
    const length = 5;
    let msg = Array(length).fill(null).map(v => crypto.randomBytes(20));
    const message_generator_seed = Buffer.from("MESSAGE GENERATOR SEED", "utf-8");
    const dst = Buffer.from("TEST", "utf-8");
    const generators = bbs.CreateGenerators(dst, message_generator_seed, length);

    // create the signature
    const header = Buffer.from("HEADER", "utf-8");
    const signature = bbs.Sign(SK, PK, header, msg, generators);

    // validate the signature
    bbs.Verify(PK, signature, header, msg, generators);

    // randomly disclose each message
    const disclosed_indexes = Array(length).fill(0).map((v,i,a) => i+1).filter(v => {return Math.random() > 0.5;}); // random coin flip for each message
    const ph = Buffer.from("PRESENTATION HEADER", "utf-8");

    const proof = bbs.ProofGen(PK, signature, header, ph, msg, generators, disclosed_indexes);
    const disclosed_msg = utils.filterDisclosedMessages(msg, disclosed_indexes);

    bbs.ProofVerify(PK, proof, header, ph, disclosed_msg, generators, disclosed_indexes);

    console.log("Success");
}
catch (e) {
    console.log(e);
}