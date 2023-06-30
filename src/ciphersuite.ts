// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { G1Point } from './math';
import { hexToBytes, expand_message_xmd, expand_message_xof } from './utils';

export class Ciphersuite {
    ciphersuite_id: string;
    octet_scalar_length = 32;
    octet_point_length = 48;
    hash_to_curve_suite: string;
    P1: G1Point;
    generator_seed: Uint8Array;
    hash_to_curve_g1 = async (input: Uint8Array) => {
        return G1Point.hashToCurve(input, this.ciphersuite_id + "SIG_GENERATOR_DST_");
    }
    seed_len = 48;  // ceil((ceil(log2(r)) + k)/8)
    expand_len = 48; // ceil((ceil(log2(r)) + k)/8)
    expand_message: (message: Uint8Array, dst: Uint8Array, len: number) => Uint8Array;

    constructor(cipherSuiteBaseId: string, P1: G1Point, expand_message: (message: Uint8Array, dst: Uint8Array, len: number) => Uint8Array) {
        this.ciphersuite_id = cipherSuiteBaseId + "H2G_";
        this.hash_to_curve_suite = cipherSuiteBaseId;
        this.P1 = P1;
        this.generator_seed = Buffer.from(this.ciphersuite_id + "MESSAGE_GENERATOR_SEED", 'utf-8');
        this.expand_message = expand_message;
    }
}

export const BLS12_381_SHA256_Ciphersuite = new Ciphersuite(
    "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_", 
    G1Point.fromOctets(hexToBytes("864df3ae75a023852b577c6aa46d1608d7bfb73c59c73dfd47250ea01c04ec1ad20560e8e4aca82296ca7c4e1b7c3620")),
    expand_message_xmd
);

export const BLS12_381_SHAKE_256_Ciphersuite = new Ciphersuite(
    "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_",
    G1Point.fromOctets(hexToBytes("8fbd0548aada70863646feef018a867981b85ab22efb80a314dc96a4efaeaeef2e40f0d40524a0dcf5ae8fe5777d6d93")),
    expand_message_xof
);
