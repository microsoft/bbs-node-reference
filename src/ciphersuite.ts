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
    hash_to_curve_g1 = async (input: Uint8Array, dst: string) => {
        return G1Point.hashToCurve(input, dst);
    }
    expand_len = 48; // ceil((ceil(log2(r)) + k)/8)
    expand_message: (message: Uint8Array, dst: Uint8Array, len: number) => Uint8Array;

    constructor(cipherSuiteBaseId: string, P1: G1Point, expand_message: (message: Uint8Array, dst: Uint8Array, len: number) => Uint8Array) {
        this.ciphersuite_id = cipherSuiteBaseId + "H2G_HM2S_";
        this.hash_to_curve_suite = cipherSuiteBaseId;
        this.P1 = P1;
        this.generator_seed = Buffer.from(this.ciphersuite_id + "MESSAGE_GENERATOR_SEED", 'utf-8');
        this.expand_message = expand_message;
    }
}

export const BLS12_381_SHA256_Ciphersuite = new Ciphersuite(
    "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_", 
    G1Point.fromOctets(hexToBytes("a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9")),
    expand_message_xmd
);

export const BLS12_381_SHAKE_256_Ciphersuite = new Ciphersuite(
    "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_",
    G1Point.fromOctets(hexToBytes("8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755")),
    expand_message_xof
);
