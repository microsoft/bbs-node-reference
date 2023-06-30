// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { G1Point } from './math';
import { hexToBytes, expand_message_xmd } from './utils';

export interface Ciphersuite {
    ciphersuite_id: string,
    octet_scalar_length: number,
    octet_point_length: number,
    hash_to_curve_suite: string,
    P1: G1Point,
    generator_seed: Uint8Array,
    hash_to_curve_g1: (input: Uint8Array) => Promise<G1Point>,
    hash_to_curve_g1_dst: Uint8Array,
    seed_len: number,  // ceil((ceil(log2(r)) + k)/8)
    expand_len: number, // ceil((ceil(log2(r)) + k)/8)
    expand_message: (message: Uint8Array, dst: Uint8Array, len: number) => Uint8Array
}

export const BLS12_381_SHA256_Ciphersuite: Ciphersuite = {
    ciphersuite_id: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_",
    octet_scalar_length: 32,
    octet_point_length: 48,
    hash_to_curve_suite: "BLS12381G1_XMD:SHA-256_SSWU_RO_",
    P1: G1Point.fromOctets(hexToBytes("864df3ae75a023852b577c6aa46d1608d7bfb73c59c73dfd47250ea01c04ec1ad20560e8e4aca82296ca7c4e1b7c3620")),
    generator_seed: Buffer.from("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_MESSAGE_GENERATOR_SEED", 'utf-8'),
    hash_to_curve_g1: async (input: Uint8Array) => {
        return G1Point.hashToCurve(input, BLS12_381_SHA256_Ciphersuite.ciphersuite_id + "SIG_GENERATOR_DST_");
    },
    hash_to_curve_g1_dst: Buffer.from("BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO", 'utf-8'),
    seed_len: 48,
    expand_len: 48,
    expand_message: expand_message_xmd
}

// TODO: implement the BLS12-381-SHAKE-256 ciphersuite