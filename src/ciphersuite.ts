// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as crypto from 'crypto';
import { G1Point, G2Point } from './math';
import { hexToBytes, concatBytes, i2osp, strxor } from './utils';

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
    // implements https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14#section-8.8.1
    hash_to_curve_g1: async (input: Uint8Array) => {
        return G1Point.hashToCurve(input, BLS12_381_SHA256_Ciphersuite.ciphersuite_id + "SIG_GENERATOR_DST_");
    },
    hash_to_curve_g1_dst: Buffer.from("BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO", 'utf-8'),
    seed_len: 48,
    expand_len: 48,
    // expand_message_xmd
    expand_message: expand_message_xmd
}

// Produces a uniformly random byte string using a cryptographic hash function H that outputs b bits
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4.1
function expand_message_xmd(
    msg: Uint8Array,
    DST: Uint8Array,
    lenInBytes: number
): Uint8Array {
    const H = (data: Uint8Array) => {
        return crypto.createHash('sha256').update(data).digest()
    }
    const b_in_bytes = 32; // SHA256_DIGEST_SIZE;
    const r_in_bytes = b_in_bytes * 2;

    const ell = Math.ceil(lenInBytes / b_in_bytes);
    if (ell > 255) throw new Error('Invalid xmd length');
    const DST_prime = concatBytes(DST, i2osp(DST.length, 1));
    const Z_pad = i2osp(0, r_in_bytes);
    const l_i_b_str = i2osp(lenInBytes, 2);
    const b = new Array<Uint8Array>(ell);
    const b_0 = H(concatBytes(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
    b[0] = H(concatBytes(b_0, i2osp(1, 1), DST_prime));
    for (let i = 1; i <= ell; i++) {
        const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
        b[i] = H(concatBytes(...args));
    }
    const pseudo_random_bytes = concatBytes(...b);
    return pseudo_random_bytes.slice(0, lenInBytes);
}


// TODO: implement the BLS12-381-SHAKE-256 ciphersuite