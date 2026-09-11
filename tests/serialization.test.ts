// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Deserialization must reject non-canonical encodings, otherwise a single
// signature or proof has several distinct valid encodings.

import { BBS } from '../src/bbs';
import * as crypto from 'crypto';
import * as utils from '../src/utils';
import { FrScalar } from '../src/math';
import { BLS12_381_SHA256_Ciphersuite, BLS12_381_SHAKE_256_Ciphersuite } from '../src/ciphersuite';

const ciphersuites = [BLS12_381_SHAKE_256_Ciphersuite, BLS12_381_SHA256_Ciphersuite];

// returns a copy of octets with the metadata byte of the point starting at offset
// replaced by m_byte (the three most significant bits of the first octet)
function setPointFlags(octets: Uint8Array, offset: number, m_byte: number): Uint8Array {
    const result = new Uint8Array(octets);
    result[offset] = (result[offset] & 0x1f) | m_byte;
    return result;
}

// returns a copy of octets with r added to the scalar starting at offset; the
// result is a different octet string encoding the same value modulo r
function addOrderToScalar(octets: Uint8Array, offset: number, length: number): Uint8Array {
    const scalar = utils.os2ip(octets.slice(offset, offset + length)).scalar;
    const shifted = scalar + FrScalar.blsFr.ORDER;
    return utils.concat(
        octets.slice(0, offset),
        utils.i2osp(shifted, length),
        octets.slice(offset + length));
}

ciphersuites.forEach(cs => {
    describe("Deserialization tests: " + cs.ciphersuite_id, () => {
        const bbs = new BBS(cs);
        const header = Buffer.from("HEADER", "utf-8");
        const ph = Buffer.from("PRESENTATION HEADER", "utf-8");
        const L = 3;
        const disclosed_indexes = [0, 2];

        let signature: Uint8Array;
        let proof: Uint8Array;

        beforeAll(async () => {
            const SK = bbs.KeyGen(crypto.randomBytes(32));
            const PK = bbs.SkToPk(SK);
            const generators = await bbs.create_generators(L);
            const msg = Array(L).fill(null).map(() => bbs.MapMessageToScalarAsHash(crypto.randomBytes(20)));

            signature = bbs.Sign(SK, PK, header, msg, generators);
            bbs.Verify(PK, signature, header, msg, generators);

            proof = bbs.ProofGen(PK, signature, header, ph, msg, generators, disclosed_indexes);
            bbs.ProofVerify(PK, proof, header, ph, utils.filterDisclosedMessages(msg, disclosed_indexes), generators, disclosed_indexes);
        });

        // Appendix B.2.1: points are always serialized compressed, so C_bit is always 1
        test("signatures are serialized with the C_bit set", () => {
            expect(signature[0] & 0x80).toBe(0x80);
            for (let k = 0; k < 3; k++) {
                expect(proof[k * cs.octet_point_length] & 0x80).toBe(0x80);
            }
        });

        // Appendix B.2.2: "If C_bit is 0 return INVALID and abort the operation".
        // Without this check, clearing that one bit yields a second, different
        // signature that still verifies.
        test("clearing the C_bit of A must not yield a second valid signature", () => {
            const mangled = setPointFlags(signature, 0, 0x00);
            expect(mangled).not.toEqual(signature);
            expect(() => bbs.octets_to_signature(mangled)).toThrow();
        });

        test("clearing the C_bit of a proof point must not yield a second valid proof", () => {
            for (let k = 0; k < 3; k++) {
                const mangled = setPointFlags(proof, k * cs.octet_point_length, 0x00);
                expect(mangled).not.toEqual(proof);
                expect(() => bbs.octets_to_proof(mangled)).toThrow();
            }
        });

        // Appendix B.2.2: "If m_byte equals 0x20 or 0x60 or 0xE0, output INVALID"
        [0x20, 0x60, 0xe0].forEach(m_byte => {
            test("m_byte 0x" + m_byte.toString(16) + " must be rejected", () => {
                expect(() => bbs.octets_to_signature(setPointFlags(signature, 0, m_byte))).toThrow();
                expect(() => bbs.octets_to_proof(setPointFlags(proof, 0, m_byte))).toThrow();
            });
        });

        // Appendix B.2.2 step 3: when I_bit is set, the encoding must be the all
        // zeros string; 0x40 additionally has C_bit unset
        [0x40, 0xc0].forEach(m_byte => {
            test("m_byte 0x" + m_byte.toString(16) + " over a non-zero x must be rejected", () => {
                expect(() => bbs.octets_to_signature(setPointFlags(signature, 0, m_byte))).toThrow();
                expect(() => bbs.octets_to_proof(setPointFlags(proof, 0, m_byte))).toThrow();
            });
        });

        // octets_to_signature step 6 and octets_to_proof step 7: the identity point
        // is not an acceptable value, even when canonically encoded
        test("the identity point must be rejected", () => {
            const identity = utils.concat(new Uint8Array([0xc0]), new Uint8Array(cs.octet_point_length - 1));
            expect(() => bbs.octets_to_signature(
                utils.concat(identity, signature.slice(cs.octet_point_length)))).toThrow();
            for (let k = 0; k < 3; k++) {
                const offset = k * cs.octet_point_length;
                expect(() => bbs.octets_to_proof(utils.concat(
                    proof.slice(0, offset),
                    identity,
                    proof.slice(offset + cs.octet_point_length)))).toThrow();
            }
        });

        // octets_to_signature step 11: "if e = 0 or e >= r, return INVALID".
        // e and e + r both fit in octet_scalar_length octets, so silently reducing
        // mod r would again yield a second valid signature.
        test("a signature with e >= r must be rejected", () => {
            const mangled = addOrderToScalar(signature, cs.octet_point_length, cs.octet_scalar_length);
            expect(mangled).not.toEqual(signature);
            expect(mangled.length).toBe(signature.length);
            expect(() => bbs.octets_to_signature(mangled)).toThrow();
        });

        // octets_to_proof step 14: "if s_j = 0 or if s_j >= r, return INVALID"
        test("a proof with a scalar >= r must be rejected", () => {
            const scalar_count = (proof.length - 3 * cs.octet_point_length) / cs.octet_scalar_length;
            for (let k = 0; k < scalar_count; k++) {
                const offset = 3 * cs.octet_point_length + k * cs.octet_scalar_length;
                const mangled = addOrderToScalar(proof, offset, cs.octet_scalar_length);
                expect(mangled).not.toEqual(proof);
                expect(() => bbs.octets_to_proof(mangled)).toThrow();
            }
        });

        // octets_to_proof steps 1, 2 and 17
        test("a proof whose length is not a valid proof length must be rejected", () => {
            expect(() => bbs.octets_to_proof(proof.slice(0, proof.length - 1))).toThrow();
            expect(() => bbs.octets_to_proof(utils.concat(proof, new Uint8Array(1)))).toThrow();
            expect(() => bbs.octets_to_proof(proof.slice(0, 3 * cs.octet_point_length + 3 * cs.octet_scalar_length))).toThrow();
        });

        test("a signature whose length is wrong must be rejected", () => {
            expect(() => bbs.octets_to_signature(signature.slice(0, signature.length - 1))).toThrow();
            expect(() => bbs.octets_to_signature(utils.concat(signature, new Uint8Array(1)))).toThrow();
        });

        // the round trip of a well-formed value must still work
        test("valid signatures and proofs still deserialize", () => {
            expect(() => bbs.octets_to_signature(signature)).not.toThrow();
            expect(() => bbs.octets_to_proof(proof)).not.toThrow();
        });
    });
});
