import * as bls from '@noble/bls12-381';
import { Hash, XOF } from './hash';
import { PointG1, PointG2, Fr, utils, Fp2, Fp } from "@noble/bls12-381";
import { bytesToHex, hexToBytes } from './utils';

export interface Ciphersuite {
    Ciphersuite_ID: string,
    octet_scalar_length: number,
    octet_point_length: number,
    hash_to_curve_suite: string,
    P1: PointG1,
    generator_seed: Uint8Array,
    createHash: () => Hash,
    createXOF: () => XOF,
    point_to_octets_g1: (P: PointG1) => Uint8Array,
    point_to_octets_g2: (P: PointG2) => Uint8Array,
    octets_to_point_g1: (ostr: Uint8Array) => PointG1,
    octets_to_point_g2: (ostr: Uint8Array) => PointG2,
    hash_to_curve_g1: (input: Uint8Array) => Promise<PointG1>,
    hash_to_curve_g1_dst: Uint8Array,
    hash_to_field: (input: Uint8Array) => Fr,
    hash_to_field_dst: Uint8Array,
    message_generator_seed: Uint8Array,
    blind_value_generator_seed: Uint8Array,
    signature_dst_generator_seed: Uint8Array,
    xof_no_of_bytes: number,
}

  
export const BLS12_381_SHA256_Ciphersuite: Ciphersuite = {
    Ciphersuite_ID: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_",
    octet_scalar_length: 32,
    octet_point_length: 48,
    hash_to_curve_suite: "BLS12381G1_XMD:SHA-256_SSWU_RO_",
    P1: PointG1.fromHex(hexToBytes("ad98180923a716ac626a3f7e7ffd3faa71820074bb7ae221fd01c406a6a5636540ef3a3e18b21619a3bdff69e81d5da7")),
    generator_seed: Buffer.from("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_MESSAGE_GENERATOR_SEED",'utf-8'),
    createHash: () => new Hash(),
    createXOF: () => new XOF(),
    point_to_octets_g1: (P: PointG1) => {
        const compressed = true;
        const serialized = P.toRawBytes(compressed);
        return serialized;
    },
    point_to_octets_g2: (P: PointG2) => {
        const compressed = true;
        const serialized = P.toRawBytes(compressed);
        return serialized;
    },
    octets_to_point_g1: (ostr: Uint8Array) => {
        const P = bls.PointG1.fromHex(bytesToHex(ostr));
        return P;
    },
    octets_to_point_g2: (ostr: Uint8Array) => {
        const P = bls.PointG2.fromHex(bytesToHex(ostr));
        return P;
    },
    // implements https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14#section-8.8.1
    hash_to_curve_g1: async (input: Uint8Array) => {
        // the noble library only implements hash to G2, so we need to implement hash to G1 here

        const u = await utils.hashToField(input, 2, 
            // params from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-14#section-8.8.1
            {
                DST: 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_', // TODO: change to this.hash_to_curve_g1_dst 
                p: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn,
                m: 1,
                k: 128,
                expand: true, // use expand_message_xmd
            })
        //console.log(`hash_to_curve(msg}) u0=${new Fp2(u[0])} u1=${new Fp2(u[1])}`);
        // TODO: https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-14.html#section-6.6.3-7
        // do this, from the spec? Note that iso_map is a group homomorphism, meaning that point addition commutes with iso_map. Thus, when using this mapping in the hash_to_curve construction of Section 3, one can effect a small optimization by first mapping u0 and u1 to E', adding the resulting points on E', and then applying iso_map to the sum. This gives the same result while requiring only one evaluation of iso_map.
        const Q0 = PointG1.BASE;// new PointG1(...isogenyMapG1(map_to_curve_simple_swu(u[0])));
        const Q1 = PointG1.BASE;// new PointG1(...isogenyMapG1(map_to_curve_simple_swu(u[1])));
        const R = Q0.add(Q1);
        const P = R.clearCofactor();
        //console.log(`hash_to_curve(msg) Q0=${Q0}, Q1=${Q1}, R=${R} P=${P}`);
        return P;
    },
    hash_to_curve_g1_dst: Buffer.from("BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO",'utf-8'),
    hash_to_field: (input: Uint8Array) => {return Fr.ONE},
    hash_to_field_dst: Buffer.from("DEFAULT DST",'utf-8'),
    message_generator_seed: Buffer.from("DEFAULT SEED",'utf-8'),
    blind_value_generator_seed: Buffer.from("DEFAULT SEED",'utf-8'),
    signature_dst_generator_seed: Buffer.from("DEFAULT SEED",'utf-8'),
    xof_no_of_bytes: 64
}

// Note: we don't currently support the BLS12-381-SHAKE-256 ciphersuite because the underlying BLS library doesn't support SHAKE