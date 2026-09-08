// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// implement the math using the bls library

import { doWhileStatement } from '@babel/types';
import { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { shake256 } from '@noble/hashes/sha3';

// unexported types from bls
type Fp = bigint;
type Fp2 = { c0: bigint; c1: bigint };
type Fp6 = { c0: Fp2; c1: Fp2; c2: Fp2 };
type Fp12 = { c0: Fp6; c1: Fp6 };

// Validates the C_bit/I_bit/S_bit metadata byte of a serialized point, per
// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-point-de-serialization
// The bls library doesn't check the C_bit of E1 points, nor that an encoding
// flagged with I_bit is the all-zeros string; without these checks, clearing
// the C_bit of a signature or proof yields a second, distinct, valid encoding.
function checkPointOctets(bytes: Uint8Array, expected_length: number): void {
    if (bytes.length !== expected_length) {
        throw new Error("invalid point length");
    }
    const m_byte = bytes[0] & 0xe0;
    if (m_byte === 0x20 || m_byte === 0x60 || m_byte === 0xe0) {
        throw new Error("invalid point encoding flag");
    }
    if ((m_byte & 0x80) === 0) {
        throw new Error("invalid point encoding: only compressed points are supported");
    }
    if ((m_byte & 0x40) !== 0 && bytes.some((b, i) => b !== (i === 0 ? 0xc0 : 0))) {
        // I_bit is set, so the encoding must be the identity point
        throw new Error("invalid identity point encoding");
    }
}

// abstract point class
export class Point<T, U extends Point<T, U>> {
    point: ProjPointType<T>;
    constructor(point: ProjPointType<T>) {
        this.point = point;
    }
    toOctets(): Uint8Array {
        return this.point.toRawBytes(true /* compressed */);
    }
    mul(s: FrScalar): U {
        return new Point<T, U>(this.point.multiply(s.scalar)) as U;
    }
    add(p: U): U {
        return new Point<T, U>(this.point.add(p.point)) as U;
    }
    neg(): U {
        return new Point<T, U>(this.point.negate()) as U;
    }
    equals(p: U): boolean {
        return this.point.equals(p.point);
    }
}

// G1 point
export class G1Point extends Point<Fp, G1Point> {
    constructor(point: ProjPointType<Fp>) {
        super(point);
    }
    static Identity = new G1Point(bls.G1.ProjectivePoint.ZERO);
    static fromOctets(bytes: Uint8Array): G1Point {
        checkPointOctets(bytes, 48);
        return new G1Point(bls.G1.ProjectivePoint.fromHex(bytes)); // fromHex takes bytes...
    }
    static async hashToCurve(msg: Uint8Array, dst: string): Promise<G1Point> {
        let options;
        if (dst.includes('SHAKE')) {
            // TODO: this is unclear in the spec, but matches the fixtures
            options = {  DST: dst, expand: 'xof', hash: shake256 } as any;
        } else {
            options = { DST: dst };
        }
        const candidate = await bls.G1.hashToCurve(msg, options);
        return new G1Point(candidate as ProjPointType<bigint>);
    }
}

// G2 point
export class G2Point extends Point<Fp2, G2Point> {
    constructor(point: ProjPointType<Fp2>) {
        super(point);
    }
    static Identity = new G2Point(bls.G2.ProjectivePoint.ZERO);
    static Base = new G2Point(bls.G2.ProjectivePoint.BASE);
    static fromOctets(bytes: Uint8Array, subgroupCheck = false): G2Point {
        // note: we ignore the subgroupCheck parameter, because the bls library fromHex function
        // always checks the subgroup membership
        checkPointOctets(bytes, 96);
        return new G2Point(bls.G2.ProjectivePoint.fromHex(bytes)); // fromHex takes bytes...
    }
}

// checks that e(pointG1_1, pointG2_1) * e(pointG1_2, pointG2_2) = GT_Identity
export function checkPairingIsIdentity(pointG1_1: G1Point, pointG2_1: G2Point, pointG1_2: G1Point, pointG2_2: G2Point): boolean {
    // (using the pairing optimization to skip final exponentiation in the pairing
    // and do it after the multiplication)
    const lh = bls.pairing(pointG1_1.point, pointG2_1.point, false);
    const rh = bls.pairing(pointG1_2.point, pointG2_2.point, false);
    let result = bls.fields.Fp12.mul(lh, rh);
    // note: bls12-381 has a final exponentiate function, but it's not visible
    result = (bls.fields.Fp12 as unknown as { finalExponentiate(f: Fp12): Fp12; }).finalExponentiate(result);
    return bls.fields.Fp12.eql(result, bls.fields.Fp12.ONE);
}

// scalar field of order r
export class FrScalar {
    static blsFr = bls.fields.Fr;

    scalar: bigint;
    private constructor(scalar: bigint) {
        this.scalar = FrScalar.blsFr.create(scalar);
    }
    static Zero = new FrScalar(0n);

    mul(s: FrScalar): FrScalar {
        return new FrScalar(FrScalar.blsFr.mul(this.scalar, s.scalar));
    }
    inv(): FrScalar {
        return new FrScalar(FrScalar.blsFr.inv(this.scalar));
    }
    add(s: FrScalar): FrScalar {
        return new FrScalar(FrScalar.blsFr.add(this.scalar, s.scalar));
    }
    neg(): FrScalar {
        return new FrScalar(FrScalar.blsFr.neg(this.scalar));
    }
    equals(s: FrScalar): boolean {
        return this.scalar === s.scalar;
    }
    // when canonical is set, the value MUST already be a scalar in the range [1, r-1];
    // deserialization operations require this (e.g., octets_to_signature step 11), since
    // silently reducing mod r would make s and s + r two valid encodings of the same value.
    // Otherwise the value is reduced mod r (used when deriving scalars from uniform bytes).
    static create(scalar: bigint, canonical: boolean = false) {
        if (canonical && (scalar <= 0n || scalar >= FrScalar.blsFr.ORDER)) {
            throw new Error("scalar is not in the range [1, r-1]");
        }
        return new FrScalar(FrScalar.blsFr.create(scalar));
    }

}