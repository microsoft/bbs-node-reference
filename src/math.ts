// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// implement the math using the bls library

import { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { bls12_381 as bls } from '@noble/curves/bls12-381';

// unexported types from bls
type Fp = bigint;
type Fp2 = { c0: bigint; c1: bigint };
type Fp6 = { c0: Fp2; c1: Fp2; c2: Fp2 };
type Fp12 = { c0: Fp6; c1: Fp6 };

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
        return new G1Point(bls.G1.ProjectivePoint.fromHex(bytes)); // fromHex takes bytes...
    }
    static async hashToCurve(msg: Uint8Array, dst: string): Promise<G1Point> {
        const candidate = await bls.G1.hashToCurve(msg, { DST: dst });
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
        return new G2Point(bls.G2.ProjectivePoint.fromHex(bytes)); // fromHex takes bytes...
    }
    static subgroup_check(a: G2Point): boolean {
        try {
            a.point.assertValidity();
            return true; // valid point
        } catch (e) {
            return false; // invalid point
        }
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

    toBytes(): Uint8Array {
        return FrScalar.blsFr.toBytes(this.scalar);
    }
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
    static create(scalar: bigint, nonZero: boolean = false) {
        if (nonZero && scalar === 0n) throw new Error("scalar is 0");
        return new FrScalar(FrScalar.blsFr.create(scalar));
    }

}