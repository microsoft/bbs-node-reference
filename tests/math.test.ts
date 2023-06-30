// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { FrScalar, G1Point, G2Point } from "../src/math";

test("G1 tests", async () => {
    const I = G1Point.Identity;
    const P = await G1Point.hashToCurve(Buffer.from("test msg"), "test dst");

    // identity and commutativity tests
    expect(P.add(I).equals(P)).toBe(true);
    expect(I.add(P).equals(P)).toBe(true);

    // scalar multiplication
    const five = FrScalar.create(5n);
    expect(P.mul(five).equals(P.add(P).add(P).add(P).add(P))).toBe(true);

    // serialization tests
    expect(G1Point.fromOctets(P.toOctets()).equals(P)).toBe(true);
});

// G2 tests
test("G2 tests", async () => {
    const I = G2Point.Identity;
    const P = G2Point.Base;

    // identity and commutativity tests
    expect(P.add(I).equals(P)).toBe(true);
    expect(I.add(P).equals(P)).toBe(true);

    // scalar multiplication
    const five = FrScalar.create(5n);
    expect(P.mul(five).equals(P.add(P).add(P).add(P).add(P))).toBe(true);

    // serialization tests
    expect(G2Point.fromOctets(P.toOctets()).equals(P)).toBe(true);
});

// TODO: pairing tests

// FrScalar tests
test("FrScalar tests", async () => {
    const zero = FrScalar.Zero;
    expect(zero.equals(FrScalar.create(0n))).toBe(true);
    const one = FrScalar.create(1n);

    expect(() => FrScalar.create(0n, true)).toThrow();

    // addition tests
    const bn = 1234567890n;
    const n = FrScalar.create(bn);
    expect(n.add(zero).equals(n)).toBe(true);
    expect(zero.add(n).equals(n)).toBe(true);
    expect(n.add(one).equals(FrScalar.create(bn + 1n))).toBe(true);

    // negation tests
    expect(n.neg().equals(FrScalar.create(-bn))).toBe(true);
    expect(zero.neg().equals(zero)).toBe(true);

    // multiplication tests
    expect(n.mul(zero).equals(zero)).toBe(true);
    expect(n.mul(one).equals(n)).toBe(true);
    expect(one.mul(n).equals(n)).toBe(true);
    expect(n.mul(FrScalar.create(2n)).equals(FrScalar.create(bn * 2n))).toBe(true);

    // inverse tests
    expect(one.inv().equals(one)).toBe(true);
    expect(n.inv().mul(n).equals(one)).toBe(true);
});