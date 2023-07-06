// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { FrScalar } from "./math";
import * as utils from '@noble/curves/abstract/utils';
import * as hash from '@noble/curves/abstract/hash-to-curve';
import {sha256} from '@noble/hashes/sha256';
import {shake256} from '@noble/hashes/sha3';

// Octet Stream to Integer
export function os2ip(bytes: Uint8Array, nonZero: boolean = false): FrScalar {
  return FrScalar.create(utils.bytesToNumberBE(bytes), nonZero);
}

// Integer to Octet Stream
export function i2osp(value: number | bigint, length: number): Uint8Array {
  return utils.numberToBytesBE(value, length);
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
  return utils.concatBytes(...arrays);
}

export function expand_message_xmd(msg: Uint8Array, DST: Uint8Array, len_in_bytes: number): Uint8Array {
  return hash.expand_message_xmd(msg, DST, len_in_bytes, sha256);
}

export function expand_message_xof(msg: Uint8Array, DST: Uint8Array, len_in_bytes: number): Uint8Array {
  return hash.expand_message_xof(msg, DST, len_in_bytes, 128, shake256); // TODO: is k = 128 the right value?
}

export function hexToBytes(hex: string): Uint8Array {
  return utils.hexToBytes(hex);
}

export function bytesToHex(bytes: Uint8Array): string {
  return utils.bytesToHex(bytes);
}

export function filterDisclosedMessages(msg: FrScalar[], disclosed_indexes: number[]): FrScalar[] {
  return msg.filter((v, i, a) => { return disclosed_indexes.includes(i + 1) });
}

export function log(...s: any): void {
  // console.log(...s);  // uncomment to print out debug statements
}