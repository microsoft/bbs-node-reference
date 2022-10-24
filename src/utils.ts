// NOTE: some functions copied from noble-bls12-381's index.ts (TODO: cleaner import or re-impl)

import { PointG1, PointG2 } from "@noble/bls12-381";

// Octet Stream to Integer
export function os2ip(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result <<= 8n;
    result += BigInt(bytes[i]);
  }
  return result;
}

// Integer to Octet Stream
export function i2osp(value: number | bigint, length: number): Uint8Array {
  // FIXME: same as toRawBytes?
  if (value < 0  || value >= 256n**BigInt(length) /*1 << (8 * length) FIXME: throws with length == 4! */) { // TODO: FIXME: make constant for our constant sizes
    throw new Error(`bad I2OSP call: value=${value} length=${length}`);
  }
  const res = Array.from({ length }).fill(0) as number[];
  for (let i = length - 1; i >= 0; i--) {
    if (typeof value === 'number') {
      res[i] = value & 0xff;
      value >>>= 8;
    } else {
      res[i] = Number(value % 256n); // use BigInt.asUintN here for modulo?
      value = value / 256n;
    }
  }
  
  return new Uint8Array(res);
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

export function strxor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const arr = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    arr[i] = a[i] ^ b[i];
  }
  return arr;
}

export function toRawBytes(P: PointG1 | PointG2, isCompressed = false) {
  return hexToBytes(P.toHex(isCompressed));
}

export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
  }
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex');
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    const hexByte = hex.slice(j, j + 2);
    if (hexByte.length !== 2) throw new Error('Invalid byte sequence');
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte) || byte < 0) throw new Error('Invalid byte sequence');
    array[i] = byte;
  }
  return array;
}

export function numberTo32BytesBE(num: bigint) {
  const length = 32;
  const hex = num.toString(16).padStart(length * 2, '0');
  return hexToBytes(hex);
}

export function bytesToNumberBE(uint8a: Uint8Array): bigint {
  if (!(uint8a instanceof Uint8Array)) throw new Error('Expected Uint8Array');
  return BigInt('0x' + bytesToHex(Uint8Array.from(uint8a)));
}

const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
export function bytesToHex(uint8a: Uint8Array): string {
  // pre-caching chars could speed this up 6x.
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += hexes[uint8a[i]];
  }
  return hex;
}

export function filterDisclosedMessages(msg: any[], disclosed_indexes: number[]): any[] {
  return msg.filter((v, i, a) => {return disclosed_indexes.includes(i+1)});
}

export function log(...s: any) : void {
  // console.log(...s); uncomment to print out debug statement
}