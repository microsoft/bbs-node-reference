import { PointG1, PointG2 } from '@noble/bls12-381';
import { Keccak, shake256 } from '@noble/hashes/sha3';
import { HashXOF } from '@noble/hashes/utils';
import { BLS12_381_SHA256_Ciphersuite, Ciphersuite } from './ciphersuite';
import { concatBytes, i2osp } from './utils';

// Uint8Array hashed directly, without pre-pending its length
export class DirectUin8Array {
  a: Uint8Array;
  constructor(a: Uint8Array) {
    this.a = a;
  }
}
export type HashInput = DirectUin8Array | PointG1 | PointG2 | string | number | bigint | Uint8Array;

export function HashInputToBytes(data: HashInput, cs: Ciphersuite = BLS12_381_SHA256_Ciphersuite): Uint8Array {

  if (typeof data === 'string') {
    return Buffer.from(data, 'utf-8');
  } else if (data instanceof DirectUin8Array) {
    return data.a;
  } else if (data instanceof PointG1) {
    return cs.point_to_octets_g1(data);
  } else if (data instanceof PointG2) {
    return cs.point_to_octets_g2(data);
  } else if (typeof data === 'bigint') { // TODO: should I only use Fr?
    return i2osp(data, cs.octet_scalar_length);
  } else if (typeof data === 'number') {
    return i2osp(data, 8);
  } else if (data instanceof Uint8Array) {
    return concatBytes(i2osp(data.length, 8), data);
  } else {
    throw "invalid input";
  }
}

// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-encodeforhash
export function encode_for_hash(input: HashInput[]): Uint8Array {
  let octets_to_hash = new Uint8Array();
  input.forEach(v => {
    octets_to_hash = concatBytes(octets_to_hash, HashInputToBytes(v));
  });
  return octets_to_hash;
}

export class Hash {
  hash = shake256.create({ dkLen: 64 }) as HashXOF<Keccak>;
  constructor() {
  }

  update(data: HashInput): void {
    const bytes = HashInputToBytes(data);
    const length = bytes.length;
    this.hash.update(i2osp(length, 4));
    this.hash.update(bytes);
  }

  digest(): Uint8Array {
    return this.hash.digest();
  }
}

export class XOF extends Hash {
  constructor() {
    super();
  }

  read(i: number) {
    return this.hash.xof(i);
  }
}