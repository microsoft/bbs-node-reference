// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as utils from './utils';
import { G1Point, G2Point, FrScalar, checkPairingIsIdentity, Point } from './math';
import { Ciphersuite, BLS12_381_SHAKE_256_Ciphersuite } from './ciphersuite';
import * as crypto from 'crypto';
import { concat, i2osp } from './utils';

// NOTE: we don't check for the max array lengths, because the JavaScript max is 2^53-1, smaller than the spec's 2^64-1

export interface Generators {
  Q1: G1Point,
  H: G1Point[]
}

export interface BBSSignature {
  A: G1Point,
  e: FrScalar
}

export interface BBSProof {
  Abar: G1Point,
  Bbar: G1Point,
  D: G1Point,
  eHat: FrScalar,
  r1Hat: FrScalar,
  r3Hat: FrScalar,
  mHat: FrScalar[],
  c: FrScalar
}

type SerializeInput = G1Point | G2Point | FrScalar | string | number | Uint8Array;

export class BBS {
  cs: Ciphersuite;

  constructor(cs = BLS12_381_SHAKE_256_Ciphersuite) {
    this.cs = cs;
  }

  //
  // 3.4 Key Generation Operations
  //

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-secret-key
  KeyGen(key_material: Uint8Array,
    key_info: Uint8Array = new Uint8Array(),
    key_dst: Uint8Array = Buffer.from(this.cs.ciphersuite_id + "KEYGEN_DST_", 'utf-8')): FrScalar {
    if (key_material.length < 32) {
      throw "key_material too short, MUST be at least 32 bytes";
    }
    if (key_info.length > 65535) {
      throw "key_material too short, MUST be at least 32 bytes";
    }
    const derive_input = utils.concat(key_material, utils.i2osp(key_info.length, 2), key_info);
    const SK = this.hash_to_scalar(derive_input, key_dst);
    return SK;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-public-key
  SkToPk(SK: FrScalar): G2Point {
    return G2Point.Base.mul(SK);
  }

  //
  // 3.6. Core Operations (the functions implement both the BBS interface
  //      and the core operations)
  //

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-generation-sign
  Sign(SK: FrScalar, PK: G2Point, header: Uint8Array, messages: FrScalar[], generators: Generators): Uint8Array {
    utils.log("Sign");

    if (messages.length !== generators.H.length) {
      throw "msg and H should have the same length";
    }
    const L = messages.length;
    const domain = this.calculate_domain(PK, generators, header);
    utils.log("domain", domain);
    const e = this.hash_to_scalar(this.serialize([SK, domain, ...messages]));
    utils.log("e", e);

    // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = this.cs.P1;
    B = B.add(generators.Q1.mul(domain));
    for (let i = 0; i < L; i++) {
      B = B.add(generators.H[i].mul(messages[i]));
    }
    utils.log("B", B);

    // A = B * (1 / (SK + e))
    const A = B.mul(SK.add(e).inv());
    utils.log("A", A);

    // signature_octets = signature_to_octets(A, e, s)
    const signature_octets = this.signature_to_octets({ A: A, e: e });
    return signature_octets;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-verification-veri
  Verify(PK: G2Point, signature: Uint8Array, header: Uint8Array, messages: FrScalar[], generators: Generators): void {
    utils.log("Verify");

    const sig = this.octets_to_signature(signature);
    const L = messages.length;
    const domain = this.calculate_domain(PK, generators, header);
    utils.log("domain", domain);

    // B = P1 + Q1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = this.cs.P1;
    B = B.add(generators.Q1.mul(domain));
    for (let i = 0; i < L; i++) {
      B = B.add(generators.H[i].mul(messages[i]));
    }
    utils.log("B", B);

    // check that e(A, W + P2 * e) * e(B, -P2) == Identity_GT
    if (!checkPairingIsIdentity(sig.A, PK.add(G2Point.Base.mul(sig.e)),
      B, G2Point.Base.neg())) {
      throw "Invalid signature (pairing)";
    }
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-generation-proofgen
  ProofGen(PK: G2Point, signature: Uint8Array, header: Uint8Array, ph: Uint8Array, messages: FrScalar[], generators: Generators, disclosed_indexes: number[]): Uint8Array {
    utils.log("ProofGen");
    const L = messages.length;
    const R = disclosed_indexes.length;
    const U = L - R;
    const signature_result = this.octets_to_signature(signature);

    const iSet = new Set<number>(disclosed_indexes);
    const i = Array.from(iSet).sort((a, b) => a - b);
    utils.log("i", i);
    const jSet = new Set<number>(Array.from({ length: L }, (e, i) => i + 1));
    iSet.forEach(v => jSet.delete(v));
    const j = Array.from(jSet).sort((a, b) => a - b);
    utils.log("j", j);

    const domain = this.calculate_domain(PK, generators, header)
    utils.log("domain", domain);
    const scalars = this.calculate_random_scalars(5 + U);
    let index = 0;
    const r1 = scalars[index++];
    utils.log("r1", r1);
    const r2 = scalars[index++];
    utils.log("r2", r2);
    const eTilda = scalars[index++];
    utils.log("eTilda", eTilda);
    const r1Tilda = scalars[index++];
    utils.log("r1Tilda", r1Tilda);
    const r3Tilda = scalars[index++];
    utils.log("r3Tilda", r3Tilda);

    const mTilda = new Array(U).fill(0n).map((v, i, a) => scalars[index + i]);
    utils.log("mTilda", mTilda);

    // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = this.cs.P1;
    B = B.add(generators.Q1.mul(domain));
    for (let k = 0; k < L; k++) {
      B = B.add(generators.H[k].mul(messages[k]));
    }
    utils.log("B", B);

    const D = B.mul(r2); // D = B * r2
    const Abar = signature_result.A.mul(r1.mul(r2)); // Abar = A * (r1 * r2)
    const Bbar = D.mul(r1).add(Abar.mul(signature_result.e).neg()); // Bbar = D * r1 - Abar * e

    // T1 = Abar * e~ + D * r1~
    let T1 = Abar.mul(eTilda).add(D.mul(r1Tilda));
    // T2 = D * r3~ + H_j1 * m~_j1 + ... + H_jU * m~_jU
    let T2 = D.mul(r3Tilda);
    for (let k = 0; k < U; k++) {
      T2 = T2.add(generators.H[j[k] - 1].mul(mTilda[k]));
    }

    // c = calculate_challenge(Abar, Bbar, D, T1, T2, (i1, ..., iR), (m_i1, ..., m_iR), domain, ph)    
    const disclosedMsg = utils.filterDisclosedMessages(messages, disclosed_indexes);
    const iZeroBased = i.map(v => v - 1); // spec's fixtures assume these are 0-based;
    const c = this.calculate_challenge(Abar, Bbar, D, T1, T2, iZeroBased, disclosedMsg, domain, ph);


    // r3 = r2^-1 (mod r)
    const r3 = r2.inv();
    // e^ = e~ + e_value * challenge
    const eHat = eTilda.add(signature_result.e.mul(c));
    // r1^ = r1~ - r1 * challenge
    const r1Hat = r1Tilda.add(r1.mul(c).neg());
    // r3^ = r3~ - r3 * challenge
    const r3Hat = r3Tilda.add(r3.mul(c).neg());
    const mHat: FrScalar[] = [];
    for (let k = 0; k < U; k++) {
      mHat[k] = messages[j[k] - 1].mul(c).add(mTilda[k]); // m^_j = m~_j + m_j * c (mod r)
    }

    const proof = { Abar: Abar, Bbar: Bbar, D: D, eHat: eHat, r1Hat: r1Hat, r3Hat: r3Hat, mHat: mHat, c: c }
    return this.proof_to_octets(proof);
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-verification-proofver
  ProofVerify(PK: G2Point, encodedProof: Uint8Array, header: Uint8Array, ph: Uint8Array, disclosed_messages: FrScalar[], extGenerators: Generators, RevealedIndexes: number[]): void {
    utils.log("ProofVerify");
    const proof = this.octets_to_proof(encodedProof);
    utils.log("proof", proof);
    const R = RevealedIndexes.length;
    const U = proof.mHat.length;
    const L = R + U;

    const iSet = new Set<number>(RevealedIndexes);
    const i = Array.from(iSet).sort((a, b) => a - b);
    utils.log("i", i);
    const jSet = new Set<number>(Array.from({ length: L }, (e, i) => i + 1));
    iSet.forEach(v => jSet.delete(v));
    const j = Array.from(jSet).sort((a, b) => a - b);
    utils.log("j", j);

    // copy and trim generators
    if (extGenerators.H.length < L) throw new Error("Not enough generators provided");
    const generators: Generators = {
      H: extGenerators.H.slice(0, L),
      Q1: extGenerators.Q1,
    }
    const domain = this.calculate_domain(PK, generators, header);
    utils.log("domain", domain);

    // T1 = Bbar * c + Abar * e^ + D * r1^
    let T1 = proof.Bbar.mul(proof.c).add(proof.Abar.mul(proof.eHat)).add(proof.D.mul(proof.r1Hat));
    // Bv = P1 + Q_1 * domain + H_i1 * msg_i1 + ... + H_iR * msg_iR
    let Bv = this.cs.P1;
    Bv = Bv.add(generators.Q1.mul(domain));
    for (let k = 0; k < R; k++) {
      Bv = Bv.add(generators.H[i[k] - 1].mul(disclosed_messages[k]));
    }
    // T2 = Bv * c + D * r3^ + H_j1 * m^_j1 + ... +  H_jU * m^_jU
    let T2 = Bv.mul(proof.c).add(proof.D.mul(proof.r3Hat));
    for (let k = 0; k < U; k++) {
      T2 = T2.add(generators.H[j[k] - 1].mul(proof.mHat[k]));
    }

    const iZeroBased = i.map(v => v - 1); // spec's fixtures assume these are 0-based
    const cv = this.calculate_challenge(proof.Abar, proof.Bbar, proof.D, T1, T2, iZeroBased, disclosed_messages, domain, ph);
    utils.log("cv", cv);

    if (!proof.c.equals(cv)) {
      utils.log("c", proof.c);
      utils.log("cv", cv);
      throw "Invalid proof (cv)";
    }

    if (!checkPairingIsIdentity(proof.Abar, PK,
      proof.Bbar, G2Point.Base.neg())) {
      throw "Invalid proof (pairing)"
    }
  }

  //
  // 4. Utility operations
  //

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-random-scalars
  calculate_random_scalars(count: number): FrScalar[] {
    const random_scalars: FrScalar[] = [];
    for (let i = 0; i < count; i++) {
      random_scalars.push(utils.os2ip(crypto.randomBytes(this.cs.expand_len)));
    }
    return random_scalars;
  }

  // implements the hash_to_generators operation
  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-generators-calculation
  async create_generators(length: number): Promise<Generators> {
    const count = length + 1; // Q1, and generators
    const seed_dst = Buffer.from(this.cs.ciphersuite_id + 'SIG_GENERATOR_SEED_', 'utf-8');
    let v = this.cs.expand_message(this.cs.generator_seed, seed_dst, this.cs.expand_len);
    const generators: G1Point[] = [];
    for (let i = 1; i <= count; i++) {
      v = this.cs.expand_message(utils.concat(v, utils.i2osp(i, 8)), seed_dst, this.cs.expand_len);
      const generator = await this.cs.hash_to_curve_g1(v, this.cs.ciphersuite_id + 'SIG_GENERATOR_DST_');
      generators.push(generator);
      utils.log("generator " + i + ": ", utils.bytesToHex(generator.toOctets()));
    }
    return {
      Q1: generators[0],
      H: generators.slice(1)
    };
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-message-to-scalar-as-hash
  MapMessageToScalarAsHash(msg: Uint8Array, dst: Uint8Array = Buffer.from(this.cs.ciphersuite_id + "MAP_MSG_TO_SCALAR_AS_HASH_", "utf8")): FrScalar {
    if (dst.length > 255) {
      throw "dst too long";
    }
    return this.hash_to_scalar(msg, dst);
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-hash-to-scalar
  hash_to_scalar(msg_octets: Uint8Array, dst: Uint8Array = Buffer.from(this.cs.ciphersuite_id + "H2S_", "utf8")): FrScalar {
    const uniform_bytes = this.cs.expand_message(msg_octets, dst, this.cs.expand_len);
    const hashed_scalar = utils.os2ip(uniform_bytes);
    return hashed_scalar;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-domain-calculation
  calculate_domain(PK: G2Point, generators: Generators, header: Uint8Array): FrScalar {
    const dom_octs = utils.concat(
      this.serialize([PK, generators.H.length, generators.Q1, ...generators.H]),
      Buffer.from(this.cs.ciphersuite_id, 'utf8'));
    const dom_input = utils.concat(dom_octs, utils.i2osp(header.length, 8), header);
    utils.log("dom_input", dom_input);
    const domain = this.hash_to_scalar(dom_input);
    return domain;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-challenge-calculation
  calculate_challenge(Abar: G1Point, Bbar: G1Point, D: G1Point, T1: G1Point, T2: G1Point, i_array: number[], msg_array: FrScalar[], domain: FrScalar, ph: Uint8Array): FrScalar {
    const challenge = this.hash_to_scalar(
      utils.concat(
        this.serialize([Abar, Bbar, D, T1, T2, i_array.length, ...i_array, ...msg_array, domain]),
        utils.i2osp(ph.length, 8),
        ph));
    return challenge;
  }

  //
  // 4.2.4 Serialization
  //

  private serializeInputToBytes(data: SerializeInput): Uint8Array {

    if (typeof data === 'string') {
      return Buffer.from(data, 'utf-8');
    } else if (data instanceof Point) {
      return data.toOctets();
    } else if (data instanceof FrScalar) {
      return i2osp(data.scalar, this.cs.octet_scalar_length);
    } else if (typeof data === 'number') {
      return i2osp(data, 8);
    } else if (data instanceof Uint8Array) {
      return concat(i2osp(data.length, 8), data);
    } else {
      throw "invalid serialize type";
    }
  }
  

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-serialize
  serialize(input_array: SerializeInput[]): Uint8Array {
    let octets_result = new Uint8Array();
    input_array.forEach(v => {
      octets_result = utils.concat(octets_result, this.serializeInputToBytes(v));
    });
    return octets_result;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-signature-to-octets
  signature_to_octets(signature: BBSSignature): Uint8Array {
    return this.serialize([signature.A, signature.e]);
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-octets-to-signature
  octets_to_signature(signature_octets: Uint8Array): BBSSignature {
    if (signature_octets.length !== this.cs.octet_point_length + this.cs.octet_scalar_length) {
      throw "Invalid signature_octets length";
    }
    const A_octets = signature_octets.slice(0, this.cs.octet_point_length);
    const A = G1Point.fromOctets(A_octets);
    if (A.equals(G1Point.Identity)) {
      throw "Invalid A";
    }
    let index = this.cs.octet_point_length;
    const e = utils.os2ip(signature_octets.slice(index, index + this.cs.octet_scalar_length), true);
    return { A: A, e: e }
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proof-to-octets
  proof_to_octets(proof: BBSProof): Uint8Array {
    const serialized = this.serialize([proof.Abar, proof.Bbar, proof.D, proof.eHat, proof.r1Hat, proof.r3Hat, ...proof.mHat, proof.c]);
    return serialized;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-octets-to-proof
  octets_to_proof(proof_octets: Uint8Array): BBSProof {
    const proof_len_floor = 3 * this.cs.octet_point_length + 4 * this.cs.octet_scalar_length;
    if (proof_octets.length < proof_len_floor) {
      throw "invalid proof (length)";
    }

    let index = 0;
    const Abar = G1Point.fromOctets(proof_octets.slice(index, index + this.cs.octet_point_length));
    index += this.cs.octet_point_length;
    const Bbar = G1Point.fromOctets(proof_octets.slice(index, index + this.cs.octet_point_length));
    index += this.cs.octet_point_length;
    const D = G1Point.fromOctets(proof_octets.slice(index, index + this.cs.octet_point_length));
    index += this.cs.octet_point_length;

    const eHat = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length), true);
    index += this.cs.octet_scalar_length;
    const r1Hat = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length), true);
    index += this.cs.octet_scalar_length;
    const r3Hat = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length), true);
    index += this.cs.octet_scalar_length;

    const mHat: FrScalar[] = [];
    const end_index = proof_octets.length - this.cs.octet_scalar_length;
    while (index < end_index) {
      const msg = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length), true);
      index += this.cs.octet_scalar_length;
      mHat.push(msg);
    }
    const c = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length), true);

    return { Abar: Abar, Bbar: Bbar, D: D, eHat: eHat, r1Hat: r1Hat, r3Hat: r3Hat, mHat: mHat, c: c }
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-octets-to-public-key
  octets_to_pubkey(PK: Uint8Array, skipPKValidation: boolean = false): G2Point {
    const W = G2Point.fromOctets(PK, true /* check subgroup */);
    if (!skipPKValidation) {
      if (W.equals(G2Point.Identity)) {
        throw "Invalid public key";
      }
    }
    return W;
  }
}
