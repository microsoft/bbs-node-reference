// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { sha256 } from '@noble/hashes/sha256';
import { extract as hkdfExtract, expand as hkdfExpand } from '@noble/hashes/hkdf';
import * as utils from './utils';
import * as bls from '@noble/bls12-381';
import { Ciphersuite, BLS12_381_SHA256_Ciphersuite } from './ciphersuite';
import { HashInput, HashInputToBytes } from './hash';
import * as crypto from 'crypto';

// NOTE: we don't check for the max array lengths, because the JavaScript max is 2^53-1, smaller than the spec's 2^64-1

export interface BBSSignature {
  A: bls.PointG1,
  e: bigint
}

export interface Generators {
  Q1: bls.PointG1,
  H: bls.PointG1[]
}

export interface BBSProof {
  ABar: bls.PointG1,
  BBar: bls.PointG1,
  c: bigint,
  r2Hat: bigint,
  r3Hat: bigint,
  mHat: bigint[]
}

export const modR = (i: bigint) => bls.utils.mod(i,bls.CURVE.r);
const checkNonZeroFr = (i: bigint, message: string) => {if (i === 0n || i >= bls.CURVE.r) throw message + "; " + ((i === 0n) ? "zero" : ">r")};

export class BBS {
  cs: Ciphersuite;

  constructor(cs = BLS12_381_SHA256_Ciphersuite) {
    this.cs = cs;
  }

  //
  // 3.3 Key Generation Operations
  //

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-keygen
  KeyGen(IKM: Uint8Array, key_info: Uint8Array = new Uint8Array()): bigint {
    const L = 72; // ceil((3 * ceil(log2(r))) / 16)
    if (IKM.length < 32) {
      throw "Input Keying Material (IKM) too short, MUST be at least 32 bytes";
    }
      
    let salt: Uint8Array = Buffer.from("BBS-SIG-KEYGEN-SALT-",'utf-8');
    let SK = 0n;
    while (SK === 0n) {
      const hash = this.cs.createHash();
      hash.update(salt);
      salt = hash.digest();
      // TODO: do not hardcode to sha256 in extract and expand calls, use the ciphersuite alg
      const PRK = hkdfExtract(sha256, utils.concatBytes(IKM,utils.i2osp(0,1)), salt);
      const OKM = hkdfExpand(sha256, PRK, utils.concatBytes(key_info, utils.i2osp(L, 2)), L);
      SK = modR(utils.os2ip(OKM));
    }
    return SK;
  }

  //https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-sktopk
  SkToPk(SK: bigint): Uint8Array {
    const W = bls.PointG2.fromPrivateKey(SK); // TODO: check that BLS impl and BBS spec match here (FIXME: not clear)
    return this.cs.point_to_octets_g2(W);
  }

  //
  // 3.4 Core Operations
  //

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-sign
  Sign(SK: bigint, PK: Uint8Array, header: Uint8Array, messages: bigint[], generators: Generators): Uint8Array {
    utils.log("Sign");

    if (messages.length !== generators.H.length) {
      throw "msg and H should have the same length";
    }
    const L = messages.length;
    const domain = this.calculate_domain(PK, generators, header);
    utils.log("domain", domain);
    const e_octs = this.serialize([SK, domain, ...messages]);
    utils.log("e_octs", e_octs);
    const expand_dst = Buffer.from(this.cs.Ciphersuite_ID + "SIG_DET_DST_",'utf-8');
    utils.log("expand_dst", expand_dst);
    utils.log("octet_scalar_length", this.cs.octet_scalar_length);
    const e_expand = this.cs.expand_message(e_octs, expand_dst, this.cs.octet_scalar_length)
    utils.log("e_expand", e_expand);
    const e = this.hash_to_scalar(e_expand);
    utils.log("e", e);
    
    // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = this.cs.P1;
    B = B.add(generators.Q1.multiply(domain));
    for (let i = 0; i < L; i++) {
      B = B.add(generators.H[i].multiply(messages[i]));
    }
    utils.log("B", B);

    // A = B * (1 / (SK + e))
    const sk = new bls.Fr(SK);
    const A = B.multiply(sk.add(new bls.Fr(e)).invert().value);
    utils.log("A", A);

    // signature_octets = signature_to_octets(A, e, s)
    const signature_octets = this.signature_to_octets({A: A, e: e});
    return signature_octets;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-verify
  Verify(PK: Uint8Array, signature: Uint8Array, header: Uint8Array, messages: bigint[], generators: Generators, skipPKValidation: boolean = false): void {
    utils.log("Sign");

    const sig = this.octets_to_signature(signature);
    const W = this.octets_to_pubkey(PK, skipPKValidation);
    const L = messages.length;
    const domain = this.calculate_domain(PK, generators, header);
    utils.log("domain", domain);

    // B = P1 + Q1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = this.cs.P1;
    B = B.add(generators.Q1.multiply(domain));
    for (let i = 0; i < L; i++) {
      B = B.add(generators.H[i].multiply(messages[i]));
    }
    utils.log("B", B);
       
    // check that e(A, W + P2 * e) * e(B, -P2) == Identity_GT
    // (using the pairing optimization to skip final exponentiation in the pairing
    // and do it after the multiplication)
    const lh = bls.pairing(sig.A, W.add(bls.PointG2.BASE.multiply(sig.e)), false);
    const rh = bls.pairing(B, bls.PointG2.BASE.negate(), false);
    const pairing = lh.multiply(rh).finalExponentiate();
    if (!pairing.equals(bls.Fp12.ONE)) {
      throw "Invalid signature (pairing)";
    }
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proofgen
  ProofGen(PK: Uint8Array, signature: Uint8Array, header: Uint8Array, ph: Uint8Array, messages: bigint[], generators: Generators, disclosed_indexes: number[]): Uint8Array {
    utils.log("ProofGen");
     const L = messages.length;
    const R = disclosed_indexes.length;
    const U = L - R;
    const signature_result = this.octets_to_signature(signature);
    
    const iSet = new Set<number>(disclosed_indexes);
    const i = Array.from(iSet).sort((a,b) => a-b);
    utils.log("i: " + i);
    const jSet = new Set<number>(Array.from({length: L}, (e, i)=> i+1));
    iSet.forEach(v => jSet.delete(v));
    const j = Array.from(jSet).sort((a,b) => a-b);
    utils.log("j: " + j);

    const domain = this.calculate_domain(PK, generators, header)
    utils.log("domain: " + domain);
    const scalars = this.calculate_random_scalars(3 + U);
    let index = 0;
    const r1 = scalars[index++];
    utils.log("r1: " + r1);
    const r2 = scalars[index++];
    utils.log("r2: " + r2);
    const r3 = scalars[index++];
    utils.log("r3: " + r3);
    const mTilda = new Array(U).fill(0n).map((v, i, a) => scalars[index + i]);
    utils.log("mTilda: " + mTilda);

    // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = this.cs.P1;
    B = B.add(generators.Q1.multiply(domain));
    for (let k = 0; k < L; k++) {
      B = B.add(generators.H[k].multiply(messages[k]));
    }
    utils.log("B: " + B);

    const ABar = signature_result.A.multiply(r1); // Abar = A * r1
    const BBar = B.multiply(r1).subtract(ABar.multiply(signature_result.e)); // Bbar = B * r1 - Abar * e

    // U = Bbar * r2 + Abar * r3 + H_j1 * m~_j1 + ... + H_jU * m~_jU;
    let C = BBar.multiply(r2).add(ABar.multiply(r3));
    for (let k = 0; k < U; k++) {
      C = C.add(generators.H[j[k]-1].multiply(mTilda[k]));
    }

    // c = calculate_challenge(Abar, Bbar, C, (i1, ..., iR), (m_i1, ..., m_iR), domain, ph)    
    const disclosedMsg = utils.filterDisclosedMessages(messages, disclosed_indexes);
    const iZeroBased = i.map(v => v-1); // TODO: spec's fixtures assume these are 0-based; double-check that
    const c = this.calculate_challenge(ABar, BBar, C, iZeroBased, disclosedMsg, domain, ph);

    const r4 = new bls.Fr(r1).negate().invert().value; // r4 = -r1^-1 (mod r)
    const r2Hat = modR(r2 + modR(r4 * c)); // r2^ = r2 + r4 * c (mod r)
    const r3Hat = modR(r3 + modR(signature_result.e * r4 * c)); // r3^ = r3 + e * r4 * c (mod r)
    const mHat: bigint[] = [];
    for (let k = 0; k < U; k++) {
      mHat[k] = modR(mTilda[k] + modR(c * messages[j[k]-1])); // m^_j = m~_j + m_j * c (mod r)
    }

    const proof = { ABar: ABar, BBar: BBar, c: c, r2Hat: r2Hat, r3Hat: r3Hat, mHat: mHat }
    return this.proof_to_octets(proof);
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-proofverify
  ProofVerify(PK: Uint8Array, proof: Uint8Array, header: Uint8Array, ph: Uint8Array, disclosed_messages: bigint[], extGenerators: Generators, RevealedIndexes: number[], skipPKValidation: boolean = false): void {
      utils.log("ProofVerify");
      //const msgScalars = disclosed_messages.map(v => this.MapMessageToScalarAsHash(v)); FIXME DELETE
      const proof_result = this.octets_to_proof(proof);
      utils.log("proof_result: " + proof_result);
      const W = this.octets_to_pubkey(PK, skipPKValidation);
      utils.log("W: " + W);
      const R = RevealedIndexes.length;
      const U = proof_result.mHat.length;
      const L = R + U;

      const iSet = new Set<number>(RevealedIndexes);
      const i = Array.from(iSet).sort((a,b) => a-b);
      utils.log("i: " + i);
      const jSet = new Set<number>(Array.from({length: L}, (e, i)=> i+1));
      iSet.forEach(v => jSet.delete(v));
      const j = Array.from(jSet).sort((a,b) => a-b);
      utils.log("j: " + j);

      // copy and trim generators
      if (extGenerators.H.length < L) throw new Error("Not enough generators provided");
      const generators: Generators = {
        H: extGenerators.H.slice(0, L),
        Q1: extGenerators.Q1,
      }
      const domain = this.calculate_domain(PK, generators, header);
      utils.log("domain: " + domain);

      // D = P1 + Q_1 * domain + H_i1 * m_i1 + ... + H_iR * m_iR
      let D = this.cs.P1;
      D = D.add(generators.Q1.multiply(domain));
      for (let k = 0; k < R; k++) {
        D = D.add(generators.H[i[k]-1].multiply(disclosed_messages[k]));
      }

      // C = Bbar * r2^ + Abar * r3^ + H_j1 * m^_j1 + ... + H_jU * m^_jU + D * c
      let C = proof_result.BBar.multiply(proof_result.r2Hat).add(
        proof_result.ABar.multiply(proof_result.r3Hat));
      for (let k = 0; k < U; k++) {
         C = C.add(generators.H[j[k]-1].multiply(proof_result.mHat[k]));
      }
      C = C.add(D.multiply(proof_result.c));

      
      const iZeroBased = i.map(v => v-1); // TODO: spec's fixtures assume these are 0-based; double-check that
      const cv = this.calculate_challenge(proof_result.ABar, proof_result.BBar, C, iZeroBased, disclosed_messages, domain, ph);
      utils.log("cv: " + cv);

      if (proof_result.c !== cv) {
        utils.log("c : " + proof_result.c);
        utils.log("cv: " + cv);
        throw "Invalid proof (cv)";
      }

      // (using the pairing optimization to skip final exponentiation in the pairing
      // and do it after the multiplication)
      const lh = bls.pairing(proof_result.ABar, W, false);
      const rh = bls.pairing(proof_result.BBar, bls.PointG2.BASE.negate(), false);
      const pairing = lh.multiply(rh).finalExponentiate();
      if (!pairing.equals(bls.Fp12.ONE)) {
        throw "Invalid proof (pairing)"
      }
  }

  //
  // 4. Utility operations
  //

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-random-scalars-computation
  calculate_random_scalars(count: number): bigint[] {
    const random_scalars: bigint[] = [];
    for (let i = 0; i < count; i++) {
      random_scalars.push(modR(utils.os2ip(crypto.randomBytes(this.cs.expand_len))));
    }
    return random_scalars;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-generator-point-computation
  async create_generators(length: number): Promise<Generators> {
      const count = length + 1; // Q1, and generators
      const seed_dst = Buffer.from(this.cs.Ciphersuite_ID + 'SIG_GENERATOR_SEED_', 'utf-8');
      let v = this.cs.expand_message(this.cs.generator_seed, seed_dst, this.cs.seed_len);
      let n = 1;
      const generators: bls.PointG1[] = [];
      for (let i = 0; i < count; i++) {
          let cont = true;
          let candidate = bls.PointG1.ZERO;
          while (cont) {
              v = this.cs.expand_message(utils.concatBytes(v, utils.i2osp(n, 4)), seed_dst, this.cs.seed_len);
              n += 1;
              candidate = await this.cs.hash_to_curve_g1(v); // generator_dst specified in the hash_to_curve_g1 function directly
              cont = generators.includes(candidate);
            }
          generators.push(candidate);
          utils.log("candidate " + i + ": " + utils.bytesToHex(this.cs.point_to_octets_g1(candidate)));
      }
      return {
        Q1: generators[0],
        H: generators.slice(1)
      };
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-mapmessagetoscalarashash
  MapMessageToScalarAsHash(msg: Uint8Array, dst: Uint8Array = Buffer.from(this.cs.Ciphersuite_ID + "MAP_MSG_TO_SCALAR_AS_HASH_", "utf8")): bigint {
    if (dst.length > 255) {
      throw "dst too long";
    }
    return this.hash_to_scalar(msg, dst);
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-hash-to-scalar
  hash_to_scalar(msg_octets: Uint8Array, dst: Uint8Array = Buffer.from(this.cs.Ciphersuite_ID + "H2S_", "utf8")): bigint {
    let hashed_scalar: bigint = 0n;
    let counter = 0;
    while (hashed_scalar === 0n) {
      if (counter > 255) {
       throw "hash_to_scalar failed, counter > 255"; 
      }
      const msg_prime =  utils.concatBytes(msg_octets, utils.i2osp(counter,1));
      const uniform_bytes = this.cs.expand_message(msg_prime, dst, this.cs.expand_len);
      hashed_scalar = modR(utils.os2ip(uniform_bytes));
      counter++;
    }
    return hashed_scalar;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-domain-calculation
  calculate_domain(PK: Uint8Array, generators: Generators, header: Uint8Array): bigint {
    const dom_octs = utils.concatBytes(
      this.serialize([generators.H.length, generators.Q1, ...generators.H]),
      Buffer.from(this.cs.Ciphersuite_ID, 'utf8'));
    const dom_input = utils.concatBytes(PK, dom_octs, utils.i2osp(header.length, 8), header);
    utils.log("dom_input: " + (dom_input));
    const domain = this.hash_to_scalar(dom_input);
    return domain;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-challenge-calculation
  calculate_challenge(ABar: bls.PointG1, BBar: bls.PointG1, C: bls.PointG1, i_array: number[], msg_array: bigint[], domain: bigint, ph: Uint8Array): bigint {
    const c_input = utils.concatBytes(
      this.serialize([ABar, BBar, C, i_array.length, ...i_array, ...msg_array, domain]),
      utils.i2osp(ph.length, 8),
      ph);
    const challenge = this.hash_to_scalar(c_input);
    return challenge;
  }
  
  //
  // 4.7 Serialization
  //

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-serialize
  serialize(input_array: HashInput[]): Uint8Array { // TODO FIXME: spec errata, octets_result returns a octet string, not a byte array
    let octets_result = new Uint8Array();
    input_array.forEach(v => {
      octets_result = utils.concatBytes(octets_result, HashInputToBytes(v));
    });
    return octets_result;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-signaturetooctets
  signature_to_octets(signature: BBSSignature): Uint8Array {
    const A_octets = this.cs.point_to_octets_g1(signature.A);
    const e_octets = utils.i2osp(signature.e, this.cs.octet_scalar_length);
    return utils.concatBytes(A_octets, e_octets);
  }

    // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-octetstosignature
    octets_to_signature(signature_octets: Uint8Array): BBSSignature {
      if (signature_octets.length !== this.cs.octet_point_length + this.cs.octet_scalar_length) {
          throw "Invalid signature_octets length";
      }
      const A_octets = signature_octets.slice(0, this.cs.octet_point_length);
      const A = this.cs.octets_to_point_g1(A_octets);
      if (A.equals(bls.PointG1.ZERO)) {
        throw "Invalid A";
      }
      let index = this.cs.octet_point_length;
      const e = utils.os2ip(signature_octets.slice(index, index + this.cs.octet_scalar_length));
      if (e === 0n || e >= bls.Fr.ORDER) {
        throw "Invalid e"
      }
  
      return { A: A, e: e }
    }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-prooftooctets
  proof_to_octets(proof: BBSProof): Uint8Array  {
    let proof_octets_elements: Uint8Array[] = [
      this.cs.point_to_octets_g1(proof.ABar),
      this.cs.point_to_octets_g1(proof.BBar),
      utils.i2osp(proof.c, this.cs.octet_scalar_length),
      utils.i2osp(proof.r2Hat, this.cs.octet_scalar_length),
      utils.i2osp(proof.r3Hat, this.cs.octet_scalar_length)
    ]
    proof.mHat.forEach(msg => 
      {
        proof_octets_elements.push(utils.i2osp(msg, this.cs.octet_scalar_length));
      });

    return utils.concatBytes(...proof_octets_elements);
  }
    
  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-octetstoproof
  octets_to_proof(proof_octets: Uint8Array): BBSProof {
    const proof_len_floor = 2 * this.cs.octet_point_length + 4 * this.cs.octet_scalar_length;
    if (proof_octets.length < proof_len_floor) {
      throw "invalid proof (length)";
    }

    let index = 0;
    const ABar = this.cs.octets_to_point_g1(proof_octets.slice(index, index + this.cs.octet_point_length));
    index += this.cs.octet_point_length;
    const BBar = this.cs.octets_to_point_g1(proof_octets.slice(index, index + this.cs.octet_point_length));
    index += this.cs.octet_point_length;

    const c = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length));
    checkNonZeroFr(c, "invalid proof (c)");
    index += this.cs.octet_scalar_length;
    const r2Hat = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length));
    index += this.cs.octet_scalar_length;
    checkNonZeroFr(r2Hat, "invalid proof (r2Hat)");
    const r3Hat = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length));
    index += this.cs.octet_scalar_length;
    checkNonZeroFr(r3Hat, "invalid proof (r3Hat)");

    const mHat: bigint[] = [];
    while (index  < proof_octets.length ) {
      const msg = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length));
      index += this.cs.octet_scalar_length;
      checkNonZeroFr(msg, `invalid proof (mHat[${mHat.length + 1}])`);
      mHat.push(msg);
    }

    return {ABar: ABar, BBar: BBar, c: c, r2Hat: r2Hat, r3Hat: r3Hat, mHat: mHat}
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-octetstopublickey
  octets_to_pubkey(PK: Uint8Array, skipPKValidation: boolean = false): bls.PointG2 {
    const W = this.cs.octets_to_point_g2(PK);
    if (!skipPKValidation) {
      if (W === bls.PointG2.ZERO) {
        throw "Invalid public key: identity value";
      }
      W.assertValidity();
    }
    return W;
  }
}
