import { sha256 } from '@noble/hashes/sha256';
import { extract as hkdfExtract, expand as hkdfExpand } from '@noble/hashes/hkdf';
import * as utils from './utils';
import * as bls from '@noble/bls12-381';
import { Ciphersuite, BLS12_381_SHA256_Ciphersuite } from './ciphersuite';
import { encode_for_hash, HashInput, DirectUin8Array } from './hash';
import * as crypto from 'crypto';

export interface BBSSignature {
  A: bls.PointG1,
  e: bigint,
  s: bigint
}

export interface Generators {
  Q1: bls.PointG1,
  Q2: bls.PointG1,
  H: bls.PointG1[]
}

export interface BBSProof {
  APrime: bls.PointG1,
  ABar: bls.PointG1,
  D: bls.PointG1,
  c: bigint,
  eHat: bigint,
  r2Hat: bigint,
  r3Hat: bigint,
  sHat: bigint,
  mHat: bigint[]
}

const modR = (i: bigint) => bls.utils.mod(i,bls.CURVE.r);
const checkNonZeroFr = (i: bigint, message: string) => {if (i === 0n || i >= bls.CURVE.r) throw message + "; " + ((i === 0n) ? "zero" : ">r")};

export class BBS {
  cs: Ciphersuite;

  constructor(cs = BLS12_381_SHA256_Ciphersuite) {
    this.cs = cs;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-keygen
  KeyGen(IKM: Uint8Array, key_info: Uint8Array = new Uint8Array()): Uint8Array {
    const L = 72; // ceil((3 * ceil(log2(q))) / 16) // TODO: double check the value  
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
    return utils.numberTo32BytesBE(SK);
  }

  //https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-sktopk
  SkToPk(SK: Uint8Array): Uint8Array {
    const W = bls.PointG2.fromPrivateKey(SK); // TODO: check that BLS impl and BBS spec match here (FIXME: not clear)
    return this.cs.point_to_octets_g2(W);
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-sign
  Sign(SK: Uint8Array, PK: Uint8Array, header: Uint8Array, messages: bigint[], generators: Generators): Uint8Array {
    if (messages.length !== generators.H.length) {
      throw "msg and H should have the same length";
    }
    const W = bls.PointG2.fromHex(PK);

    const L = messages.length;

    const dom_for_hash = encode_for_hash([new DirectUin8Array(PK),L,generators.Q1,generators.Q2,...generators.H,this.cs.Ciphersuite_ID,header]);
    const domain = this.hash_to_scalar(dom_for_hash, 1)[0];
    const e_s_for_hash = encode_for_hash([new DirectUin8Array(SK), domain, ...messages]); // FIXME: SK also need to be encoded directly for fixtures to pass, but not mentioned in the spec
    const [e, s] = this.hash_to_scalar(e_s_for_hash, 2);
    
    // B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = this.cs.P1;
    B = B.add(generators.Q1.multiply(s));
    B = B.add(generators.Q2.multiply(domain));
    for (let i = 0; i < L; i++) {
      B = B.add(generators.H[i].multiply(messages[i]));
    }

    // A = B * (1 / (SK + e))
    const sk = new bls.Fr(utils.bytesToNumberBE(SK));
    const A = B.multiply(sk.add(new bls.Fr(e)).invert().value);
    
    // signature_octets = signature_to_octets(A, e, s)
    const signature_octets = this.signature_to_octets({A: A, e: e, s: s});
    return signature_octets;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-verify
  Verify(PK: Uint8Array, signature: Uint8Array, header: Uint8Array, messages: bigint[], generators: Generators, skipPKValidation: boolean = false): void {
    const sig = this.octets_to_signature(signature);
    const W = this.octets_to_pubkey(PK, skipPKValidation);
    const L = messages.length;
    const dom_for_hash = encode_for_hash([new DirectUin8Array(PK),L,generators.Q1,generators.Q2,...generators.H,this.cs.Ciphersuite_ID,header]);
    const domain = this.hash_to_scalar(dom_for_hash, 1)[0];

    // B = P1 + Q1 * s + Q2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = this.cs.P1;
    B = B.add(generators.Q1.multiply(sig.s));
    B = B.add(generators.Q2.multiply(domain));
    for (let i = 0; i < L; i++) {
      B = B.add(generators.H[i].multiply(messages[i]));
    }
       
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

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-proofgen
  ProofGen(PK: Uint8Array, signature: Uint8Array, header: Uint8Array, ph: Uint8Array, messages: bigint[], generators: Generators, disclosed_indexes: number[]): Uint8Array {
    utils.log("ProofGen");
    const L = messages.length;
    const R = disclosed_indexes.length;
    const U = L - R;
    const prf_len = 256; // TODO: double check that ceil(ceil(log2(r))/8)

    const signature_result = this.octets_to_signature(signature);
    
    const iSet = new Set<number>(disclosed_indexes);
    const i = Array.from(iSet).sort((a,b) => a-b);
    utils.log("i: " + i);
    const jSet = new Set<number>(Array.from({length: L}, (e, i)=> i+1));
    iSet.forEach(v => jSet.delete(v));
    const j = Array.from(jSet).sort((a,b) => a-b);
    utils.log("j: " + j);

    const dom_for_hash = encode_for_hash([new DirectUin8Array(PK),L,generators.Q1,generators.Q2,...generators.H,this.cs.Ciphersuite_ID,header]);
    utils.log("dom_for_hash: " + dom_for_hash);
    const domain = this.hash_to_scalar(dom_for_hash, 1)[0];
    utils.log("domain: " + domain);
    const scalars = this.hash_to_scalar(crypto.randomBytes(prf_len), 6);
    const r1 = scalars[0];
    utils.log("r1: " + r1);
    const r2 = scalars[1];
    utils.log("r2: " + r2);
    const eTilda = scalars[2];
    utils.log("eTilda: " + eTilda);
    const r2Tilda = scalars[3];
    utils.log("r2Tilda: " + r2Tilda);
    const r3Tilda = scalars[4];
    utils.log("r3Tilda: " + r3Tilda);
    const sTilda = scalars[5];
    utils.log("sTilda: " + sTilda);

    const mTilda = this.hash_to_scalar(crypto.randomBytes(prf_len), U);
    utils.log("mTilda: " + mTilda);
    // B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
    let B = this.cs.P1;
    B = B.add(generators.Q1.multiply(signature_result.s));
    B = B.add(generators.Q2.multiply(domain));
    for (let k = 0; k < L; k++) {
      B = B.add(generators.H[k].multiply(messages[k]));
    }
    utils.log("B: " + B);

    const r3 = new bls.Fr(r1).invert().value; // r3 = r1 ^ -1 mod r
    const APrime = signature_result.A.multiply(r1); // A' = A * r1
    const ABar = APrime.multiply(new bls.Fr(signature_result.e).negate().value).add(B.multiply(r1));// Abar = A' * (-e) + B * r1
    const D = B.multiply(r1).add(generators.Q1.multiply(r2)); // D = B * r1 + Q1 * r2
    const sPrime = modR(signature_result.s + modR(r2 * r3)); // s' = r2 * r3 + s mod r
    const C1 = APrime.multiply(eTilda).add(generators.Q1.multiply(r2Tilda));// C1 = A' * e~ + Q1 * r2~
    utils.log(`C1: ${C1}`);
    // C2 = D * (-r3~) + Q1 * s~ + H_j1 * m~_1 + ... + H_jU * m~_U
    let C2 = D.multiply(new bls.Fr(r3Tilda).negate().value);
    C2 = C2.add(generators.Q1.multiply(sTilda));
    for (let k = 0; k < U; k++) {
      C2 = C2.add(generators.H[j[k]-1].multiply(mTilda[k]));
    }
    utils.log("C2: " + C2);
    //  c_array = (A', Abar, D, C1, C2, R, i1, ..., iR, msg_i1, ..., msg_iR, domain, ph)
    const disclosedMsg = utils.filterDisclosedMessages(messages, disclosed_indexes);
    const iZeroBased = i.map(v => v-1); // TODO: spec's fixtures assume these are 0-based; double-check that
    const c_for_hash = encode_for_hash([APrime, ABar, D, C1, C2, R, ...iZeroBased, ...disclosedMsg, domain, ph]);
    const c = this.hash_to_scalar(c_for_hash, 1)[0];
    
    const eHat = modR(eTilda + modR(c * signature_result.e)); // e^ = c * e + e~ mod r 
    const r2Hat = modR(r2Tilda + modR(c * r2)); // r2^ = c * r2 + r2~ mod r
    const r3Hat = modR(r3Tilda + modR(c * r3)); // r3^ = c * r3 + r3~ mod r
    const sHat = modR(sTilda + modR(c * sPrime)); // s^ = c * s' + s~ mod r
    const mHat: bigint[] = [];
    for (let k = 0; k < U; k++) {
      mHat[k] = modR(mTilda[k] + modR(c * messages[j[k]-1])); // m^_j = c * msg_j + m~_j mod r
    }

    const proof = { APrime: APrime, ABar: ABar, D: D, c: c, eHat: eHat, r2Hat: r2Hat, r3Hat: r3Hat, sHat: sHat, mHat: mHat }    
    return this.proof_to_octets(proof);
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-proofverify
  ProofVerify(PK: Uint8Array, proof: Uint8Array, header: Uint8Array, ph: Uint8Array, disclosed_messages: bigint[], generators: Generators, RevealedIndexes: number[], skipPKValidation: boolean = false): void {
    utils.log("ProofVerify");
      const L = generators.H.length;
      const R = RevealedIndexes.length;
      const U = L - R;
      //const msgScalars = disclosed_messages.map(v => this.MapMessageToScalarAsHash(v));
      const W = this.octets_to_pubkey(PK, skipPKValidation);

      const iSet = new Set<number>(RevealedIndexes);
      const i = Array.from(iSet).sort((a,b) => a-b);
      utils.log("i: " + i);
      const jSet = new Set<number>(Array.from({length: L}, (e, i)=> i+1));
      iSet.forEach(v => jSet.delete(v));
      const j = Array.from(jSet).sort((a,b) => a-b);
      utils.log("j: " + j);

      const proof_value = this.octets_to_proof(proof);
      const dom_for_hash = encode_for_hash([new DirectUin8Array(PK),L,generators.Q1,generators.Q2,...generators.H,this.cs.Ciphersuite_ID,header]);
      utils.log("dom_for_hash: " + dom_for_hash);
      const domain = this.hash_to_scalar(dom_for_hash, 1)[0];
      utils.log("domain: " + domain);
      // C1 = (Abar - D) * c + A' * e^ + Q1 * r2^
      const C1 = proof_value.ABar.subtract(proof_value.D).multiply(proof_value.c)
        .add(proof_value.APrime.multiply(proof_value.eHat))
        .add(generators.Q1.multiply((proof_value.r2Hat))); 
        utils.log(`C1: ${C1}`);
      // T = P1 + Q2 * domain + H_i1 * msg_i1 + ... H_iR * msg_iR
      let T = this.cs.P1;
      T = T.add(generators.Q2.multiply(domain));
      for (let k = 0; k < R; k++) {
        T = T.add(generators.H[i[k]-1].multiply(disclosed_messages[k]));
      }
      // C2 = T * c - D * r3^ + Q_1 * s^ + H_j1 * m^_j1 + ... + H_jU * m^_jU
      let C2 = T.multiply(proof_value.c)
                .subtract(proof_value.D.multiply(proof_value.r3Hat))
                .add(generators.Q1.multiply(proof_value.sHat));
      for (let k = 0; k < U; k++) {
        C2 = C2.add(generators.H[j[k]-1].multiply(proof_value.mHat[k]));
      }
      utils.log("C2: " + C2);
      // cv_array = (A', Abar, D, C1, C2, R, i1, ..., iR, msg_i1, ..., msg_iR, domain, ph)
      const iZeroBased = i.map(v => v-1); // TODO: spec's fixtures assume these are 0-based; double-check that
      const cv_for_hash = encode_for_hash([proof_value.APrime, proof_value.ABar, proof_value.D, C1, C2, R, ...iZeroBased, ...disclosed_messages, domain, ph]);
      utils.log("cv_for_hash: " + cv_for_hash);
      const cv = this.hash_to_scalar(cv_for_hash, 1)[0];                
      utils.log("cv: " + cv);

      if (proof_value.c !== cv) {
        utils.log("c : " + proof_value.c);
        utils.log("cv: " + cv);
        throw "Invalid proof (cv)";
      }

      if (proof_value.APrime.equals(bls.PointG1.ZERO)) {
        throw "Invalid proof (A')";
      }

      // (using the pairing optimization to skip final exponentiation in the pairing
      // and do it after the multiplication)
      const lh = bls.pairing(proof_value.APrime, W, false);
      const rh = bls.pairing(proof_value.ABar, bls.PointG2.BASE.negate(), false);
      const pairing = lh.multiply(rh).finalExponentiate();
      if (!pairing.equals(bls.Fp12.ONE)) {
        throw "Invalid proof (pairing)"
      }
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-creategenerators
  CreateGenerators(length: number): Generators {
      // NOTE: we don't implement CreateGenerators because we need a hash to G1 not supported by the bls library (FIXME)
      const test_vectors: bls.PointG1[] = [
        this.cs.octets_to_point_g1(utils.hexToBytes("90248350d94fd550b472a54269e28b680757d8cbbe6bb2cb000742c07573138276884c2872a8285f4ecf10df6029be15")),
        this.cs.octets_to_point_g1(utils.hexToBytes("8fb7d5c43273a142b6fc445b76a8cdfc0f96c5fdac7cdd73314ac4f7ec4990a0a6f28e4ad97fb0a3a22efb07b386e3ff")),
        this.cs.octets_to_point_g1(utils.hexToBytes("8241e3e861aaac2a54a8d7093301143d7d3e9911c384a2331fcc232a3e64b4882498ce4d9da8904ffcbe5d6eadafc82b")),
        this.cs.octets_to_point_g1(utils.hexToBytes("99bb19d202a4019c14a36933264ae634659994076bf02a94135e1026ea309c7d3fd6da60c7929d30b656aeaba7c0dcec")),
        this.cs.octets_to_point_g1(utils.hexToBytes("81779fa5268e75a980799c0a01677a763e14ba82cbf0a66c653edc174057698636507ac58e73522a59585558dca80b42")),
        this.cs.octets_to_point_g1(utils.hexToBytes("98a3f9af71d391337bc6ae5d26980241b6317d5d71570829ce03d63c17e0d2164e1ad793645e1762bfcc049a17f5994b")),
        this.cs.octets_to_point_g1(utils.hexToBytes("aca6a84770bb1f515591b4b95d69777856ddc52d5439325839e31ce5b6237618a9bc01a04b0057d33eab14341504c7e9")),
        this.cs.octets_to_point_g1(utils.hexToBytes("b96e206d6cf32b51d2f4d543972d488a4c4cbc5d994f6ebb0bdffbc5459dcb9a8e5ab045c5949dc7eb33b0545b62aae3")),
        this.cs.octets_to_point_g1(utils.hexToBytes("8edf840b56ecf8d7c5a9c4a0aaf8a5525f3480df735743298dd2f4ae1cbb56f56ed6a04ef6fa7c92cd68d9101c7b8c8f")),
        this.cs.octets_to_point_g1(utils.hexToBytes("86d4ae04738dc082eb37e753bc8ec35a8d982e463559214d0f777599f71aa1f95780b3dccbdcae45e146e5c7623dfe7d")),
      ];

      const generators: bls.PointG1[] = [];
      for (let i = 0; i < length; i++) {
        generators[i] = test_vectors[i];
      }

      return {
        Q1: this.cs.octets_to_point_g1(utils.hexToBytes("b57ec5e001c28d4063e0b6f5f0a6eee357b51b64d789a21cf18fd11e73e73577910182d421b5a61812f5d1ca751fa3f0")),
        Q2: this.cs.octets_to_point_g1(utils.hexToBytes("909573cbb9da401b89d2778e8a405fdc7d504b03f0158c31ba64cdb9b648cc35492b18e56088b44c8b4dc6310afb5e49")),
        H: generators
      };
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-mapmessagetoscalar
  MapMessageToScalarAsHash(msg: Uint8Array, dst: Uint8Array = Buffer.from(this.cs.Ciphersuite_ID + "MAP_MSG_TO_SCALAR_AS_HASH_", "utf8")): bigint {
    if (dst.length > 255) {
      throw "dst too long";
    }
    const msg_for_hash = encode_for_hash([msg]);
    const result = this.hash_to_scalar(msg_for_hash, 1, dst);
    return result[0];
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-hash-to-scalar
  hash_to_scalar(msg_octets: Uint8Array, count: number, dst: Uint8Array = Buffer.from(this.cs.Ciphersuite_ID + "H2S_", "utf8")): bigint[] {
    const scalars: bigint[] = [];
    const len_in_bytes = count * this.cs.expand_len;
    let t = 0;
    let cont = true;
    while (cont) {
      const msg_prime =  utils.concatBytes(msg_octets, utils.i2osp(t,1), utils.i2osp(count, 4));
      const uniform_bytes = this.cs.expand_message(msg_prime, dst, len_in_bytes);
      for (let i=0; i<count; i++) {
        scalars.push(modR(utils.os2ip(uniform_bytes.slice(i*this.cs.expand_len,(i+1)*this.cs.expand_len))));
      }
      if (scalars.some(v => v == 0n)) {
        t++;
      } else {
        cont = false;
      }
    }
    return scalars;
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-octetstosignature
  octets_to_signature(signature_octets: Uint8Array): BBSSignature {
    if (signature_octets.length !== this.cs.octet_point_length + 2 * this.cs.octet_scalar_length) {
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

    index += this.cs.octet_scalar_length;
    const s = utils.os2ip(signature_octets.slice(index, index + this.cs.octet_scalar_length));
    if (s === 0n || s >= bls.Fr.ORDER) {
      throw "Invalid s"
    }

    return { A: A, e: e, s: s }
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-signaturetooctets
  signature_to_octets(signature: BBSSignature): Uint8Array {
    const A_octets = this.cs.point_to_octets_g1(signature.A);
    const e_octets = utils.i2osp(signature.e, this.cs.octet_scalar_length);
    const s_octets = utils.i2osp(signature.s, this.cs.octet_scalar_length);
    return utils.concatBytes(A_octets, e_octets, s_octets);
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-octetstoproof
  octets_to_proof(proof_octets: Uint8Array): BBSProof {
    const proof_len_floor = 3 * this.cs.octet_point_length + 5 * this.cs.octet_scalar_length;
    if (proof_octets.length < proof_len_floor) {
      throw "invalid proof";
    }

    let index = 0;
    const APrime = this.cs.octets_to_point_g1(proof_octets.slice(index, index + this.cs.octet_point_length));
    index += this.cs.octet_point_length;
    const ABar = this.cs.octets_to_point_g1(proof_octets.slice(index, index + this.cs.octet_point_length));
    index += this.cs.octet_point_length;
    const D = this.cs.octets_to_point_g1(proof_octets.slice(index, index + this.cs.octet_point_length));
    index += this.cs.octet_point_length;

    const c = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length));
    checkNonZeroFr(c, "invalid proof (c)");
    index += this.cs.octet_scalar_length;
    const eHat = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length));
    index += this.cs.octet_scalar_length;
    checkNonZeroFr(eHat, "invalid proof (eHat)");
    const r2Hat = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length));
    index += this.cs.octet_scalar_length;
    checkNonZeroFr(r2Hat, "invalid proof (r2Hat)");
    const r3Hat = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length));
    index += this.cs.octet_scalar_length;
    checkNonZeroFr(r3Hat, "invalid proof (r3Hat)");
    const sHat = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length));
    index += this.cs.octet_scalar_length;
    checkNonZeroFr(sHat, "invalid proof (sHat)");

    const mHat: bigint[] = [];
    while (index  < proof_octets.length ) {
      const msg = utils.os2ip(proof_octets.slice(index, index + this.cs.octet_scalar_length));
      index += this.cs.octet_scalar_length;
      checkNonZeroFr(msg, `invalid proof (mHat[${mHat.length + 1}])`);
      mHat.push(msg);
    }

    return {APrime: APrime, ABar: ABar, D: D, c: c, eHat: eHat, r2Hat: r2Hat, r3Hat: r3Hat, sHat: sHat, mHat: mHat}
  }

  // https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html.html#name-prooftooctets
  proof_to_octets(proof: BBSProof): Uint8Array  {
    let proof_octets_elements: Uint8Array[] = [
      this.cs.point_to_octets_g1(proof.APrime),
      this.cs.point_to_octets_g1(proof.ABar),
      this.cs.point_to_octets_g1(proof.D),
      utils.i2osp(proof.c, this.cs.octet_scalar_length),
      utils.i2osp(proof.eHat, this.cs.octet_scalar_length),
      utils.i2osp(proof.r2Hat, this.cs.octet_scalar_length),
      utils.i2osp(proof.r3Hat, this.cs.octet_scalar_length),
      utils.i2osp(proof.sHat, this.cs.octet_scalar_length)
    ]
    proof.mHat.forEach(msg => 
      {
        proof_octets_elements.push(utils.i2osp(msg, this.cs.octet_scalar_length));
      });

    return utils.concatBytes(...proof_octets_elements);
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
