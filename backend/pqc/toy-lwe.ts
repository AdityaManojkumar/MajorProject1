/**
 * Toy LWE-style public-key encryption (browser PQCService mirrored for backend demos).
 * Educational only — tiny modulus, not Kyber.
 */

const Q = 257;
const N_DIM = 10;
const M_SAMPLES = 20;
const ERROR_BOUND = 2;

export type ToyLwePublicKey = { A: number[][]; b: number[] };
export type ToyLweSecretKey = number[];
export type ToyLweCt = { u: number[]; v: number };

function randMod(q: number): number {
  return Math.floor(Math.random() * q);
}

export function generateToyLweKeyPair(): { publicKey: ToyLwePublicKey; privateKey: ToyLweSecretKey } {
  const s = Array.from({ length: N_DIM }, () => randMod(Q));
  const A = Array.from({ length: M_SAMPLES }, () =>
    Array.from({ length: N_DIM }, () => randMod(Q))
  );
  const e = Array.from({ length: M_SAMPLES }, () =>
    Math.floor(Math.random() * (2 * ERROR_BOUND + 1)) - ERROR_BOUND
  );
  const b = A.map((row, i) => {
    const dot = row.reduce((sum, val, j) => (sum + val * s[j]) % Q, 0);
    return (dot + e[i] + Q) % Q;
  });
  return { publicKey: { A, b }, privateKey: s };
}

function encryptBit(bit: number, publicKey: ToyLwePublicKey): ToyLweCt {
  const { A, b } = publicKey;
  const subset = Array.from({ length: M_SAMPLES }, () => (Math.random() > 0.5 ? 1 : 0));
  const u = Array.from({ length: N_DIM }, (_, j) =>
    subset.reduce((sum, val, i) => (sum + val * A[i][j]) % Q, 0)
  );
  const vSum = subset.reduce((sum, val, i) => (sum + val * b[i]) % Q, 0);
  const v = (vSum + bit * Math.floor(Q / 2)) % Q;
  return { u, v };
}

function decryptBit(ct: ToyLweCt, privateKey: ToyLweSecretKey): number {
  const { u, v } = ct;
  const dot = u.reduce((sum, val, i) => (sum + val * privateKey[i]) % Q, 0);
  const result = (v - dot + Q) % Q;
  const diffToHalf = Math.abs(result - Math.floor(Q / 2));
  const diffToZero = Math.min(result, Q - result);
  return diffToHalf < diffToZero ? 1 : 0;
}

export function encryptToyLweMessage(message: string, publicKey: ToyLwePublicKey): ToyLweCt[] {
  const bits: number[] = [];
  for (let i = 0; i < message.length; i++) {
    const code = message.charCodeAt(i);
    for (let j = 0; j < 8; j++) bits.push((code >> j) & 1);
  }
  return bits.map((bit) => encryptBit(bit, publicKey));
}

export function decryptToyLweMessage(ciphertexts: ToyLweCt[], privateKey: ToyLweSecretKey): string {
  const bits = ciphertexts.map((ct) => decryptBit(ct, privateKey));
  let message = "";
  for (let i = 0; i < bits.length; i += 8) {
    let charCode = 0;
    for (let j = 0; j < 8; j++) charCode |= (bits[i + j] ?? 0) << j;
    message += String.fromCharCode(charCode);
  }
  return message;
}

/** Attacker without the secret key — wrong key yields wrong bits → unreadable payload. */
export function decryptToyLweWithWrongKey(ciphertexts: ToyLweCt[], wrongKey: ToyLweSecretKey): string {
  return decryptToyLweMessage(ciphertexts, wrongKey);
}

export function randomWrongSecretKey(): ToyLweSecretKey {
  return Array.from({ length: N_DIM }, () => randMod(Q));
}
