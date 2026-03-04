/**
 * Post-Quantum Cryptography (PQC) Simulation
 * Using a simplified Learning With Errors (LWE) based scheme.
 * 
 * LWE is a lattice-based hard problem that is believed to be 
 * resistant to quantum computing attacks (Shor's Algorithm).
 */

export class PQCService {
  private static q = 257; // A small prime modulus
  private static n = 10;  // Dimension of the secret vector
  private static m = 20;  // Number of samples in the public key
  private static errorBound = 2; // Small error range

  /**
   * Generates a keypair based on LWE.
   * Public Key: (A, b) where b = As + e
   * Private Key: s
   */
  static generateKeyPair() {
    // Secret vector s (private key)
    const s = Array.from({ length: this.n }, () => Math.floor(Math.random() * this.q));

    // Matrix A (part of public key)
    const A = Array.from({ length: this.m }, () => 
      Array.from({ length: this.n }, () => Math.floor(Math.random() * this.q))
    );

    // Error vector e
    const e = Array.from({ length: this.m }, () => Math.floor(Math.random() * (2 * this.errorBound + 1)) - this.errorBound);

    // Vector b = As + e (part of public key)
    const b = A.map((row, i) => {
      const dotProduct = row.reduce((sum, val, j) => (sum + val * s[j]) % this.q, 0);
      return (dotProduct + e[i] + this.q) % this.q;
    });

    return {
      publicKey: { A, b },
      privateKey: s
    };
  }

  /**
   * Encrypts a single bit using the public key.
   * To encrypt a message, we encrypt each bit.
   */
  static encryptBit(bit: number, publicKey: { A: number[][], b: number[] }) {
    const { A, b } = publicKey;
    
    // Choose a random subset of samples
    const subset = Array.from({ length: this.m }, () => Math.random() > 0.5 ? 1 : 0);
    
    // u = sum(A_i) for i in subset
    const u = Array.from({ length: this.n }, (_, j) => 
      subset.reduce((sum, val, i) => (sum + val * A[i][j]) % this.q, 0)
    );

    // v = sum(b_i) + bit * (q/2) for i in subset
    const v_sum = subset.reduce((sum, val, i) => (sum + val * b[i]) % this.q, 0);
    const v = (v_sum + bit * Math.floor(this.q / 2)) % this.q;

    return { u, v };
  }

  /**
   * Decrypts a single bit using the private key.
   */
  static decryptBit(ciphertext: { u: number[], v: number }, privateKey: number[]) {
    const { u, v } = ciphertext;
    
    // result = v - u * s
    const dotProduct = u.reduce((sum, val, i) => (sum + val * privateKey[i]) % this.q, 0);
    const result = (v - dotProduct + this.q) % this.q;

    // If result is closer to q/2 than 0, it's a 1
    const diffToHalf = Math.abs(result - Math.floor(this.q / 2));
    const diffToZero = Math.min(result, this.q - result);

    return diffToHalf < diffToZero ? 1 : 0;
  }

  /**
   * Encrypts a string message.
   */
  static encryptMessage(message: string, publicKey: { A: number[][], b: number[] }) {
    const bits: number[] = [];
    for (let i = 0; i < message.length; i++) {
      const charCode = message.charCodeAt(i);
      for (let j = 0; j < 8; j++) {
        bits.push((charCode >> j) & 1);
      }
    }

    return bits.map(bit => this.encryptBit(bit, publicKey));
  }

  /**
   * Decrypts a string message.
   */
  static decryptMessage(ciphertexts: { u: number[], v: number }[], privateKey: number[]) {
    const bits = ciphertexts.map(ct => this.decryptBit(ct, privateKey));
    let message = "";
    for (let i = 0; i < bits.length; i += 8) {
      let charCode = 0;
      for (let j = 0; j < 8; j++) {
        charCode |= (bits[i + j] << j);
      }
      message += String.fromCharCode(charCode);
    }
    return message;
  }
}
