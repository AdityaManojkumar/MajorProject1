/**
 * Simulated comparison: RSA confidentiality falls once the modulus is factored (Shor-class threat),
 * while a toy lattice ciphertext stays unreadable without the private vector (same hard problem family as Kyber).
 */

import { runRsaShorDemo } from "../quantum/rsa-shor.js";
import {
  decryptToyLweWithWrongKey,
  encryptToyLweMessage,
  decryptToyLweMessage,
  generateToyLweKeyPair,
  randomWrongSecretKey,
} from "./toy-lwe.js";

const MAX_MSG = 48;

export interface RsaLatticeProtectionResult {
  runId: string;
  completedAt: string;
  processingMs: number;
  summary: string;
  secretPayload: string;
  rsa: {
    modulusN: number;
    bitLength: number;
    ciphertextBlocks: number;
    attackLabel: string;
    attackerRecoveredSecret: string;
    secretLeaked: boolean;
    explanation: string;
  };
  lattice: {
    ciphertextBitBlocks: number;
    schemeNote: string;
    attackerRecoveredGarbage: string;
    legitimateRecoveredSecret: string;
    latticeProtectsPayload: boolean;
    explanation: string;
  };
  takeaway: string;
}

function garbledPreview(s: string): string {
  const printable = [...s].every((c) => {
    const code = c.charCodeAt(0);
    return code >= 32 && code < 127;
  });
  if (printable && s.length <= 120) return s;
  const hex = Buffer.from(s, "utf8").toString("hex");
  return `〈not valid UTF-8 / wrong key — ${hex.slice(0, 48)}${hex.length > 48 ? "…" : ""}〉`;
}

export function runRsaLatticeProtectionDemo(rawMessage?: string): RsaLatticeProtectionResult {
  const t0 = Date.now();
  const secretPayload =
    typeof rawMessage === "string" && rawMessage.trim().length > 0
      ? rawMessage.trim().slice(0, MAX_MSG)
      : "Secret payload: session AW7 • rotate credentials";

  const rsa = runRsaShorDemo(secretPayload);
  /** After factoring n (Shor-class), attacker recomputes d and decrypts — same string as legitimate decrypt here. */
  const attackerRecoveredSecret = rsa.decrypted;

  const { publicKey, privateKey } = generateToyLweKeyPair();
  const latticeCt = encryptToyLweMessage(secretPayload, publicKey);
  const wrongKey = randomWrongSecretKey();
  const attackerGarbage = decryptToyLweWithWrongKey(latticeCt, wrongKey);
  const legitimate = decryptToyLweMessage(latticeCt, privateKey);

  const latticeProtects = legitimate === secretPayload && attackerGarbage !== secretPayload;

  const summary =
    "RSA layer: modulus factored → secret leaked. Lattice layer: same secret remains confidential without the private vector.";

  const processingMs = Date.now() - t0;
  const runId = `PQ-${t0.toString(36)}-${Math.random().toString(36).slice(2, 8)}`.toUpperCase();

  return {
    runId,
    completedAt: new Date().toISOString(),
    processingMs,
    summary,
    secretPayload,
    rsa: {
      modulusN: rsa.n,
      bitLength: Math.ceil(Math.log2(rsa.n + 1)),
      ciphertextBlocks: rsa.ciphertext.length,
      attackLabel: "Quantum-era threat: integer factorization (e.g. Shor) breaks RSA confidentiality at scale",
      attackerRecoveredSecret,
      secretLeaked: attackerRecoveredSecret === secretPayload,
      explanation:
        "Demo uses tiny RSA; intercept ciphertext + factor n (simulated Shor output) → rebuild φ(n) and d → plaintext recovered.",
    },
    lattice: {
      ciphertextBitBlocks: latticeCt.length,
      schemeNote: "Toy LWE-style encryption (same hardness family as Kyber / ML-KEM; not full Kyber)",
      attackerRecoveredGarbage: garbledPreview(attackerGarbage),
      legitimateRecoveredSecret: legitimate,
      latticeProtectsPayload: latticeProtects,
      explanation:
        "Attacker sees public key + ciphertext but not the short secret vector; wrong key ⇒ wrong noise alignment ⇒ garbage bits — no factorization shortcut.",
    },
    takeaway:
      "Migrating sensitive data to post-quantum (lattice/hash) crypto protects confidentiality even when legacy RSA falls to a quantum-capable factorization adversary.",
  };
}
