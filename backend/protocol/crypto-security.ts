/**
 * Cross-Layer Cryptographic Security Module.
 * Classifies whether a threat is classical (network/app) or quantum-era (crypto break / PQC migration).
 */
import type { CryptoThreatClass, ProtocolAnalysisResult, SecurityEventRow } from "../types.js";

const QUANTUM_KEYWORDS = [
  "quantum",
  "shor",
  "rsa",
  "ecc",
  "elliptic",
  "factor",
  "lattice",
  "pqc",
  "kyber",
  "dilithium",
  "post-quantum",
  "cryptographic",
  "private key",
  "modulus",
];

const CLASSICAL_ATTACK_TYPES = new Set([
  "ddos",
  "brute_force",
  "port_scan",
  "botnet",
  "sqli",
  "dos",
  "scan",
  "flood",
  "malware",
]);

/**
 * Determine if the threat targets classical infrastructure or quantum-vulnerable cryptography.
 * Layer 3/4/7 classical attacks → "classical".
 * RSA/ECC/Shor/PQC-related signals → "quantum_cryptographic".
 */
export function classifyCryptoThreat(
  event: SecurityEventRow,
  analysis: ProtocolAnalysisResult,
  attackType: string | null
): CryptoThreatClass {
  const combined = `${event.description || ""} ${event.features_json || ""} ${event.reason || ""}`.toLowerCase();
  const atk = (attackType || "").toLowerCase();

  if (atk === "quantum_crypto" || atk.includes("quantum")) return "quantum_cryptographic";

  for (const kw of QUANTUM_KEYWORDS) {
    if (combined.includes(kw)) return "quantum_cryptographic";
  }

  if (CLASSICAL_ATTACK_TYPES.has(atk)) return "classical";

  if (analysis.primaryOsiLayer === "Layer 7 - Application" && analysis.layer7.apiRequests === 0) {
    // Pure auth/login abuse remains classical
    return "classical";
  }

  if (event.ground_truth_label === "attack" && !combined.includes("rsa")) {
    return "classical";
  }

  return event.classification === "normal" ? "none" : "classical";
}

/** Human-readable protection note for dashboard / docs. */
export function cryptoProtectionSummary(threatClass: CryptoThreatClass): string {
  switch (threatClass) {
    case "quantum_cryptographic":
      return "Mitigate via PQC migration (Kyber/Dilithium); classical IDS rules insufficient for key compromise.";
    case "classical":
      return "Protected by network monitoring, AI classification, and layer-aware incident response.";
    default:
      return "No active cryptographic threat signal.";
  }
}

/**
 * OSI layers protected by the platform's cross-layer security stack.
 * Used in architecture documentation and API responses.
 */
export const PROTECTED_OSI_LAYERS = [
  {
    layer: "Layer 3 - Network",
    protection: "Flow analytics, DDoS detection, IP blocking, rate limiting",
    quantumNote: "Classical flood/recon; PQC does not replace L3 controls",
  },
  {
    layer: "Layer 4 - Transport",
    protection: "TCP flag analysis, port blocking, session termination",
    quantumNote: "Transport integrity separate from post-quantum key exchange",
  },
  {
    layer: "Layer 7 - Application",
    protection: "Auth/API monitoring, account lockout, API throttling",
    quantumNote: "Application data protected by migrating to PQC ciphersuites",
  },
  {
    layer: "Cryptographic (cross-layer)",
    protection: "PQC module: lattice/Kyber-style demos vs RSA vulnerability",
    quantumNote: "Addresses Shor-class breaks on RSA/ECC public-key confidentiality",
  },
] as const;
