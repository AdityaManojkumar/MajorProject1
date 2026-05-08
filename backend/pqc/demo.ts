/**
 * Educational post-quantum demo (API-shaped).
 * Real Kyber/Dilithium/SPHINCS+ require audited libraries; this returns structured steps.
 */

export function runPqcDemo(): {
  algorithms: Array<{
    name: string;
    family: string;
    quantumResistance: string;
    steps: string[];
  }>;
  message: string;
  note: string;
} {
  return {
    algorithms: [
      {
        name: "CRYSTALS-Kyber",
        family: "Lattice-based KEM (ML-KEM)",
        quantumResistance: "Based on Module-LWE; not broken by Shor's algorithm.",
        steps: [
          "KeyGen: generate lattice-based public/secret key pair.",
          "Encaps: sender derives shared secret under public key.",
          "Decaps: receiver recovers shared secret with secret key.",
        ],
      },
      {
        name: "CRYSTALS-Dilithium",
        family: "Lattice-based signatures (ML-DSA)",
        quantumResistance: "Short integer solution (SIS) hardness; quantum attacks not known to break parameters.",
        steps: [
          "Sign message with secret key (Fiat–Shamir style).",
          "Verify with public key; reject if lattice relation fails.",
        ],
      },
      {
        name: "SPHINCS+",
        family: "Hash-based signatures (SLH-DSA)",
        quantumResistance: "Security reduces to hash function collision/preimage resistance (Grover gives sqrt speedup only).",
        steps: [
          "One-time signatures from hash trees; stateless variant uses hypertree.",
          "Verify by recomputing hash chains.",
        ],
      },
    ],
    message: "Sensitive payload protected with PQC hybrid handshake (demonstration).",
    note: "This endpoint returns an educational walkthrough. Production systems should use standards-compliant libraries (e.g. liboqs, BoringSSL PQC).",
  };
}
