import type { ClassifyResult } from "./classify.js";

export interface AnalysisDisplayRow extends ClassifyResult {
  httpStatus: number;
  statusLine: string;
  attackSummary: string;
  recommendation: string;
  mitigation_hint: string;
}

function classificationToHttp(
  c: ClassifyResult["classification"]
): { httpStatus: number; statusLine: string } {
  if (c === "confirmed_attack") {
    return {
      httpStatus: 403,
      statusLine: "403 Forbidden – attack-like pattern; layer-aware block per policy",
    };
  }
  if (c === "suspicious") {
    return {
      httpStatus: 429,
      statusLine: "429 / elevated risk – hold, verify, or rate-limit",
    };
  }
  return {
    httpStatus: 200,
    statusLine: "200 OK – no hostile pattern detected for this event",
  };
}

function attackTypeLongSummary(attackType: string | null, osiLayer?: string): string {
  const t = (attackType || "none").toLowerCase();
  const layer = osiLayer ? ` (${osiLayer})` : "";
  const map: Record<string, string> = {
    ddos: `Denial-of-service or flood-style volume${layer}.`,
    brute_force: `Credential stuffing or repeated auth failures${layer}.`,
    port_scan: `Reconnaissance or port sweep${layer}.`,
    botnet: `C2-style or distributed bot activity${layer}.`,
    sqli: `SQL or code injection in request content${layer}.`,
    quantum_crypto: `Quantum-era cryptographic threat — RSA/ECC confidentiality at risk${layer}.`,
    unknown: `Heuristic threat — review protocol features and context${layer}.`,
    none: "No specific attack family assigned.",
  };
  return map[t] || map.unknown;
}

function mitigationHint(osiLayer?: string, cryptoClass?: string): string {
  if (cryptoClass === "quantum_cryptographic") {
    return "Mitigation: enable PQC (Kyber/Dilithium); rotate RSA/ECC keys; monitor crypto-agility posture.";
  }
  switch (osiLayer) {
    case "Layer 3 - Network":
      return "Mitigation: IP blocking and rate limiting (L3).";
    case "Layer 4 - Transport":
      return "Mitigation: port blocking and session termination (L4).";
    case "Layer 7 - Application":
      return "Mitigation: account lockout and API throttling (L7).";
    default:
      return "Mitigation: follow SOC playbook for classified layer.";
  }
}

function recommendationLine(
  c: ClassifyResult["classification"],
  attackType: string | null,
  osiLayer?: string
): string {
  const layer = osiLayer ? ` at ${osiLayer}` : "";
  if (c === "confirmed_attack") {
    return `Action: apply layer-aware containment${layer} for ${attackType || "this pattern"}.`;
  }
  if (c === "suspicious") {
    return `Action: increase logging and throttle${layer}; confirm before hard block.`;
  }
  return "Action: allow with baseline monitoring; no block from this signal alone.";
}

export function enrichAnalysisResult(r: ClassifyResult): AnalysisDisplayRow {
  const { httpStatus, statusLine } = classificationToHttp(r.classification);
  return {
    ...r,
    httpStatus,
    statusLine,
    attackSummary: attackTypeLongSummary(r.attack_type, r.osi_layer),
    recommendation: recommendationLine(r.classification, r.attack_type, r.osi_layer),
    mitigation_hint: mitigationHint(r.osi_layer, r.crypto_threat_class),
  };
}

export function enrichAnalysisResults(results: ClassifyResult[]): AnalysisDisplayRow[] {
  return results.map(enrichAnalysisResult);
}
