import type { ClassifyResult } from "./classify.js";

export interface AnalysisDisplayRow extends ClassifyResult {
  httpStatus: number;
  statusLine: string;
  attackSummary: string;
  recommendation: string;
}

function classificationToHttp(
  c: ClassifyResult["classification"]
): { httpStatus: number; statusLine: string } {
  if (c === "confirmed_attack") {
    return {
      httpStatus: 403,
      statusLine: "403 Forbidden – attack-like pattern; block or quarantine per policy",
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

function attackTypeLongSummary(attackType: string | null): string {
  const t = (attackType || "none").toLowerCase();
  const map: Record<string, string> = {
    ddos: "Denial-of-service or flood-style volume / reflector behavior (network layer).",
    brute_force: "Credential stuffing, repeated auth failures, or password guessing (application/auth).",
    port_scan: "Reconnaissance, wide port sweep, or mapping of services (network scan).",
    botnet: "C2-style coordination, malware beacons, or distributed bot activity (if labeled in data).",
    sqli: "SQL or code injection in request content (application layer).",
    unknown: "Heuristic or generic threat — review features and context.",
    none: "No specific attack family assigned; treat as general classification output.",
  };
  return map[t] || map.unknown;
}

function recommendationLine(
  c: ClassifyResult["classification"],
  attackType: string | null
): string {
  if (c === "confirmed_attack") {
    return `Action: contain source, alert SOC, and apply block rules for ${attackType || "this pattern"}.`;
  }
  if (c === "suspicious") {
    return "Action: increase logging, require step-up auth, or throttle; confirm before hard block.";
  }
  return "Action: allow with baseline monitoring; no block from this signal alone.";
}

export function enrichAnalysisResult(r: ClassifyResult): AnalysisDisplayRow {
  const { httpStatus, statusLine } = classificationToHttp(r.classification);
  return {
    ...r,
    httpStatus,
    statusLine,
    attackSummary: attackTypeLongSummary(r.attack_type),
    recommendation: recommendationLine(r.classification, r.attack_type),
  };
}

export function enrichAnalysisResults(results: ClassifyResult[]): AnalysisDisplayRow[] {
  return results.map(enrichAnalysisResult);
}
