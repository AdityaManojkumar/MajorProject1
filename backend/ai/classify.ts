import type { GoogleGenAI } from "@google/genai";
import type { AttackMetadata, ProtocolAnalysisResult, SecurityEventRow } from "../types.js";

export interface ClassifyResult {
  id: number;
  classification: "normal" | "suspicious" | "confirmed_attack";
  attack_type: string | null;
  confidence: number;
  reason: string;
  feature_importance?: string;
  /** From Protocol Analysis + AI fusion */
  osi_layer?: string;
  protocol?: string;
  severity_score?: number;
  crypto_threat_class?: "classical" | "quantum_cryptographic" | "none";
}

const SCHEMA = `Return ONLY a JSON array (no markdown) of objects with:
id (number), classification ("normal"|"suspicious"|"confirmed_attack"),
attack_type ("ddos"|"brute_force"|"port_scan"|"botnet"|"sqli"|"quantum_crypto"|"none"),
confidence (0-1 number), reason (short string),
osi_layer ("Layer 3 - Network"|"Layer 4 - Transport"|"Layer 7 - Application"),
protocol (string e.g. TCP, UDP, HTTP),
severity_score (0-100 number),
crypto_threat_class ("classical"|"quantum_cryptographic"|"none"),
feature_importance (optional string explaining key L3/L4/L7 signals)`;

function parseProtocolAnalysis(row: SecurityEventRow): ProtocolAnalysisResult | null {
  if (!row.protocol_analysis_json) return null;
  try {
    return JSON.parse(row.protocol_analysis_json) as ProtocolAnalysisResult;
  } catch {
    return null;
  }
}

export async function classifyWithGemini(
  ai: GoogleGenAI,
  events: SecurityEventRow[]
): Promise<ClassifyResult[]> {
  const prompt = `${SCHEMA}
You are the AI Threat Detection Engine. Each event was pre-processed by the Protocol Analysis Layer (L3 network, L4 transport, L7 application features).
Use protocol_analysis and features to assign OSI layer, protocol, severity_score, and crypto_threat_class.
Classical threats: ddos, brute_force, port_scan, botnet, sqli. Quantum cryptographic: RSA/ECC/Shor/PQC-related key compromise.
Events: ${JSON.stringify(
    events.map((e) => ({
      id: e.id,
      source_ip: e.source_ip,
      event_kind: e.event_kind,
      action: e.action,
      login_success: e.login_success,
      dataset: e.dataset,
      ground_truth_label: e.ground_truth_label,
      severity: e.severity,
      description: e.description,
      features: e.features_json,
      protocol_analysis: parseProtocolAnalysis(e),
      pre_osi_layer: e.osi_layer,
      pre_protocol: e.protocol,
    }))
  )}`;

  const response = await ai.models.generateContent({
    model: "gemini-2.0-flash",
    contents: [{ parts: [{ text: prompt }] }],
    config: { responseMimeType: "application/json" },
  });

  const text = (response.text || "[]").trim();
  try {
    const parsed = JSON.parse(text) as ClassifyResult[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    const m = text.match(/\[[\s\S]*\]/);
    if (m) {
      const parsed = JSON.parse(m[0]) as ClassifyResult[];
      return Array.isArray(parsed) ? parsed : [];
    }
    throw new Error("Invalid JSON from model");
  }
}

function severityScoreFromClassification(
  classification: ClassifyResult["classification"],
  event: SecurityEventRow
): number {
  if (classification === "confirmed_attack") return event.severity === "high" ? 92 : 85;
  if (classification === "suspicious") return 58;
  return 25;
}

export function classifyHeuristic(events: SecurityEventRow[]): ClassifyResult[] {
  return events.map((e) => {
    const desc = (e.description || "").toLowerCase();
    const feat = (e.features_json || "").toLowerCase();
    const combined = desc + feat;
    let classification: ClassifyResult["classification"] = "normal";
    let attack_type: string | null = "none";
    let confidence = 0.55;
    let reason = "Heuristic: no strong attack indicators.";
    let feature_importance = "severity and L3/L4/L7 keywords";
    let osi_layer = e.osi_layer || "Layer 7 - Application";
    let protocol = e.protocol || "TCP";
    let crypto_threat_class: ClassifyResult["crypto_threat_class"] = "none";

    if (combined.includes("quantum") || combined.includes("shor") || combined.includes("rsa factor")) {
      classification = "suspicious";
      attack_type = "quantum_crypto";
      crypto_threat_class = "quantum_cryptographic";
      osi_layer = "Layer 7 - Application";
      protocol = "TLS";
      reason = "Quantum-era cryptographic threat indicators (RSA/ECC break class).";
      confidence = 0.72;
    } else if (e.ground_truth_label === "attack" || e.severity === "high") {
      classification = "confirmed_attack";
      confidence = 0.82;
      reason = "High severity or dataset-labeled attack pattern.";
      osi_layer = combined.includes("ddos") ? "Layer 3 - Network" : osi_layer;
    } else if (combined.includes("brute") || combined.includes("patator")) {
      classification = "confirmed_attack";
      attack_type = "brute_force";
      confidence = 0.78;
      osi_layer = "Layer 7 - Application";
      protocol = "HTTP";
      reason = "Brute-force pattern in L7 auth features.";
    } else if (combined.includes("ddos") || combined.includes("dos")) {
      classification = "confirmed_attack";
      attack_type = "ddos";
      confidence = 0.8;
      osi_layer = "Layer 3 - Network";
      protocol = "TCP";
      reason = "DDoS-related L3 flow/packet indicators.";
    } else if (combined.includes("scan") || combined.includes("port")) {
      classification = "suspicious";
      attack_type = "port_scan";
      confidence = 0.7;
      osi_layer = "Layer 4 - Transport";
      protocol = "TCP";
      reason = "Port scan-like L4 connection attempts.";
    } else if (combined.includes("sql") || combined.includes("injection")) {
      classification = "confirmed_attack";
      attack_type = "sqli";
      confidence = 0.75;
      osi_layer = "Layer 7 - Application";
      protocol = "HTTP";
      reason = "SQL injection indicators at application layer.";
    } else if (combined.includes("botnet")) {
      classification = "confirmed_attack";
      attack_type = "botnet";
      confidence = 0.76;
      osi_layer = "Layer 3 - Network";
      reason = "Botnet-related L3 coordination indicators.";
    } else if (e.login_success === 0) {
      classification = "suspicious";
      attack_type = "brute_force";
      confidence = 0.62;
      osi_layer = "Layer 7 - Application";
      protocol = "HTTP";
      reason = "Failed login attempt; monitor L7 auth frequency.";
    } else if (e.suspicious_indicators) {
      classification = "suspicious";
      confidence = 0.68;
      osi_layer = "Layer 7 - Application";
      reason = `Suspicious L7 indicators: ${e.suspicious_indicators}`;
    }

    if (attack_type === "none" && classification === "confirmed_attack") {
      attack_type = "unknown";
    }

    if (crypto_threat_class === "none" && classification !== "normal") {
      crypto_threat_class = attack_type === "quantum_crypto" ? "quantum_cryptographic" : "classical";
    }

    const severity_score = severityScoreFromClassification(classification, e);

    return {
      id: e.id,
      classification,
      attack_type: attack_type === "none" ? null : attack_type,
      confidence,
      reason,
      feature_importance,
      osi_layer,
      protocol,
      severity_score,
      crypto_threat_class,
    };
  });
}

/** Merge AI/heuristic result with protocol-layer defaults when fields are missing. */
export function normalizeClassifyResult(
  r: ClassifyResult,
  event: SecurityEventRow,
  metadata: AttackMetadata
): ClassifyResult {
  return {
    ...r,
    osi_layer: r.osi_layer || metadata.osi_layer,
    protocol: r.protocol || metadata.protocol,
    severity_score: r.severity_score ?? metadata.severity_score,
    crypto_threat_class: r.crypto_threat_class || metadata.crypto_threat_class,
  };
}
