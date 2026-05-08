import type { GoogleGenAI } from "@google/genai";
import type { SecurityEventRow } from "../types.js";

export interface ClassifyResult {
  id: number;
  classification: "normal" | "suspicious" | "confirmed_attack";
  attack_type: string | null;
  confidence: number;
  reason: string;
  feature_importance?: string;
}

const SCHEMA = `Return ONLY a JSON array (no markdown) of objects with:
id (number), classification ("normal"|"suspicious"|"confirmed_attack"),
attack_type ("ddos"|"brute_force"|"port_scan"|"botnet"|"sqli"|"none"),
confidence (0-1 number), reason (short string), feature_importance (optional string explaining key signals)`;

export async function classifyWithGemini(
  ai: GoogleGenAI,
  events: SecurityEventRow[]
): Promise<ClassifyResult[]> {
  const prompt = `${SCHEMA}
Analyze these security events. Do NOT recommend immediate blocking; classify threat level.
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

export function classifyHeuristic(events: SecurityEventRow[]): ClassifyResult[] {
  return events.map((e) => {
    const desc = (e.description || "").toLowerCase();
    const feat = (e.features_json || "").toLowerCase();
    const combined = desc + feat;
    let classification: ClassifyResult["classification"] = "normal";
    let attack_type: string | null = "none";
    let confidence = 0.55;
    let reason = "Heuristic: no strong attack indicators.";
    let feature_importance = "severity and keywords";

    if (e.ground_truth_label === "attack" || e.severity === "high") {
      classification = "confirmed_attack";
      confidence = 0.82;
      reason = "High severity or dataset-labeled attack pattern.";
    } else if (combined.includes("brute") || combined.includes("patator")) {
      classification = "confirmed_attack";
      attack_type = "brute_force";
      confidence = 0.78;
      reason = "Brute-force pattern in description/features.";
    } else if (combined.includes("ddos") || combined.includes("dos")) {
      classification = "confirmed_attack";
      attack_type = "ddos";
      confidence = 0.8;
      reason = "DDoS-related traffic indicators.";
    } else if (combined.includes("scan") || combined.includes("port")) {
      classification = "suspicious";
      attack_type = "port_scan";
      confidence = 0.7;
      reason = "Port scan-like activity.";
    } else if (combined.includes("sql") || combined.includes("injection")) {
      classification = "confirmed_attack";
      attack_type = "sqli";
      confidence = 0.75;
      reason = "SQL injection indicators.";
    } else if (combined.includes("botnet")) {
      classification = "confirmed_attack";
      attack_type = "botnet";
      confidence = 0.76;
      reason = "Botnet-related indicators.";
    } else if (e.login_success === 0) {
      classification = "suspicious";
      attack_type = "brute_force";
      confidence = 0.62;
      reason = "Failed login attempt; monitor for repeated failures.";
    } else if (e.suspicious_indicators) {
      classification = "suspicious";
      confidence = 0.68;
      reason = `Suspicious indicators: ${e.suspicious_indicators}`;
    }

    if (attack_type === "none" && classification === "confirmed_attack") {
      attack_type = "unknown";
    }

    return {
      id: e.id,
      classification,
      attack_type: attack_type === "none" ? null : attack_type,
      confidence,
      reason,
      feature_importance,
    };
  });
}
