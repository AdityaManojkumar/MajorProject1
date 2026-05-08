export type EventKind = "login" | "network" | "application";
export type EventAction =
  | "login_attempt"
  | "auth_success"
  | "auth_failure"
  | "traffic"
  | "layer7_trace";

export type Classification = "normal" | "suspicious" | "confirmed_attack";
export type AttackType =
  | "ddos"
  | "brute_force"
  | "port_scan"
  | "botnet"
  | "sqli"
  | "none";

export interface SecurityEventRow {
  id: number;
  timestamp: string;
  source_ip: string;
  event_kind: EventKind;
  action: EventAction;
  login_success: number | null;
  username: string | null;
  features_json: string | null;
  dataset: string | null;
  ground_truth_label: string | null;
  classification: Classification | null;
  attack_type: AttackType | null;
  confidence: number | null;
  reason: string | null;
  severity: string;
  description: string;
  status: string;
  suspicious_indicators: string | null;
}
