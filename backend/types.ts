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
  | "quantum_crypto"
  | "none";

/** OSI layer label used in attack metadata and mitigation routing. */
export type OsiLayerLabel =
  | "Layer 3 - Network"
  | "Layer 4 - Transport"
  | "Layer 7 - Application";

export type CryptoThreatClass = "classical" | "quantum_cryptographic" | "none";

export type MitigationStatus = "pending" | "applied" | "none";

export interface Layer3Features {
  sourceIp: string;
  destinationIp: string;
  packetCount: number;
  flowStatistics: {
    bytesPerSecond: number;
    packetsPerSecond: number;
    flowDurationMs: number;
  };
}

export interface Layer4Features {
  protocol: string;
  tcpFlags: string[];
  sourcePort: number | null;
  destinationPort: number | null;
  connectionAttempts: number;
  sessionDurationMs: number;
}

export interface Layer7Features {
  authenticationRequests: number;
  apiRequests: number;
  loginFailures: number;
  requestFrequencyPerMinute: number;
}

/** Output of the Protocol Analysis Layer (between app backend and AI engine). */
export interface ProtocolAnalysisResult {
  layer3: Layer3Features;
  layer4: Layer4Features;
  layer7: Layer7Features;
  primaryOsiLayer: OsiLayerLabel;
  detectedProtocol: string;
}

/** Structured attack metadata mapped to the OSI model. */
export interface AttackMetadata {
  attack_type: string;
  osi_layer: OsiLayerLabel;
  protocol: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  severity_score: number;
  crypto_threat_class: CryptoThreatClass;
}

export interface MitigationActionRow {
  id: number;
  event_id: number;
  osi_layer: string;
  action_type: string;
  status: string;
  details: string;
  timestamp: string;
}

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
  /** Populated by Protocol Analysis Layer */
  osi_layer: string | null;
  protocol: string | null;
  severity_score: number | null;
  crypto_threat_class: CryptoThreatClass | null;
  mitigation_status: MitigationStatus | null;
  attack_metadata_json: string | null;
  protocol_analysis_json: string | null;
}
