export interface SecurityEvent {
  id: number;
  timestamp: string;
  source_ip: string;
  event_kind: string;
  action: string;
  login_success: number | null;
  username: string | null;
  features_json: string | null;
  dataset: string | null;
  ground_truth_label: string | null;
  classification: string | null;
  attack_type: string | null;
  confidence: number | null;
  reason: string | null;
  severity: string;
  description: string;
  status: string;
  suspicious_indicators: string | null;
  osi_layer?: string | null;
  protocol?: string | null;
  severity_score?: number | null;
  crypto_threat_class?: string | null;
  mitigation_status?: string | null;
  attack_metadata_json?: string | null;
  protocol_analysis_json?: string | null;
}

export interface ProtocolThreatRow {
  id: number;
  timestamp: string;
  source_ip: string;
  attack_type: string | null;
  protocol: string | null;
  osi_layer: string | null;
  severity_score: number | null;
  crypto_threat_class: string | null;
  mitigation_status: string | null;
  classification: string | null;
  attack_metadata_json: string | null;
  description: string;
}

export interface DashboardStats {
  classicalAttacksDetected: number;
  suspiciousEvents: number;
  normalClassified: number;
  quantumVulnerabilityDemos: number;
  datasetInjectedEvents?: number;
  simulatedAttackEvents?: number;
  loginDemoEvents?: number;
  classicalDemoTraffic?: number;
  pqcStatus: string;
  rsaStatus: string;
}
