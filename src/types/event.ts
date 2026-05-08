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
