/**
 * Protocol Analysis Layer — sits between the backend application and the AI Threat Detection Engine.
 * Inspects incoming traffic and extracts L3/L4/L7 features before classification.
 */
import type {
  Layer3Features,
  Layer4Features,
  Layer7Features,
  OsiLayerLabel,
  ProtocolAnalysisResult,
  SecurityEventRow,
} from "../types.js";

function parseFeatures(raw: string | null): Record<string, unknown> {
  if (!raw) return {};
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function num(v: unknown, fallback: number): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function str(v: unknown, fallback: string): string {
  return typeof v === "string" && v.length ? v : fallback;
}

function inferDestinationIp(sourceIp: string, features: Record<string, unknown>): string {
  const dest =
    str(features.destination_ip, "") ||
    str(features.dest_ip, "") ||
    str(features.Destination, "") ||
    str(features.dst_ip, "");
  if (dest) return dest;
  if (sourceIp.startsWith("192.168.") || sourceIp.startsWith("10.")) return "203.0.113.10";
  return "10.0.0.1";
}

function inferProtocol(event: SecurityEventRow, features: Record<string, unknown>): string {
  const fromFeat =
    str(features.protocol, "") ||
    str(features.proto, "") ||
    str(features.Protocol, "") ||
    str(features.l4_proto, "");
  if (fromFeat) return fromFeat.toUpperCase();
  if (event.event_kind === "login" || event.action.startsWith("auth")) return "HTTP";
  if (event.event_kind === "application") return "HTTP";
  return "TCP";
}

function inferTcpFlags(event: SecurityEventRow, features: Record<string, unknown>): string[] {
  const raw = features.tcp_flags ?? features.flags ?? features.Flag;
  if (Array.isArray(raw)) return raw.map(String);
  if (typeof raw === "string" && raw.length) return raw.split(/[\s,|]+/).filter(Boolean);
  const desc = (event.description || "").toLowerCase();
  if (desc.includes("syn flood") || desc.includes("ddos")) return ["SYN", "ACK"];
  if (desc.includes("scan")) return ["SYN"];
  if (event.event_kind === "network") return ["SYN", "ACK"];
  return ["ACK"];
}

function inferPorts(features: Record<string, unknown>): { src: number | null; dst: number | null } {
  const dst = num(features.destination_port ?? features.dst_port ?? features.DstPort ?? features.dport, NaN);
  const src = num(features.source_port ?? features.src_port ?? features.SrcPort ?? features.sport, NaN);
  return {
    src: Number.isFinite(src) ? src : null,
    dst: Number.isFinite(dst) ? dst : 443,
  };
}

function extractLayer3(event: SecurityEventRow, features: Record<string, unknown>): Layer3Features {
  const packetCount = num(
    features.packet_count ?? features.Packets ?? features.total_packets ?? features.flow_packets,
    event.severity === "high" ? 1200 : event.event_kind === "network" ? 480 : 64
  );
  const durationMs = num(features.flow_duration_ms ?? features.Duration ?? features.duration, 5000);
  const pps = num(features.packets_per_second, Math.max(1, Math.round(packetCount / Math.max(1, durationMs / 1000))));
  const bps = num(features.bytes_per_second, pps * 512);

  return {
    sourceIp: event.source_ip,
    destinationIp: inferDestinationIp(event.source_ip, features),
    packetCount,
    flowStatistics: {
      bytesPerSecond: bps,
      packetsPerSecond: pps,
      flowDurationMs: durationMs,
    },
  };
}

function extractLayer4(event: SecurityEventRow, features: Record<string, unknown>): Layer4Features {
  const protocol = inferProtocol(event, features);
  const ports = inferPorts(features);
  const connectionAttempts = num(
    features.connection_attempts ?? features.conn_count ?? features.Flows,
    event.event_kind === "network" ? 24 : event.event_kind === "login" ? 3 : 1
  );
  const sessionDurationMs = num(
    features.session_duration_ms ?? features.session_ms ?? features.Duration,
    event.event_kind === "login" ? 1200 : 8000
  );

  return {
    protocol,
    tcpFlags: inferTcpFlags(event, features),
    sourcePort: ports.src,
    destinationPort: ports.dst,
    connectionAttempts,
    sessionDurationMs,
  };
}

function extractLayer7(event: SecurityEventRow, features: Record<string, unknown>): Layer7Features {
  const isAuth = event.event_kind === "login" || event.action.startsWith("auth");
  const loginFailures =
    event.login_success === 0 ? 1 : num(features.login_failures ?? features.failed_logins, 0);
  const authRequests = isAuth
    ? num(features.authentication_requests, 1)
    : num(features.authentication_requests, 0);
  const apiRequests = num(
    features.api_requests ?? features.http_requests ?? features.request_count,
    event.event_kind === "application" ? 12 : isAuth ? 2 : 0
  );
  const rpm = num(
    features.requests_per_minute ?? features.req_freq,
    event.severity === "high" ? 180 : apiRequests > 0 ? 45 : 8
  );

  if (event.suspicious_indicators) {
    return {
      authenticationRequests: Math.max(authRequests, 3),
      apiRequests: Math.max(apiRequests, 6),
      loginFailures: Math.max(loginFailures, 2),
      requestFrequencyPerMinute: Math.max(rpm, 60),
    };
  }

  return {
    authenticationRequests: authRequests,
    apiRequests,
    loginFailures,
    requestFrequencyPerMinute: rpm,
  };
}

/** Determine primary OSI layer from extracted features and event semantics. */
export function resolvePrimaryOsiLayer(
  event: SecurityEventRow,
  layer3: Layer3Features,
  layer4: Layer4Features,
  layer7: Layer7Features
): OsiLayerLabel {
  const desc = (event.description || "").toLowerCase();
  const feat = (event.features_json || "").toLowerCase();

  if (
    event.event_kind === "login" ||
    event.action.startsWith("auth") ||
    event.event_kind === "application" ||
    layer7.loginFailures > 0 ||
    layer7.authenticationRequests > 0 ||
    desc.includes("sql") ||
    desc.includes("injection") ||
    desc.includes("api")
  ) {
    return "Layer 7 - Application";
  }

  if (
    desc.includes("ddos") ||
    desc.includes("dos") ||
    desc.includes("flood") ||
    layer3.packetCount > 800 ||
    layer3.flowStatistics.packetsPerSecond > 120 ||
    feat.includes("ddos")
  ) {
    return "Layer 3 - Network";
  }

  if (
    desc.includes("scan") ||
    desc.includes("port") ||
    layer4.connectionAttempts > 10 ||
    (layer4.destinationPort !== null && layer4.destinationPort < 1024 && layer4.connectionAttempts > 4)
  ) {
    return "Layer 4 - Transport";
  }

  if (event.event_kind === "network") return "Layer 3 - Network";
  return "Layer 7 - Application";
}

/**
 * Inspect an event and extract multi-layer protocol features.
 * Called on ingest and again before AI classification.
 */
export function analyzeProtocolTraffic(event: SecurityEventRow): ProtocolAnalysisResult {
  const features = parseFeatures(event.features_json);
  const layer3 = extractLayer3(event, features);
  const layer4 = extractLayer4(event, features);
  const layer7 = extractLayer7(event, features);
  const primaryOsiLayer = resolvePrimaryOsiLayer(event, layer3, layer4, layer7);

  return {
    layer3,
    layer4,
    layer7,
    primaryOsiLayer,
    detectedProtocol: layer4.protocol,
  };
}

/** Infer attack type hint from protocol features (pre-AI signal). */
export function inferAttackTypeFromProtocol(
  event: SecurityEventRow,
  analysis: ProtocolAnalysisResult
): string | null {
  const desc = (event.description || "").toLowerCase();
  const feat = (event.features_json || "").toLowerCase();

  if (desc.includes("ddos") || feat.includes("ddos") || analysis.layer3.packetCount > 900) return "DDoS";
  if (analysis.layer7.loginFailures >= 2 || desc.includes("brute") || feat.includes("brute")) return "Brute Force";
  if (desc.includes("scan") || analysis.layer4.connectionAttempts > 12) return "Port Scan";
  if (desc.includes("sql") || feat.includes("sqli")) return "SQLi";
  if (desc.includes("botnet") || feat.includes("botnet")) return "Botnet";
  if (desc.includes("quantum") || desc.includes("rsa") || desc.includes("shor")) return "Quantum Crypto";
  return null;
}

/** Map protocol analysis + event context to structured attack metadata. */
export function buildAttackMetadata(
  event: SecurityEventRow,
  analysis: ProtocolAnalysisResult,
  classification: string,
  attackType: string | null,
  cryptoThreatClass: import("../types.js").CryptoThreatClass
): import("../types.js").AttackMetadata {
  const inferred = attackType || inferAttackTypeFromProtocol(event, analysis) || "Unknown";
  const normalizedType = inferred.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

  let severity: "Low" | "Medium" | "High" | "Critical" = "Low";
  let severityScore = 25;

  if (classification === "confirmed_attack" || event.ground_truth_label === "attack") {
    severity = event.severity === "high" ? "Critical" : "High";
    severityScore = event.severity === "high" ? 92 : 85;
  } else if (classification === "suspicious") {
    severity = "Medium";
    severityScore = event.suspicious_indicators ? 68 : 58;
  } else if (event.severity === "high") {
    severity = "High";
    severityScore = 78;
  } else if (event.severity === "medium") {
    severity = "Medium";
    severityScore = 52;
  }

  if (analysis.layer3.packetCount > 1000) severityScore = Math.min(100, severityScore + 8);
  if (analysis.layer7.loginFailures >= 3) severityScore = Math.min(100, severityScore + 10);
  if (cryptoThreatClass === "quantum_cryptographic") severityScore = Math.min(100, severityScore + 5);

  return {
    attack_type: normalizedType,
    osi_layer: analysis.primaryOsiLayer,
    protocol: analysis.detectedProtocol,
    severity,
    severity_score: severityScore,
    crypto_threat_class: cryptoThreatClass,
  };
}
