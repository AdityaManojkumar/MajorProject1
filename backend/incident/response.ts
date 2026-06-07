/**
 * Layer-aware Incident Response Engine.
 * Applies mitigation actions based on the OSI layer identified by the Protocol Analysis Layer.
 *
 * Layer 3 → IP blocking / rate limiting
 * Layer 4 → port blocking / session termination
 * Layer 7 → account lockout / API throttling
 */
import type { AttackMetadata, OsiLayerLabel, SecurityEventRow } from "../types.js";
import { insertMitigationAction, upsertBlockedIp } from "../db.js";
import { publish } from "../stream.js";

export interface MitigationResult {
  action_type: string;
  osi_layer: OsiLayerLabel;
  status: "applied" | "recommended";
  details: string;
}

function layer3Actions(event: SecurityEventRow, metadata: AttackMetadata): MitigationResult[] {
  const actions: MitigationResult[] = [];
  if (metadata.severity_score >= 50) {
    const reason = `L3 ${metadata.attack_type}: rate limit ${event.source_ip} (${metadata.severity} severity)`;
    actions.push({
      action_type: "rate_limiting",
      osi_layer: "Layer 3 - Network",
      status: "applied",
      details: reason,
    });
    insertMitigationAction(event.id, "Layer 3 - Network", "rate_limiting", "applied", reason);
  }
  if (metadata.severity_score >= 75) {
    const reason = `L3 auto-block: ${metadata.attack_type} from ${event.source_ip}`;
    upsertBlockedIp(event.source_ip, reason);
    actions.push({
      action_type: "ip_blocking",
      osi_layer: "Layer 3 - Network",
      status: "applied",
      details: reason,
    });
    insertMitigationAction(event.id, "Layer 3 - Network", "ip_blocking", "applied", reason);
    publish({ type: "blocked_ip_updated", data: { ip: event.source_ip, reason } });
  }
  return actions;
}

function layer4Actions(event: SecurityEventRow, metadata: AttackMetadata): MitigationResult[] {
  const port = metadata.protocol === "TCP" || metadata.protocol === "UDP" ? "target service port" : "ephemeral";
  const blockDetail = `L4 port block on ${port} for ${event.source_ip} (${metadata.attack_type})`;
  const sessionDetail = `L4 session termination: reset active flows from ${event.source_ip}`;

  insertMitigationAction(event.id, "Layer 4 - Transport", "port_blocking", "applied", blockDetail);
  insertMitigationAction(event.id, "Layer 4 - Transport", "session_termination", "applied", sessionDetail);

  return [
    {
      action_type: "port_blocking",
      osi_layer: "Layer 4 - Transport",
      status: "applied",
      details: blockDetail,
    },
    {
      action_type: "session_termination",
      osi_layer: "Layer 4 - Transport",
      status: "applied",
      details: sessionDetail,
    },
  ];
}

function layer7Actions(event: SecurityEventRow, metadata: AttackMetadata): MitigationResult[] {
  const user = event.username || "unknown-account";
  const lockDetail = `L7 account lockout: ${user} after ${metadata.attack_type} pattern from ${event.source_ip}`;
  const throttleDetail = `L7 API throttling: 10 req/min cap for ${event.source_ip}`;

  insertMitigationAction(event.id, "Layer 7 - Application", "account_lockout", "applied", lockDetail);
  insertMitigationAction(event.id, "Layer 7 - Application", "api_throttling", "applied", throttleDetail);

  return [
    {
      action_type: "account_lockout",
      osi_layer: "Layer 7 - Application",
      status: metadata.severity_score >= 60 ? "applied" : "recommended",
      details: lockDetail,
    },
    {
      action_type: "api_throttling",
      osi_layer: "Layer 7 - Application",
      status: "applied",
      details: throttleDetail,
    },
  ];
}

/**
 * Execute layer-aware mitigation for a classified threat.
 * Returns applied/recommended actions and publishes SSE updates.
 */
export function applyLayerAwareMitigation(
  event: SecurityEventRow,
  metadata: AttackMetadata,
  classification: string
): MitigationResult[] {
  if (classification === "normal") return [];

  const results: MitigationResult[] = [];

  switch (metadata.osi_layer) {
    case "Layer 3 - Network":
      results.push(...layer3Actions(event, metadata));
      break;
    case "Layer 4 - Transport":
      results.push(...layer4Actions(event, metadata));
      if (metadata.severity_score >= 80) {
        results.push(...layer3Actions(event, metadata));
      }
      break;
    case "Layer 7 - Application":
      results.push(...layer7Actions(event, metadata));
      break;
    default:
      break;
  }

  if (metadata.crypto_threat_class === "quantum_cryptographic") {
    const pqcDetail = `PQC advisory: migrate RSA/ECC endpoints; enable lattice/Kyber for ${event.source_ip} traffic class`;
    insertMitigationAction(event.id, "Cryptographic", "pqc_migration_advisory", "recommended", pqcDetail);
    results.push({
      action_type: "pqc_migration_advisory",
      osi_layer: metadata.osi_layer,
      status: "recommended",
      details: pqcDetail,
    });
  }

  const concernBlock = applyConcernIpBlock(event, metadata, classification, results);
  if (concernBlock.length > 0) {
    results.push(...concernBlock);
  }

  if (results.length > 0) {
    publish({
      type: "mitigation_applied",
      data: { eventId: event.id, actions: results, metadata },
    });
  }

  return results;
}

/** Block IPs flagged as suspicious or confirmed when layer actions did not already block. */
function applyConcernIpBlock(
  event: SecurityEventRow,
  metadata: AttackMetadata,
  classification: string,
  existing: MitigationResult[]
): MitigationResult[] {
  if (classification === "normal" || !event.source_ip) return [];
  if (existing.some((r) => r.action_type === "ip_blocking")) return [];

  const isConcern =
    classification === "confirmed_attack" ||
    classification === "suspicious" ||
    Boolean(event.suspicious_indicators);

  if (!isConcern) return [];

  const shouldBlock =
    classification === "confirmed_attack" ||
    metadata.severity_score >= 55 ||
    Boolean(event.suspicious_indicators);

  if (!shouldBlock) return [];

  const reason =
    classification === "suspicious"
      ? `Concern block: ${metadata.attack_type || "suspicious activity"} from ${event.source_ip}${
          event.suspicious_indicators ? ` · ${event.suspicious_indicators}` : ""
        }`
      : `Auto-block: ${metadata.attack_type} from ${event.source_ip} (${metadata.severity}, score ${metadata.severity_score})`;

  upsertBlockedIp(event.source_ip, reason);
  insertMitigationAction(event.id, metadata.osi_layer, "ip_blocking", "applied", reason);
  publish({ type: "blocked_ip_updated", data: { ip: event.source_ip, reason } });

  return [
    {
      action_type: "ip_blocking",
      osi_layer: metadata.osi_layer,
      status: "applied",
      details: reason,
    },
  ];
}

export function mitigationStatusFromResults(
  results: MitigationResult[],
  classification: string
): "applied" | "pending" | "none" {
  if (classification === "normal") return "none";
  if (results.some((r) => r.status === "applied")) return "applied";
  if (results.length > 0) return "pending";
  return "none";
}
