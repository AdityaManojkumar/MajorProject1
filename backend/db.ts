import Database from "better-sqlite3";
import type { SecurityEventRow } from "./types.js";

let db: Database.Database;

export function getDb(): Database.Database {
  return db;
}

export function initDb(path = "cybersecurity.db"): Database.Database {
  db = new Database(path);

  db.exec(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT,
    event_type TEXT,
    severity TEXT,
    description TEXT,
    status TEXT DEFAULT 'pending'
  );

  CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE,
    reason TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );

  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT NOT NULL,
    event_kind TEXT NOT NULL DEFAULT 'network',
    action TEXT NOT NULL DEFAULT 'traffic',
    login_success INTEGER,
    username TEXT,
    features_json TEXT,
    dataset TEXT,
    ground_truth_label TEXT,
    classification TEXT,
    attack_type TEXT,
    confidence REAL,
    reason TEXT,
    severity TEXT NOT NULL DEFAULT 'low',
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending_analyze',
    suspicious_indicators TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);

  CREATE TABLE IF NOT EXISTS mitigation_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    osi_layer TEXT NOT NULL,
    action_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'applied',
    details TEXT NOT NULL DEFAULT '',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_mitigation_event ON mitigation_actions(event_id);
  `);

  // Protocol Analysis Layer columns (idempotent migrations)
  const protocolCols: Array<[string, string]> = [
    ["osi_layer", "TEXT"],
    ["protocol", "TEXT"],
    ["severity_score", "REAL"],
    ["crypto_threat_class", "TEXT"],
    ["mitigation_status", "TEXT"],
    ["attack_metadata_json", "TEXT"],
    ["protocol_analysis_json", "TEXT"],
  ];
  for (const [col, typ] of protocolCols) {
    try {
      db.exec(`ALTER TABLE events ADD COLUMN ${col} ${typ}`);
    } catch {
      /* column exists */
    }
  }

  // Normalize legacy replay row labels to application-layer semantics (idempotent)
  db.exec(`
    UPDATE events SET event_kind = 'application', action = 'layer7_trace'
    WHERE event_kind = 'dataset_replay' OR action = 'dataset_row';
    UPDATE events SET description = replace(description, 'Dataset replay:', 'Application-layer signal:')
    WHERE description LIKE 'Dataset replay:%';
  `);

  // Migrate legacy logs into events once
  const migrated = db
    .prepare("SELECT value FROM settings WHERE key = 'events_migrated_from_logs'")
    .get() as { value: string } | undefined;
  if (!migrated) {
    const logCount = (db.prepare("SELECT COUNT(*) as c FROM logs").get() as { c: number }).c;
    if (logCount > 0) {
      const rows = db.prepare("SELECT * FROM logs").all() as Array<{
        timestamp: string;
        source_ip: string;
        event_type: string;
        severity: string;
        description: string;
        status: string;
      }>;
      const ins = db.prepare(`
        INSERT INTO events (
          timestamp, source_ip, event_kind, action, severity, description, status, classification
        ) VALUES (?, ?, 'network', 'traffic', ?, ?, ?, ?)
      `);
      for (const r of rows) {
        const cls =
          r.status === "blocked"
            ? "confirmed_attack"
            : r.status === "cleared"
              ? "normal"
              : null;
        const st = r.status === "pending" ? "pending_analyze" : "analyzed";
        ins.run(
          r.timestamp,
          r.source_ip || "0.0.0.0",
          r.severity || "low",
          r.description || r.event_type,
          st,
          cls
        );
      }
    }
    db.prepare(
      "INSERT OR REPLACE INTO settings (key, value) VALUES ('events_migrated_from_logs', '1')"
    ).run();
  }

  // Seed events if empty
  const ec = (db.prepare("SELECT COUNT(*) as c FROM events").get() as { c: number }).c;
  if (ec === 0) {
    db.exec(`
      INSERT INTO events (source_ip, event_kind, action, login_success, severity, description, status, classification, confidence, reason)
      VALUES
      ('192.168.1.1', 'network', 'traffic', NULL, 'low', 'QuantumGuard Node SG-01 initialized', 'analyzed', 'normal', 0.95, 'Seed: system startup'),
      ('10.0.0.15', 'login', 'auth_success', 1, 'low', 'Successful admin login from internal network', 'analyzed', 'normal', 0.9, 'Seed: legitimate login');
    `);
  }

  return db;
}

export function insertEvent(params: {
  source_ip: string;
  event_kind: string;
  action: string;
  login_success?: number | null;
  username?: string | null;
  features_json?: string | null;
  dataset?: string | null;
  ground_truth_label?: string | null;
  severity?: string;
  description: string;
  status?: string;
  suspicious_indicators?: string | null;
}): number {
  const info = db
    .prepare(
      `INSERT INTO events (
        source_ip, event_kind, action, login_success, username, features_json,
        dataset, ground_truth_label, severity, description, status, suspicious_indicators
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      params.source_ip,
      params.event_kind,
      params.action,
      params.login_success ?? null,
      params.username ?? null,
      params.features_json ?? null,
      params.dataset ?? null,
      params.ground_truth_label ?? null,
      params.severity ?? "low",
      params.description,
      params.status ?? "pending_analyze",
      params.suspicious_indicators ?? null
    );
  return Number(info.lastInsertRowid);
}

export function getEventById(id: number): SecurityEventRow | undefined {
  return db.prepare("SELECT * FROM events WHERE id = ?").get(id) as SecurityEventRow | undefined;
}

export function listEvents(limit = 200): SecurityEventRow[] {
  return db
    .prepare("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?")
    .all(limit) as SecurityEventRow[];
}

export function listPendingEvents(limit: number): SecurityEventRow[] {
  return db
    .prepare(
      "SELECT * FROM events WHERE status = 'pending_analyze' ORDER BY timestamp ASC LIMIT ?"
    )
    .all(limit) as SecurityEventRow[];
}

export function updateEventAnalysis(
  id: number,
  classification: string,
  attack_type: string | null,
  confidence: number,
  reason: string,
  extras?: {
    osi_layer?: string | null;
    protocol?: string | null;
    severity_score?: number | null;
    crypto_threat_class?: string | null;
    mitigation_status?: string | null;
    attack_metadata_json?: string | null;
  }
): void {
  db.prepare(
    `UPDATE events SET
      classification = ?, attack_type = ?, confidence = ?, reason = ?, status = 'analyzed',
      osi_layer = COALESCE(?, osi_layer),
      protocol = COALESCE(?, protocol),
      severity_score = COALESCE(?, severity_score),
      crypto_threat_class = COALESCE(?, crypto_threat_class),
      mitigation_status = COALESCE(?, mitigation_status),
      attack_metadata_json = COALESCE(?, attack_metadata_json)
    WHERE id = ?`
  ).run(
    classification,
    attack_type,
    confidence,
    reason,
    extras?.osi_layer ?? null,
    extras?.protocol ?? null,
    extras?.severity_score ?? null,
    extras?.crypto_threat_class ?? null,
    extras?.mitigation_status ?? null,
    extras?.attack_metadata_json ?? null,
    id
  );
}

export function updateEventProtocolAnalysis(
  id: number,
  fields: {
    osi_layer?: string;
    protocol?: string;
    protocol_analysis_json?: string;
  }
): void {
  db.prepare(
    `UPDATE events SET
      osi_layer = COALESCE(?, osi_layer),
      protocol = COALESCE(?, protocol),
      protocol_analysis_json = COALESCE(?, protocol_analysis_json)
    WHERE id = ?`
  ).run(fields.osi_layer ?? null, fields.protocol ?? null, fields.protocol_analysis_json ?? null, id);
}

export function insertMitigationAction(
  eventId: number,
  osiLayer: string,
  actionType: string,
  status: string,
  details: string
): number {
  const info = db
    .prepare(
      `INSERT INTO mitigation_actions (event_id, osi_layer, action_type, status, details)
       VALUES (?, ?, ?, ?, ?)`
    )
    .run(eventId, osiLayer, actionType, status, details);
  return Number(info.lastInsertRowid);
}

export function listMitigationActions(eventId?: number, limit = 100) {
  if (eventId != null) {
    return db
      .prepare("SELECT * FROM mitigation_actions WHERE event_id = ? ORDER BY timestamp DESC")
      .all(eventId);
  }
  return db
    .prepare("SELECT * FROM mitigation_actions ORDER BY timestamp DESC LIMIT ?")
    .all(limit);
}

export function listProtocolThreats(limit = 30) {
  return db
    .prepare(
      `SELECT id, timestamp, source_ip, attack_type, protocol, osi_layer,
              severity_score, crypto_threat_class, mitigation_status, classification,
              attack_metadata_json, description
       FROM events
       WHERE attack_metadata_json IS NOT NULL OR (classification IS NOT NULL AND classification != 'normal')
       ORDER BY timestamp DESC LIMIT ?`
    )
    .all(limit);
}

export function listBlockedIps() {
  return db.prepare("SELECT * FROM blocked_ips ORDER BY timestamp DESC").all();
}

export function upsertBlockedIp(ip: string, reason: string): void {
  if (!ip) return;
  db.prepare(
    `
    INSERT INTO blocked_ips (ip, reason, timestamp)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(ip) DO UPDATE SET
      reason = excluded.reason,
      timestamp = CURRENT_TIMESTAMP
    `
  ).run(ip, reason);
}
