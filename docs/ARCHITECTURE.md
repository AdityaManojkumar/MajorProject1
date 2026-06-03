# QuantumGuard AI — Architecture

## Pipeline overview

Traffic and security events flow through a **Protocol Analysis Layer** before the **AI Threat Detection Engine** and **Incident Response Engine**. A **Cross-Layer Cryptographic Security Module** classifies whether threats are classical or quantum-era (PQC migration).

```
┌─────────────────────┐
│ Backend Application │  REST ingest: login, simulate, replay, protocol/analyze
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Protocol Analysis   │  backend/protocol/analyzer.ts
│ Layer               │  Extract L3 / L4 / L7 features → protocol_analysis_json
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ AI Threat Detection │  backend/ai/classify.ts (Gemini + heuristic)
│ Engine              │  Output: attack_type, osi_layer, protocol, severity_score,
└──────────┬──────────┘  crypto_threat_class
           │
           ▼
┌─────────────────────┐
│ Incident Response   │  backend/incident/response.ts
│ Engine              │  Layer-aware mitigation → mitigation_actions table
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Cross-Layer Crypto  │  backend/protocol/crypto-security.ts
│ Security (PQC)      │  classical vs quantum_cryptographic threat class
└─────────────────────┘
```

## OSI layers protected

| OSI layer | Features extracted | Detection focus | Mitigation actions |
|-----------|-------------------|-----------------|-------------------|
| **Layer 3 — Network** | Source/dest IP, packet count, flow stats (PPS, BPS, duration) | DDoS, floods, botnet coordination | IP blocking, rate limiting |
| **Layer 4 — Transport** | TCP flags, ports, connection attempts, session duration | Port scans, session abuse | Port blocking, session termination |
| **Layer 7 — Application** | Auth requests, API requests, login failures, request frequency | Brute force, SQLi, API abuse | Account lockout, API throttling |
| **Cryptographic (cross-layer)** | RSA/ECC/Shor/PQC keywords and quantum demo events | Quantum cryptographic threat | PQC migration advisory (Kyber/Dilithium) |

## Protocol Analysis Module

**File:** `backend/protocol/analyzer.ts`

Inspects each `SecurityEventRow` and produces:

```json
{
  "layer3": { "sourceIp", "destinationIp", "packetCount", "flowStatistics" },
  "layer4": { "protocol", "tcpFlags", "sourcePort", "destinationPort", "connectionAttempts", "sessionDurationMs" },
  "layer7": { "authenticationRequests", "apiRequests", "loginFailures", "requestFrequencyPerMinute" },
  "primaryOsiLayer": "Layer 3 - Network",
  "detectedProtocol": "TCP"
}
```

Structured attack metadata example (stored in `attack_metadata_json`):

```json
{
  "attack_type": "DDoS",
  "osi_layer": "Layer 3 - Network",
  "protocol": "TCP",
  "severity": "High",
  "severity_score": 85,
  "crypto_threat_class": "classical"
}
```

## AI Threat Detection Engine

**File:** `backend/ai/classify.ts`

Classification now includes:

- `attack_type` — ddos, brute_force, port_scan, botnet, sqli, quantum_crypto
- `osi_layer` — Layer 3 / 4 / 7 label
- `protocol` — TCP, UDP, HTTP, TLS, …
- `severity_score` — 0–100 numeric score
- `crypto_threat_class` — `classical` | `quantum_cryptographic` | `none`

Gemini receives pre-computed `protocol_analysis` from the Protocol Analysis Layer. Heuristic fallback uses the same fields when no API key is configured.

## Incident Response Engine

**File:** `backend/incident/response.ts`

Mitigation is **layer-aware**:

| OSI layer | Actions |
|-----------|---------|
| Layer 3 | `rate_limiting`, `ip_blocking` (also updates `blocked_ips`) |
| Layer 4 | `port_blocking`, `session_termination` |
| Layer 7 | `account_lockout`, `api_throttling` |
| Quantum crypto | `pqc_migration_advisory` (recommended) |

Actions are persisted in `mitigation_actions` and broadcast via SSE `mitigation_applied`.

## Cross-Layer Cryptographic Security Module

**File:** `backend/protocol/crypto-security.ts`

- **Classical threat** — network/application attacks (DDoS, brute force, scans, botnet, SQLi)
- **Quantum cryptographic threat** — RSA/ECC/Shor/PQC-related signals; mitigated by post-quantum migration, not IP block alone

Educational PQC demos live in `backend/pqc/` and the **PQC** UI tab.

## API endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /api/protocol/analyze` | Ingest traffic with L3/L4/L7 feature hints |
| `GET /api/protocol/threats` | Dashboard widget data |
| `GET /api/protocol/mitigations` | List layer-aware mitigation actions |
| `GET /api/protocol/architecture` | Protected OSI layers and pipeline description |
| `POST /api/analyze` | Runs protocol refresh → AI classify → incident response |

## Frontend

**Component:** `src/components/ProtocolThreatWidget.tsx`

Shows attack type, protocol, OSI layer, threat class (classical/quantum), and mitigation status on **Overview** and **Defense** tabs.

## Key source files

| Path | Role |
|------|------|
| `backend/pipeline.ts` | Orchestrates protocol analysis on ingest |
| `backend/protocol/analyzer.ts` | L3/L4/L7 feature extraction |
| `backend/protocol/crypto-security.ts` | Classical vs quantum threat classification |
| `backend/incident/response.ts` | Layer-aware mitigation |
| `backend/ai/classify.ts` | AI + heuristic threat detection |
| `backend/db.ts` | Schema: protocol columns, `mitigation_actions` table |
