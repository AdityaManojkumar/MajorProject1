# Paper figures — QuantumGuard AI

Use these in your report/thesis. **Mermaid** blocks render on GitHub, many Markdown editors, and [mermaid.live](https://mermaid.live). Export PNG/SVG from mermaid.live for Word/LaTeX.

---

## Figure 1 — Proposed system architecture

Three-tier view: browser dashboard, API layer, persistence and external services. Matches Option 2 deployment (Vercel frontend + Render backend) or single-host dev.

```mermaid
flowchart TB
  subgraph Client["Presentation tier (React + Vite)"]
    UI["QuantumGuard dashboard\n(Overview · Logs · Live · Quantum · PQC · Defense)"]
    ES["EventSource client\nRealtimePanel.tsx"]
    API_CLIENT["fetch / apiUrl()\nsrc/lib/api.ts"]
  end

  subgraph Server["Application tier (Node.js + Express)"]
    ROUTES["backend/routes.ts\nREST + SSE endpoints"]
    STREAM["backend/stream.ts\nSSE publish/subscribe"]
    AI["backend/ai/classify.ts\nGemini + heuristic fallback"]
    REPLAY["backend/replay/\nloaders + scheduler"]
    QCRYPT["backend/quantum/rsa-shor.ts\nbackend/pqc/*"]
    ANALYSIS["backend/ai/analysis-display.ts"]
  end

  subgraph Data["Data tier"]
    DB[("SQLite\ncybersecurity.db\nbackend/db.ts")]
    CSV["datasets/samples/*.csv\nCICIDS · NSL-KDD · UNSW-style"]
  end

  subgraph External["External (optional)"]
    GEMINI["Google Gemini API\nGEMINI_API_KEY"]
  end

  UI --> API_CLIENT
  UI --> ES
  API_CLIENT -->|HTTPS REST| ROUTES
  ES -->|GET /api/stream| ROUTES

  ROUTES --> STREAM
  ROUTES --> AI
  ROUTES --> REPLAY
  ROUTES --> QCRYPT
  ROUTES --> ANALYSIS
  ROUTES --> DB

  REPLAY --> CSV
  REPLAY --> DB
  AI --> GEMINI
  AI --> DB
  STREAM -->|event_created\nevent_analyzed\nblocked_ip_updated| ES
```

**Caption (suggested):** *Proposed architecture of QuantumGuard AI: React dashboard communicates with Express via REST and Server-Sent Events; events persist in SQLite; optional Gemini classification; dataset samples feed replay/injection.*

---

## Figure 2 — End-to-end working flow (operational)

Main path from user action to visible outcome.

```mermaid
flowchart TD
  START([Operator / demo user]) --> A{Action type}

  A -->|Quick simulate / inject| B["POST /api/sim/inject-sample\nscheduler.injectDatasetSample()"]
  A -->|Live login| C["POST /api/auth/login\ninsert login event"]
  A -->|Run AI analysis| D["POST /api/analyze\nrunBatchAnalyze()"]
  A -->|Quantum tab| E["POST /api/quantum/rsa-demo"]
  A -->|PQC tab| F["POST /api/pqc/protection-demo"]

  B --> G["insertEvent()\napplication / layer7_trace"]
  C --> G

  G --> H[("SQLite events table")]
  G --> I["publish(event_created)\nbackend/stream.ts"]
  I --> J["SSE → RealtimePanel\nUI updates Logs / charts"]

  D --> K{Gemini available?}
  K -->|Yes| L["classifyWithGemini()"]
  K -->|No| M["classifyHeuristic()"]
  L --> N["updateEventAnalysis()\nclassification · confidence · reason"]
  M --> N
  N --> H
  N --> O{confirmed_attack?}
  O -->|Yes| P["upsertBlockedIp()\nDefense tab list"]
  O -->|No| Q[Continue monitoring]
  P --> I
  N --> I

  E --> R["Toy RSA + Shor narrative\nincrement quantum_demo_runs stat"]
  F --> S["RSA vs toy lattice benchmark\nrunId + timing"]

  J --> T([Dashboard: Overview / Logs / Defense])
  P --> T
  R --> T
  S --> T
```

**Caption (suggested):** *Operational flow: events are ingested, stored, streamed to the UI, optionally classified; confirmed attacks trigger demo auto-block entries.*

---

## Figure 3 — Threat analysis sequence (AI path)

```mermaid
sequenceDiagram
  participant U as User (Overview)
  participant FE as React App
  participant API as Express routes
  participant AI as classify.ts
  participant G as Gemini API
  participant DB as SQLite
  participant SSE as SSE clients

  U->>FE: Run AI analysis
  FE->>API: POST /api/analyze
  API->>DB: listPendingEvents()
  alt GEMINI_API_KEY set
    API->>AI: classifyWithGemini()
    AI->>G: structured JSON prompt
    G-->>AI: labels + confidence + reason
  else key missing / API error
    API->>AI: classifyHeuristic()
  end
  AI-->>API: ClassifyResult[]
  API->>DB: updateEventAnalysis()
  opt classification = confirmed_attack
    API->>DB: upsertBlockedIp()
  end
  API->>SSE: publish(event_analyzed)
  SSE-->>FE: SSE message
  API-->>FE: JSON + httpStatus + attackSummary
  FE-->>U: Analysis panel + updated Logs
```

---

## Figure 4 — Classical vs quantum threat model (conceptual)

For Section 2 / Discussion — not a runtime diagram.

```mermaid
flowchart LR
  subgraph Classical["Classical threat surface (this project)"]
    C1["Network / application abuse\nDDoS · brute force · scans · injection"]
    C2["Detection\nIDS-style replay + AI labels"]
    C3["Mitigation demo\nmonitor · classify · block IP list"]
  end

  subgraph Quantum["Quantum-era crypto threat (demo)"]
    Q1["Target: RSA / ECC math\nfactorization · discrete log"]
    Q2["Method: Shor-style narrative\n(+ optional Qiskit service)"]
    Q3["Mitigation story\nPQC: lattice / hash signatures"]
  end

  C1 --> C2 --> C3
  Q1 --> Q2 --> Q3
```

---

## Figure 5 — Evaluation / metrics graphs (what to plot)

These match data your system **actually produces**. Generate numbers from SQLite or screenshot the **Defense → Comparison** tab after running demos.

### 5a. Confusion matrix (classifier vs ground truth)

*Requires events with `ground_truth_label` and completed `classification`.*

|  | Pred. normal | Pred. suspicious | Pred. confirmed_attack |
|--|--------------|------------------|------------------------|
| **GT normal** | TN | FP₁ | FP₂ |
| **GT attack** | FN₁ | FN₂ | TP |

**Caption:** *Confusion matrix on replayed rows with ground-truth labels (define “positive” as confirmed_attack or suspicious∪confirmed_attack).*

### 5b. Bar chart — demo event volume (built into UI)

```mermaid
xychart-beta
    title "Classical demo traffic vs quantum RSA demos (example layout)"
    x-axis ["Classical surface Σ", "Quantum RSA demos"]
    y-axis "Event count" 0 --> 100
    bar [45, 8]
```

Replace `[45, 8]` with values from **`GET /api/stats`**: `classicalDemoTraffic`, `quantumVulnerabilityDemos`.

### 5c. Stacked breakdown — classical demo sources

```mermaid
xychart-beta
    title "Sources of classical demo events (example)"
    x-axis ["Count"]
    y-axis "Events" 0 --> 50
    bar "Replay/batch" [20]
    bar "Login monitor" [12]
    bar "Legacy synthetic" [3]
```

Map to: `datasetInjectedEvents`, `loginDemoEvents`, `simulatedAttackEvents`.

### 5d. Line chart — threat flags over time (Overview)

Conceptual; your Overview builds this from recent events:

```mermaid
xychart-beta
    title "Recent threat indicator (0/1) vs time — illustrative"
    x-axis ["t1", "t2", "t3", "t4", "t5", "t6"]
    y-axis "Threat flag" 0 --> 1
    line [0, 0, 1, 1, 0, 1]
```

**Implementation:** `App.tsx` maps last N events → `threats: 1` if `severity === 'high'` or `classification === 'confirmed_attack'`.

### 5e. Pie / bar — AI label distribution

After analysis, count rows by `classification`:

```mermaid
pie showData
    title AI label distribution (example after analyze run)
    "normal" : 30
    "suspicious" : 15
    "confirmed_attack" : 12
    "unclassified" : 8
```

---

## Figure 6 — Deployment architecture (Option 2)

```mermaid
flowchart LR
  USER[Browser] --> VERCEL["Vercel\nstatic React (dist/)"]
  VERCEL -->|VITE_API_BASE_URL| RENDER["Render / Fly\nExpress + SQLite"]
  RENDER --> DB2[("Persistent disk\nDB_PATH")]
  RENDER -.->|optional| GEMINI2[Gemini API]
  VERCEL -->|FRONTEND_ORIGIN CORS| RENDER
```

---

## How to cite in your paper

| Figure | Suggested label |
|--------|-----------------|
| Fig. 1 | Proposed three-tier architecture of QuantumGuard AI |
| Fig. 2 | End-to-end operational workflow from event ingestion to dashboard |
| Fig. 3 | Sequence of AI-assisted threat analysis and SSE notification |
| Fig. 4 | Classical intrusion monitoring vs quantum cryptographic threat model |
| Fig. 5 | Evaluation charts (confusion matrix + dashboard-derived counts) |
| Fig. 6 | Split deployment: Vercel frontend and Render backend |

---

## Quick checklist before submission

1. Run: inject scenarios → **Run AI analysis** → open **Defense** tab → export screenshots for Fig. 5.
2. Replace example numbers in xychart blocks with your **`/api/stats`** JSON.
3. Export Mermaid figures as PNG (300 dpi) from mermaid.live for Word/PDF.
4. Add one screenshot of **Logs** table showing `application` / `layer7_trace` and classification columns.
