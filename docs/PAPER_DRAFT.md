# QuantumGuard AI: A Web-Based Cybersecurity Monitoring Platform with AI Threat Classification and Post-Quantum Cryptography Awareness

**Draft paper content** — edit names, institution, and citations before submission.

---

## Abstract

Cybersecurity operations increasingly require timely visibility into authentication and network-like events, automated triage of suspicious behavior, and awareness of long-term cryptographic risks posed by quantum computing. This work presents **QuantumGuard AI**, a full-stack web application that combines a Node.js backend, a SQLite-backed event store, real-time streaming to the browser, dataset-driven attack replay, and AI-assisted threat labeling. Login attempts are captured through a dedicated authentication API and surfaced with source IP, timestamp, success or failure, and heuristic indicators of repeated failures. Simulated traffic is injected from curated samples compatible with public intrusion-detection datasets (CICIDS2017, NSL-KDD, UNSW-NB15–style schemas). A Gemini-based classifier assigns each event a threat tier—normal, suspicious, or confirmed attack—with confidence scores and natural-language rationales, with a deterministic fallback when the cloud model is unavailable. The system also includes an educational **quantum threat** demonstration that uses small-key RSA to illustrate factorization-based key recovery, paired with a post-quantum cryptography (PQC) narrative covering CRYSTALS-Kyber, CRYSTALS-Dilithium, and SPHINCS+, plus a client-side lattice-style simulation. Evaluation is qualitative: the platform supports end-to-end demonstration of monitoring, analysis, and comparative classical-versus-quantum security messaging suitable for coursework or capstone reporting.

---

## 1. Introduction

Modern security dashboards must integrate **data ingestion**, **real-time feedback**, and **actionable analytics**. Traditional log-only prototypes often fail to convey how analysts distinguish benign activity from attacks, or how cryptographic defenses may evolve as quantum algorithms mature. Meanwhile, students and practitioners need **safe, reproducible demos** that do not require production network taps or specialized hardware.

**Motivation.** This project addresses three goals: (1) show **live-style event flow** from client actions and replayed dataset rows into a single event timeline; (2) apply **AI-assisted classification** that **flags** rather than blindly blocks, aligning with modern SOC workflows; (3) connect **classical** attack patterns (e.g., brute force, scans, denial-of-service–like labels) with **quantum-era** risks to public-key cryptography and **PQC** mitigations.

**Contributions (project scope).** We implement:

- A **unified event model** stored in SQLite, with fields for classification, confidence, rationale, and optional ground-truth labels from replayed data.
- **Server-Sent Events (SSE)** for pushing new events and analysis results to the dashboard without manual refresh.
- **Dataset replay** from bundled CSV samples to simulate labeled attack traffic at a controlled rate.
- **AI threat analysis** via the Gemini API when configured, plus a **rule-based fallback** for reliability during quota limits or offline use.
- **Quantum attack pedagogy** through a small-integer RSA demo and **simulated** Shor-style factorization narrative.
- **PQC pedagogy** through an API-delivered walkthrough of Kyber-, Dilithium-, and SPHINCS+-style roles, complemented by a lightweight lattice-inspired client simulation.

**Limitations.** The system does not perform passive packet capture on a live enterprise network; “real-time” monitoring is **application-level** (HTTP login API and injected events). The quantum demonstration is **educational** and uses **tiny** RSA parameters; it does not break cryptographically sized keys. PQC descriptions are standards-oriented explanations rather than audited production integrations.

---

## 2. System Design

### 2.1 Architecture Overview

The system follows a **single-process development** pattern: an **Express** server hosts REST APIs, streams SSE to browsers, and (in development) embeds **Vite** middleware for the React front end. In production, the server can serve static assets from a built `dist` folder.

**Major components:**

| Layer | Responsibility |
|--------|----------------|
| **Client (React)** | Tabbed dashboard: overview charts, event table, live monitoring, quantum demo, PQC panels. Subscribes to SSE for instant updates. |
| **API (Express)** | CRUD-style access to events, auth demo, replay control, AI analysis triggers, quantum/PQC demo endpoints. |
| **Persistence (SQLite)** | Stores normalized `events` and optional legacy structures; supports migration from earlier log-centric schemas. |
| **Streaming (SSE)** | Broadcasts `event_created`, `event_analyzed`, and replay lifecycle messages to connected clients. |
| **AI (Gemini)** | Batch classification of pending events into labels with confidence and explanations. |
| **Heuristic engine** | Deterministic scoring when the model is unavailable or returns partial output. |

### 2.2 Data Model

**Events** capture heterogeneous activity in one table: timestamp, source IP, event kind (e.g., login vs. network vs. dataset replay), action (e.g., auth success/failure, traffic row), optional features JSON, dataset name, optional ground-truth label, AI outputs (`classification`, `attack_type`, `confidence`, `reason`), severity, and analysis status. This design supports both **live demo auth** and **offline replay** without separate schemas per source.

### 2.3 Real-Time Path

Clients open **`GET /api/stream`** as an `EventSource`. On each inserted or analyzed event, the server **publishes** a JSON message to all subscribers. The UI merges streamed payloads into local state so operators see new rows without polling.

### 2.4 Threat Analysis Path

Pending events are selected for batch analysis. The model is prompted to return **structured JSON** with per-event labels and rationale. Results are written back to the database and pushed over SSE. A **fallback classifier** uses severity, dataset labels, keywords, and login failure context to approximate the same fields when the API fails.

### 2.5 Dataset Replay Path

Sample CSV files ship with the repository. The loader maps heterogeneous column names to a canonical internal representation, filters attack-labeled rows when requested, and a scheduler emits rows as **synthetic network events** at a configurable interval, each persisted and streamed like any other event.

### 2.6 Quantum and Post-Quantum Pedagogy

- **RSA demo:** Fixed small primes define `n`; textbook RSA encrypt/decrypt illustrates classical confidentiality. A **simulated** factorization step narrates how Shor’s algorithm would endanger RSA if `n` could be factored—here the factors are **known by construction** for clarity.
- **PWC narrative:** A read-only API returns structured steps for Kyber (KEM), Dilithium (signatures), and SPHINCS+ (hash-based signatures), emphasizing resistance assumptions that are not trivially broken by Shor’s algorithm on RSA/ECC groups.

---

## 3. Implementation

### 3.1 Backend

- **Runtime:** Node.js (recommended LTS 20+), **TypeScript** executed via `tsx` for development.
- **Framework:** Express with JSON body parsing.
- **Database:** `better-sqlite3` with initialization and migration logic in a dedicated module; events are queried with prepared statements for predictable performance on small workloads.
- **Environment:** `dotenv` loads `.env` and `.env.local`; `GEMINI_API_KEY` enables cloud classification.
- **Endpoints (representative):** `GET /api/events`, `GET /api/stream`, `POST /api/auth/login`, `POST /api/sim/replay/start`, `POST /api/analyze`, `POST /api/quantum/rsa-demo`, `GET /api/pqc/demo`, `GET /api/stats`.

### 3.2 Frontend

- **Stack:** React 19, Vite, Tailwind-style utility classes, Recharts for charts, Motion for light UI animation.
- **Real-time:** `EventSource` listens to `/api/stream` and updates lists and feed text when messages arrive.
- **Tabs:** Overview (charts + comparative widgets + AI run), Logs (tabular detail), Live (login + replay + stream), Quantum (RSA/Shor demo), PQC (API narrative + optional client lattice demo), Defense (legacy blocked-IP view if used).

### 3.3 AI and Fallback

The AI path uses the vendor SDK to request **JSON-only** outputs matching a fixed schema. Parsing tolerates minor formatting issues; missing IDs are completed by the heuristic layer so every pending row receives a label for demo continuity.

### 3.4 Security and Ethics Note

This software is intended for **education and demonstration**. Simulated attacks and dataset replay must not be misrepresented as unauthorized testing against third-party systems. The RSA demo uses **non-cryptographic** parameters.

---

## 4. Conclusion

QuantumGuard AI delivers an integrated demonstration platform that ties together **live-style event ingestion**, **dataset-based replay**, **AI-assisted threat labeling with explanations**, and **quantum/PQC literacy** in one deployable artifact. The architecture is intentionally modest—SQLite, SSE, and a single server process—so that the focus remains on observable behavior and clear narrative for reports and presentations. Future work could add authenticated multi-user sessions, richer feature extraction from replayed rows, integration with real log forwarders under strict consent, or optional Qiskit/Cirq microservices for a closer facsimile of period-finding circuits—while preserving the educational clarity of the current design.

---

## References

1. National Institute of Standards and Technology (NIST). *Post-Quantum Cryptography Standardization* — overview of selected algorithms (e.g., ML-KEM / Kyber, ML-DSA / Dilithium, SLH-DSA / SPHINCS+). https://csrc.nist.gov/projects/post-quantum-cryptography  

2. Shor, P. W. (1997). *Polynomial-time algorithms for prime factorization and discrete logarithms on a quantum computer.* SIAM Journal on Computing, 26(5), 1484–1509.  

3. Rivest, R. L., Shamir, A., & Adleman, L. (1978). *A method for obtaining digital signatures and public-key cryptosystems.* Communications of the ACM, 21(2), 120–126.  

4. Google AI for Developers. *Gemini API documentation* — model usage, JSON mode, and rate limits. https://ai.google.dev/gemini-api/docs  

5. Sharafaldin, I., et al. (2018). *Toward developing a systematic approach to generate intrusion detection benchmark datasets.* (CICIDS2017 family of datasets — cite the specific version you use if you swap in full data).  

6. Tavallaee, M., et al. (2009). *A detailed analysis of the KDD CUP 99 data set.* (NSL-KDD lineage — cite the NSL-KDD paper if you use that dataset in full).  

7. Moustafa, N., & Turnbull, B. (2018). *UNSW-NB15: a comprehensive data set for network intrusion detection systems.* IEEE Military Communications and Information Systems Conference.  

8. Express.js documentation — routing, middleware, and production static file serving. https://expressjs.com/  

9. SQLite documentation — SQL syntax and embedded database semantics. https://www.sqlite.org/docs.html  

10. HTML Living Standard — *Server-sent events* (`EventSource`). https://html.spec.whatwg.org/multipage/server-sent-events.html  

---

*End of draft. Replace bracketed notes, tighten related work, and add evaluation metrics or screenshots as required by your institution.*
