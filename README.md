# CyberShield AI

> AI-assisted defensive phishing and threat-intelligence platform for structured URL and domain security analysis.

[![CI](https://github.com/hack2ai/cyber-shield-AI2.2/actions/workflows/ci.yml/badge.svg)](https://github.com/hack2ai/cyber-shield-AI2.2/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://react.dev/)
[![Node.js](https://img.shields.io/badge/Node.js-20-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Google Gemini](https://img.shields.io/badge/Google%20Gemini-4285F4?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev/)

## Overview

CyberShield AI combines **deterministic URL heuristics, security intelligence, destination validation, and optional AI-assisted explanations** into a layered analysis pipeline.

The project is designed for defensive security research and demonstrates how local evidence can be combined with external intelligence while keeping the baseline risk assessment independent from an LLM response.

> **Defensive-use project:** risk scores are heuristic and intelligence-driven. A score is not proof that a resource is safe or malicious and should never be the sole basis for a security decision.

## Detection Pipeline

```text
URL / Browser Extension
          ↓
Request + URL Validation
          ↓
SSRF / Destination Checks
          ↓
┌───────────────────────┐
│ Local URL Features    │
│ Risk Rules            │
│ DNS / TLS / WHOIS     │
│ VirusTotal Intelligence│
└───────────┬───────────┘
            ↓
     Redirect Analysis
            ↓
     Evidence Fusion
            ↓
     Calibrated Score
            ↓
   Structured Security Report
            ↓
 Optional AI Explanation
```

## Security Capabilities

| Capability | Status |
|---|---|
| URL structural analysis | Implemented |
| Deterministic risk scoring | Implemented |
| SSRF-aware destination validation | Implemented |
| DNS intelligence | Implemented |
| TLS / certificate intelligence | Implemented |
| WHOIS / domain intelligence | Implemented |
| VirusTotal enrichment | Implemented when configured |
| Redirect-chain analysis | Implemented |
| Typed analysis API | Implemented |
| Automated tests | Implemented |
| GitHub Actions CI | Implemented |
| Gemini-assisted explanation | Existing capability |
| Firebase authentication / data | Existing capability |
| Browser extension | Existing capability |
| QR / file workflows | Existing capability |

## Architecture

```text
src/                         # React frontend
extension/                   # Browser extension
server/
├── api/                     # Routes, controllers, contracts
├── analysis/                # Features, scoring, analysis
├── config/                  # Environment configuration
├── security/                # Headers, rate limits, SSRF checks
└── services/                # DNS, TLS, WHOIS, VT, redirects
```

The backend is intentionally being decomposed into focused layers so security analysis, external providers, validation, and HTTP concerns remain independently testable.

## Technology Stack

**Frontend**

React • TypeScript • Vite • Tailwind CSS • Recharts • Motion • Lucide

**Backend**

Node.js • Express • TypeScript

**Security Intelligence**

DNS • TLS • WHOIS • VirusTotal • Redirect Analysis

**AI**

Google Gemini

**Authentication / Data**

Firebase Authentication • Firestore • Firebase Admin

**Quality**

Vitest • Firebase Rules Testing • TypeScript Strict Mode • GitHub Actions

## Security Model

The platform treats external analysis as untrusted I/O:

- Validate request bodies before analysis.
- Validate external destinations before network access.
- Re-validate redirect destinations before following hops.
- Apply explicit timeouts to external intelligence providers.
- Keep third-party provider failures non-fatal where local analysis remains possible.
- Keep secrets server-side and out of client bundles.
- Keep the baseline risk score deterministic from collected evidence.
- Treat AI explanations as contextual assistance rather than authoritative security verdicts.

## Installation

### Requirements

- Node.js 20+
- npm 10+
- Firebase project for Firebase-backed features
- Gemini API key for Gemini-dependent features
- VirusTotal API key for VirusTotal enrichment

```bash
npm install
cp .env.example .env.local
```

Populate only the credentials required by the features you intend to use.

## Environment Configuration

The modular backend reads configuration through `server/config/env.ts`.

Typical variables include:

```dotenv
NODE_ENV=development
PORT=3000
ALLOWED_ORIGINS=http://localhost:5173
GEMINI_API_KEY=
VIRUSTOTAL_API_KEY=
```

**Never commit API keys, Firebase service-account credentials, `.env.local`, or other secrets.**

## Development & Testing

```bash
npm run dev
npm run typecheck
npm test
npm run build
npm run check
```

Security-focused tests:

```bash
npm run test:security
```

Firebase rules tests:

```bash
npm run test:rules
```

The analysis tests mock external intelligence providers so unit tests can remain deterministic without live credentials.

## API

```http
POST /api/analysis
Content-Type: application/json
```

Example request:

```json
{
  "url": "https://example.com"
}
```

The response contains structured evidence, findings, risk assessment, intelligence results, and redirect information.

## CI

GitHub Actions validates changes through the project quality gate:

```text
npm ci
  ↓
npm run typecheck
  ↓
npm test
  ↓
npm run build
```

## Roadmap

- Complete migration from legacy server entry points
- Expand controller and integration coverage
- Add dependency vulnerability scanning
- Add secret scanning to CI
- Add structured security-event telemetry
- Improve evidence/confidence explanations
- Expand browser-extension integration
- Continue dashboard and result-model improvements

## License

Apache-2.0

## Author

**Pankaj (Tony) Kumar**  
AI Engineer • Full Stack Developer • Generative AI & RAG Specialist

[GitHub](https://github.com/hack2ai) • [LinkedIn](https://www.linkedin.com/in/pankaj-kumar-ab591a216)
