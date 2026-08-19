# Cyber Shield AI

[![CI](https://github.com/hack2ai/cyber-shield-AI2.2/actions/workflows/ci.yml/badge.svg)](https://github.com/hack2ai/cyber-shield-AI2.2/actions/workflows/ci.yml)

AI-assisted phishing and threat-intelligence platform for defensive URL and domain analysis.

Cyber Shield AI combines deterministic URL heuristics with external security intelligence and optional AI-assisted explanations. The project is being structured as a layered security-analysis platform with a React/Vite interface, an Express API, typed analysis services, and automated regression testing.

> **Defensive-use project:** results are heuristic and intelligence-driven. A score is not proof that a resource is safe or malicious and should not be the sole basis for a security decision.

## Highlights

| Capability | Status |
|---|---|
| URL structural analysis | Implemented |
| Deterministic risk scoring | Implemented |
| SSRF-aware destination validation | Implemented |
| DNS intelligence | Implemented |
| TLS/certificate intelligence | Implemented |
| WHOIS/domain intelligence | Implemented |
| VirusTotal domain enrichment | Implemented when configured |
| Redirect-chain analysis | Implemented |
| Typed analysis API | Implemented |
| Automated unit/regression tests | Implemented |
| GitHub Actions CI | Implemented |
| Gemini-assisted explanation | Existing project capability |
| Firebase authentication/data | Existing project capability |
| File and QR workflows | Existing project capability |
| Browser extension | Existing project capability |

## Detection pipeline

```text
                         User / Extension
                               |
                               v
                      POST /api/analysis
                               |
                               v
                    Request + URL validation
                               |
                               v
                         SSRF checks
                               |
                 +-------------+-------------+
                 |                           |
                 v                           v
        Deterministic analysis       Threat intelligence
                 |                           |
        +--------+--------+        +---------+---------+
        |                 |        |         |    |    |
        v                 v        v         v    v    v
   URL features       Risk rules   DNS       TLS WHOIS VT
                 \                /
                  \              /
                   +------------+
                         |
                         v
                  Redirect analysis
                         |
                         v
                Combined evidence
                         |
                         v
                Calibrated scoring
                         |
                         v
                Typed security report
```

## Architecture

The backend is being decomposed into focused layers instead of putting all analysis logic in one Express entry point:

```text
server/
├── api/                    # HTTP contracts, controllers, routes
├── analysis/               # features, scoring, enriched analysis
├── config/                 # validated environment configuration
├── security/               # headers, rate limiting, URL/SSRF validation
├── services/               # DNS, TLS, WHOIS, VirusTotal, redirects
├── app.ts                  # Express application factory
└── startup.ts              # process startup / listen()
```

The legacy `server.ts` remains in the repository for compatibility while the modular server layer is introduced incrementally.

## Security model

The project treats external analysis as untrusted I/O:

- Request bodies are validated before analysis.
- External destinations are passed through URL/destination validation before network analysis.
- Redirect destinations are validated again before following the next hop.
- External intelligence services use explicit timeouts.
- VirusTotal failure is non-fatal; local analysis can still produce a result.
- Secrets are read from server-side environment configuration and are not intended for client bundles.
- Risk scores are deterministic from collected evidence; AI output is not the sole source of the baseline score.

## Technology stack

**Frontend**

React 18 · TypeScript · Vite · Tailwind CSS · Recharts · Motion · Lucide

**Backend**

Node.js · Express · TypeScript

**Security intelligence**

Node DNS · TLS certificate inspection · WHOIS · VirusTotal · redirect analysis

**AI**

Google Gemini

**Authentication / data**

Firebase Authentication · Firestore · Firebase Admin

**Testing / quality**

Vitest · Firebase Rules Unit Testing · TypeScript strict checking · GitHub Actions

## Requirements

- Node.js 20+
- npm 10+
- A Firebase project for deployments that use the Firebase-backed features
- Gemini API key for Gemini-dependent functionality
- VirusTotal API key for VirusTotal enrichment

## Installation

```bash
npm install
```

Create a local environment file from the example configuration:

```bash
cp .env.example .env.local
```

Populate only the credentials required for the features you are using.

## Environment configuration

The modular server reads configuration through `server/config/env.ts`.

Common variables include:

```dotenv
NODE_ENV=development
PORT=3000
ALLOWED_ORIGINS=http://localhost:5173
GEMINI_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
HIBP_API_KEY=
DEHASHED_EMAIL=
DEHASHED_API_KEY=
LYZR_API_KEY=
```

Never commit `.env.local`, API keys, Firebase service-account credentials, or other secrets.

## Development

The existing project entry point remains:

```bash
npm run dev
```

Run the quality checks with:

```bash
npm run typecheck
npm test
npm run build
```

Or run the full local gate:

```bash
npm run check
```

## Testing

Run the full Vitest suite:

```bash
npm test
```

Run security-analysis tests only:

```bash
npm run test:security
```

Run Firestore rules tests:

```bash
npm run test:rules
```

The analysis tests mock external intelligence providers so unit tests can remain deterministic and do not require live API credentials.

## API contract

The modular API exposes the analysis route through the API router:

```http
POST /api/analysis
Content-Type: application/json
```

Request:

```json
{
  "url": "https://example.com"
}
```

The response contains structured analysis data including URL features, findings, a calibrated risk assessment, threat-intelligence results, and redirect evidence.

## CI

GitHub Actions runs on pushes and pull requests targeting `main`:

```text
npm ci
   ↓
npm run typecheck
   ↓
npm test
   ↓
npm run build
```

Workflow: `.github/workflows/ci.yml`

## Project structure

```text
.
├── src/                  # React application
├── extension/            # Browser extension
├── assets/               # Static project assets
├── docs/                 # Deployment/build assets used by the project
├── server/               # Modular backend architecture
│   ├── api/
│   ├── analysis/
│   ├── config/
│   ├── security/
│   └── services/
├── server.ts             # Existing application entry point
├── firestore.rules
├── firestore.rules.test.ts
├── vite.config.ts
├── tsconfig.json
├── package.json
└── .github/workflows/ci.yml
```

## Production considerations

Before production deployment, configure strict CORS origins, rate limits appropriate to the expected traffic, centralized secret management, structured logging, least-privilege Firebase IAM, dependency and secret scanning, and monitoring for failed external intelligence providers.

## Roadmap

- Complete incremental extraction from the legacy `server.ts`
- Add controller/API integration tests
- Add provider-specific service tests and fixtures
- Add dependency vulnerability and secret scanning to CI
- Add structured security-event telemetry
- Improve explanation quality around evidence and confidence
- Expand browser-extension integration with the typed analysis API
- Continue frontend/dashboard improvements based on the enriched result model

## License

Apache-2.0
