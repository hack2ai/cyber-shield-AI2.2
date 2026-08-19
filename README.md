# Cyber Shield AI

AI-assisted phishing and threat-intelligence platform for URL, domain, certificate, and file analysis.

Cyber Shield AI combines deterministic security heuristics with live network intelligence and Gemini-assisted analysis. It can run with the full Express analysis service or degrade gracefully to browser-side heuristics when deployed as a static site.

## What it does

- URL and domain threat analysis
- DNS, TLS certificate, WHOIS, and redirect intelligence
- Suspicious TLD and URL-shortener detection
- Entropy and structural URL heuristics
- VirusTotal enrichment when configured
- Gemini-assisted threat explanation and scoring
- File and QR-code analysis workflows
- Firebase Authentication and Firestore-backed security data
- Browser-extension integration
- Admin controls, scan history, and security telemetry
- Firestore security-rule tests

## Architecture

```text
React + Vite UI
      |
      +---- Browser heuristics (static fallback)
      |
      +---- Express analysis API
                 |
                 +---- DNS / TLS / WHOIS
                 +---- VirusTotal
                 +---- Gemini
                 +---- Puppeteer / redirect inspection
                 +---- Firebase Admin / Firestore
```

The UI is separated conceptually from privileged server-side intelligence. API keys and server credentials must remain on the server and must never be embedded in the browser bundle.

## Stack

- Frontend: React 18, TypeScript, Vite, Tailwind CSS, Recharts, Motion
- Backend: Node.js, Express, TypeScript
- Security intelligence: DNS, TLS, WHOIS, VirusTotal, Puppeteer
- AI: Google Gemini
- Data/auth: Firebase, Firestore
- Testing: Vitest + Firebase Rules Unit Testing

## Requirements

- Node.js 20+
- npm 10+
- Firebase project for authenticated/server-backed deployments
- Gemini API key for AI analysis
- VirusTotal API key for optional enrichment

## Local development

```bash
npm install
cp .env.example .env.local
npm run dev
```

Then open `http://localhost:3000`.

## Environment variables

See `.env.example`. Keep secrets only in local environment files or your deployment secret manager.

```dotenv
GEMINI_API_KEY=
VIRUSTOTAL_API_KEY=
LYZR_API_KEY=
```

Do not commit `.env.local`, API keys, Firebase service-account credentials, or runtime debug logs.

## Production build

```bash
npm run build
npm start
```

The Vite frontend is emitted to `docs/` for the current GitHub Pages deployment model, while the Express server bundle is emitted to `dist/server.js`.

## Security notes

This project is a defensive security-analysis tool. Results are heuristic and enrichment-driven, not a guarantee that a resource is safe or malicious. Never use a single score as the sole basis for a security decision.

For production use, configure strict CORS origins, secure headers, rate limiting, request validation, structured logging, secret management, and least-privilege Firebase IAM.

## Testing

```bash
npm run test:rules
npm run typecheck
npm run lint
```

## Project structure

```text
.
├── src/                  # React application
│   ├── components/       # Reusable UI components
│   ├── lib/              # Client-side service integrations
│   ├── utils/            # Shared client utilities
│   └── App.tsx           # Current application shell
├── extension/            # Browser extension
├── docs/                 # GitHub Pages build output
├── assets/               # Static project assets
├── firestore.rules       # Firestore authorization rules
├── firestore.rules.test.ts
├── server.ts             # Express analysis service
├── vite.config.ts
└── package.json
```

## Deployment

### GitHub Pages

Build the project and publish the `docs/` directory from the `main` branch, as configured in `vite.config.ts`.

### Full server deployment

Deploy the Node.js server to a platform that supports long-running Express processes and configure required environment variables in the platform's secret manager.

## Roadmap

- Modularize the analysis engine into typed services
- Add API request schemas and centralized error handling
- Add automated CI for type-checking, linting, tests, and builds
- Add API/integration tests for threat-analysis endpoints
- Add security dependency scanning and secret scanning
- Improve observability with structured security events
- Add calibrated scoring and explainable finding weights

## License

Apache-2.0
