<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/d708adea-0ac2-46e6-98ae-db015f5d5c43

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in `.env.local` to your Gemini API key
3. Run the app:
   `npm run dev`

## Build for Production

To compile the React application and build the static assets for production, run:
```bash
npm run build
```
This command compiles the source code into the `docs/` folder (configured via `vite.config.ts`), preparing it for both static web servers (like GitHub Pages) and Express production server deployments.

## Deploying on GitHub Pages

The project is pre-configured to be served dynamically from GitHub Pages via the `/docs` directory on the `main` branch. 

To enable this on GitHub:
1. Open your repository on GitHub: `https://github.com/hack2ai/cyber-shield-AI2.2`.
2. Navigate to **Settings** (tab at the top menu).
3. Under the left-hand sidebar, select **Pages**.
4. In the **Build and deployment** section:
   - Under **Source**, choose **Deploy from a branch**.
   - Under **Branch**, select `main` (or your active branch) and change the folder from `/ (root)` to `/docs`.
   - Click **Save**.
5. Give GitHub Actions/Pages a minute to build and refresh. The application will be live and functional without any blank screen!

## Dual-Core Threat Intelligence Architecture

To provide a seamless user experience, Cyber Shield AI uses a **Dual-Core Threat Intelligence** execution engine:
1. **Server AI Mode (Local / Express Node Server):** Full live DNS lookups, TLS handshake certification parsing, WHOIS domain age extraction, and live Gemini AI threat assessment scoring.
2. **Static Heuristics Fallback (GitHub Pages Hosting):** Since static CDNs cannot execute server-side code, a client-side graceful heuristic parser automatically activates if the Express API is unreachable. It calculates entropy, validates IP formats, identifies high-risk Top-Level Domains (TLDs), detects URL shorteners, and formats realistic technical summaries dynamically in the browser, ensuring a zero-error user experience!
