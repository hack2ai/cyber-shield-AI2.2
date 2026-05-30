# Cyber Shield Browser Extension

This extension allows you to perform real-time phishing scans directly from your browser toolbar.

## Installation Instructions (Developer Mode)

1. **Download the Extension Files**:
   Ensure you have the following files in a folder named `extension`:
   - `manifest.json`
   - `popup.html`
   - `popup.js`
   - `popup.css`

2. **Open Extensions Page**:
   In your browser (Chrome, Edge, Brave), go to `chrome://extensions/` (or equivalent).

3. **Enable Developer Mode**:
   Toggle the **Developer mode** switch in the top right corner.

4. **Load Unpacked**:
   Click the **Load unpacked** button and select the `extension` folder.

5. **Configure API URL**:
   - Click the Cyber Shield icon in your toolbar.
   - Click **CONFIG**.
   - Enter your Cyber Shield App URL (e.g., `https://your-app-id.run.app`).
   - Click **SAVE_CONFIG**.

## Features
- One-click URL scanning.
- TLD reputation check.
- SSL validity verification.
- Threat scoring consistent with the main Cyber Shield dashboard.
