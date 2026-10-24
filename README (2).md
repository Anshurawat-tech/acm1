# PhishGuard Frontend

A responsive frontend prototype for a phishing link and email checker.

## Included features

- URL scanning with explainable heuristic findings
- Suspicious TLD, IP address, `@` symbol, URL shortener, brand impersonation, Unicode, long URL, and sensitive-keyword checks
- Email and raw-header analysis
- Urgency, credential requests, financial lures, attachment extensions, links, and SPF/DKIM/DMARC warning signals
- Risk score from 0–100 with Safe, Suspicious, and High risk states
- Recent scan history stored only in the current browser
- `.eml`, `.msg`, and `.txt` upload support through local browser reading
- Responsive dashboard layout for desktop and mobile
- No npm packages or external assets required

## Run locally

Open `index.html` directly in a browser, or run a local server:

```bash
python3 -m http.server 8000
```

Then visit `http://localhost:8000`.

## Upload to GitHub

1. Create a new GitHub repository.
2. Upload `index.html` and `README.md`.
3. Open **Settings → Pages**.
4. Under **Build and deployment**, choose **Deploy from a branch**.
5. Choose the `main` branch and `/ (root)` folder, then save.

The frontend is currently in demo mode. The scanner logic runs in the browser and threat-intelligence responses are simulated. For production, connect a secure backend to Google Safe Browsing, VirusTotal, OpenPhish/PhishTank, URLScan, WHOIS/DNS checks, sandboxed screenshots, and an LLM explanation service. Never expose API keys in this frontend.

## Important safety note

This prototype cannot guarantee detection of every phishing or zero-day attack. Users should avoid opening suspicious links, downloading unknown attachments, or entering passwords until the destination is independently verified.
