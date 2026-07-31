# Email Analyzer

A serverless, browser-based email forensics dashboard. Paste raw email headers or upload a `.eml` file to trace the delivery path, verify SPF/DKIM/DMARC authentication, identify the sending ESP, check IP reputation against 8 blacklists, and generate one-click abuse reports.

**All processing happens in your browser. Email data never leaves your machine.**

## Features

- Parse email headers and trace the full delivery path (Received chain)
- Extract sending IP and identify ESP/network owner via RDAP
- Check SPF, DKIM, DMARC authentication records live via DNS
- Query 8 public IP blacklists + Spamhaus ZEN
- Full IPv4 and IPv6 support
- One-click abuse report generation (opens your email client pre-filled)
- Two views: Basic (end-user) and Advanced (deliverability specialist)

## Deployment

### 1. GitHub Pages

1. Push this repo to GitHub
2. Go to **Settings > Pages**
3. Set Source: `Deploy from a branch`, Branch: `main`, folder `/`
4. Site goes live at `https://<username>.github.io/EmailAnalyzer/`

### 2. Cloudflare Worker (required for Spamhaus)

Spamhaus blocks queries from shared public resolvers (1.1.1.1, 8.8.8.8). A Cloudflare Worker queries it from the edge instead.

1. Go to [dash.cloudflare.com](https://dash.cloudflare.com/)
2. **Workers & Pages > Create Service**
3. Name it `email-analyzer-spamhaus`, click **Create**
4. In the editor, paste the contents of `worker.js`
5. Click **Deploy**
6. Copy your Worker URL — looks like `https://email-analyzer-spamhaus-abc123.workers.dev`
7. In `app.js`, find this line and replace the placeholder:
   ```js
   const workerUrl = 'https://YOUR-WORKER-SUBDOMAIN.workers.dev';
   ```
8. Commit and push

**Free tier:** 100,000 requests/day — plenty for personal or team use.

To verify the Worker is working:
```bash
curl -X POST https://YOUR-WORKER-URL.workers.dev \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4"}'
# Expected: {"listed":false,"error":null}
```

### 3. Local Testing

```bash
# Python 3
python -m http.server 8000

# Or Node.js
npx http-server
```

Open `http://localhost:8000` and paste the contents of `SAMPLE_EMAIL.txt` to test.

## Usage

1. Paste raw email headers into the text area, or upload a `.eml` file
2. Click **Analyze Email**
3. **Basic View** — authentication badges, sender info, IP, ESP, blacklist results, abuse contact
4. **Advanced View** — received hops table with latency, raw SPF/DMARC records, RDAP JSON, full raw headers
5. Click **One-Click Abuse Report** to open your email client with the abuse report pre-filled

## Architecture

```
Browser                        Edge / Public APIs
──────────────────────         ────────────────────────────────────
index.html + app.js            Cloudflare DoH      → SPF, DMARC, DNSBL lookups
  │                            rdap.org            → IP owner, abuse contact
  │  POST { ip }               Cloudflare Worker   → Spamhaus ZEN
  └─────────────────────────►  (worker.js)
```

- No npm, no build step — open `index.html` directly or serve with any static host
- Email data (From, To, Subject, headers) stays in the browser; only IPs and domains go to public APIs
- Cloudflare Worker adds CORS headers so the browser can call Spamhaus indirectly

## Tech Stack

| Layer | Technology |
|-------|-----------|
| UI | HTML5 + Tailwind CSS v4 (CDN) |
| Logic | Vanilla ES6+ JavaScript |
| DNS | Cloudflare DoH (`cloudflare-dns.com/dns-query`) |
| IP info | RDAP via `rdap.org` proxy |
| Spamhaus | Cloudflare Worker (free tier) |
| Hosting | GitHub Pages |

## Security & Privacy

- No cookies, tracking, or analytics
- Email data never transmitted — only IPs and domain names reach public APIs
- Worker validates IP format before forwarding to Spamhaus
- XSS-safe: all user-supplied content rendered via `textContent`, never `innerHTML`

## License

MIT
