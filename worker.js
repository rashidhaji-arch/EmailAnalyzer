/**
 * Cloudflare Worker — DNSBL Proxy for Email Analyzer
 *
 * Browser JavaScript cannot query DNSBL zones because:
 *   1. Spamhaus and others block queries from shared public resolvers (1.1.1.1, 8.8.8.8)
 *   2. Cloudflare's and Google's public DoH APIs enforce these restrictions
 *
 * This Worker runs on Cloudflare's edge and uses Cloudflare's internal resolver,
 * which IS allowed to query all major DNSBL zones. Results are returned as JSON
 * with proper CORS headers so the browser app can read them.
 *
 * ── Deployment (free, ~2 minutes) ────────────────────────────────────────────
 *   1. Go to https://dash.cloudflare.com → Workers & Pages → Create application
 *   2. Click "Create Worker" → name it anything (e.g. "email-dnsbl")
 *   3. Click "Edit code", paste the contents of this file, click "Deploy"
 *   4. Copy the Worker URL  (e.g. https://email-dnsbl.yourname.workers.dev)
 *   5. Open app.js and paste that URL as the value of WORKER_URL at the top
 *   6. Commit and push — blacklist checks will now work
 * ─────────────────────────────────────────────────────────────────────────────
 */

const DNSBL_LIST = [
    { name: 'Spamhaus ZEN',  host: 'zen.spamhaus.org' },
    { name: 'SpamCop',       host: 'bl.spamcop.net' },
    { name: 'Barracuda',     host: 'b.barracudacentral.org' },
    { name: 'UCEProtect L1', host: 'dnsbl.uceprotect.net' },
    { name: 'PSBL',          host: 'psbl.surriel.com' },
    { name: 'NordSpam',      host: 'dnsbl.nordspam.com' },
];

export default {
    async fetch(request) {
        if (request.method === 'OPTIONS') {
            return corsResponse(null, 204);
        }

        const url = new URL(request.url);
        const ip = url.searchParams.get('ip');

        if (!ip) return corsResponse({ error: 'Missing ?ip= parameter' }, 400);
        if (!isValidIPv4(ip)) return corsResponse({ error: 'Invalid IPv4 address' }, 400);

        const reversed = ip.split('.').reverse().join('.');
        const results = await Promise.all(
            DNSBL_LIST.map(bl => checkDNSBL(reversed, bl))
        );

        return corsResponse(results, 200);
    }
};

async function checkDNSBL(reversedIP, bl) {
    const query = `${reversedIP}.${bl.host}`;
    try {
        const res = await fetch(
            `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(query)}&type=A`,
            { headers: { 'Accept': 'application/dns-json' } }
        );
        if (!res.ok) return { ...bl, listed: false, error: `HTTP ${res.status}` };

        const data = await res.json();

        if (data.Status === 3) return { ...bl, listed: false, error: null };           // NXDOMAIN = not listed
        if (data.Status === 2) return { ...bl, listed: false, error: 'SERVFAIL' };     // resolver error
        if (data.Status !== 0) return { ...bl, listed: false, error: `DNS ${data.Status}` };

        const listed = (data.Answer || []).some(a => a.type === 1 && a.data.startsWith('127.'));
        const response = listed ? (data.Answer.find(a => a.type === 1)?.data || null) : null;
        return { ...bl, listed, response, error: null };
    } catch (err) {
        return { ...bl, listed: false, error: err.message };
    }
}

function isValidIPv4(ip) {
    const parts = ip.split('.');
    return parts.length === 4 && parts.every(p => {
        const n = parseInt(p, 10);
        return String(n) === p && n >= 0 && n <= 255;
    });
}

function corsResponse(body, status) {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    };
    if (body === null) return new Response(null, { status, headers });
    return new Response(JSON.stringify(body), {
        status,
        headers: { ...headers, 'Content-Type': 'application/json' },
    });
}
