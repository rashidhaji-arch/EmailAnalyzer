/**
 * Cloudflare Worker — Spamhaus DNSBL Proxy
 *
 * Browser cannot query Spamhaus directly because Spamhaus blocks shared public
 * DNS resolvers (1.1.1.1, 8.8.8.8). This Worker runs on the Cloudflare edge
 * and queries Spamhaus using Cloudflare's own resolver, then returns JSON to
 * the browser with proper CORS headers.
 *
 * Deploy steps:
 *   1. Go to https://dash.cloudflare.com/
 *   2. Workers & Pages > Create Service
 *   3. Paste this file into the editor
 *   4. Deploy
 *   5. Copy Worker URL → paste into app.js querySpamhausWorker() workerUrl const
 */

export default {
    async fetch(request) {
        // CORS preflight
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                status: 204,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'POST',
                    'Access-Control-Allow-Headers': 'Content-Type'
                }
            });
        }

        if (request.method !== 'POST') {
            return jsonResponse({ error: 'POST required' }, 405);
        }

        let payload;
        try {
            payload = await request.json();
        } catch (_) {
            return jsonResponse({ error: 'Invalid JSON body' }, 400);
        }

        const ip = payload.ip;
        if (!ip || typeof ip !== 'string') {
            return jsonResponse({ error: 'ip parameter required' }, 400);
        }

        // Validate IP format before forwarding to Spamhaus
        if (!isValidIP(ip)) {
            return jsonResponse({ error: 'Invalid IP address format' }, 400);
        }

        const result = await querySpamhausZen(ip);
        return jsonResponse(result, 200);
    }
};

function jsonResponse(data, status) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    });
}

function isValidIP(ip) {
    // IPv4
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        return ip.split('.').every(o => parseInt(o, 10) <= 255);
    }
    // IPv6 (simplified check)
    if (/^[0-9a-f:]{2,39}$/i.test(ip)) {
        return true;
    }
    return false;
}

async function querySpamhausZen(ip) {
    const reversedIP = reverseIP(ip);
    if (!reversedIP) {
        return { listed: false, error: 'Could not reverse IP for DNSBL query' };
    }

    const hostname = `${reversedIP}.zen.spamhaus.org`;

    try {
        const response = await fetch(
            `https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`,
            { headers: { 'Accept': 'application/dns-json' } }
        );

        if (!response.ok) {
            return { listed: false, error: `DNS lookup failed: HTTP ${response.status}` };
        }

        const data = await response.json();

        // NXDOMAIN (Status 3) = not listed
        if (data.Status === 3) {
            return { listed: false, error: null };
        }

        // Any A record in 127.0.0.0/24 means the IP is listed
        if (data.Answer) {
            for (const answer of data.Answer) {
                if (answer.type === 1 && answer.data.startsWith('127.0.0')) {
                    return { listed: true, error: null };
                }
            }
        }

        return { listed: false, error: null };
    } catch (err) {
        return { listed: false, error: err.message };
    }
}

function reverseIP(ip) {
    if (ip.includes('.')) {
        const octets = ip.split('.');
        if (octets.length !== 4) return null;
        return octets.reverse().join('.');
    }
    if (ip.includes(':')) {
        return reverseIPv6(ip);
    }
    return null;
}

function reverseIPv6(ipv6) {
    ipv6 = ipv6.replace(/[\[\]]/g, '');
    const expanded = expandIPv6(ipv6);
    if (!expanded) return null;
    const hex = expanded.replace(/:/g, '');
    return hex.split('').reverse().join('.');
}

function expandIPv6(ipv6) {
    if (ipv6.includes('::')) {
        const parts = ipv6.split('::');
        if (parts.length !== 2) return null;
        const left = parts[0] ? parts[0].split(':') : [];
        const right = parts[1] ? parts[1].split(':') : [];
        const missing = 8 - left.length - right.length;
        const expanded = [...left, ...Array(missing).fill('0'), ...right];
        return expanded.map(p => p.padStart(4, '0')).join(':');
    }
    return ipv6;
}