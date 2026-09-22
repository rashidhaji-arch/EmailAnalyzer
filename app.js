// ─── Worker Configuration ─────────────────────────────────────────────────────
// Deploy worker.js to Cloudflare Workers (free), then paste your Worker URL here.
// Without this, blacklist checks cannot run — browser JS cannot query DNSBL zones
// directly because the major blacklist providers block shared public DNS resolvers.
//
// Steps: https://dash.cloudflare.com → Workers & Pages → Create Worker
//        Paste worker.js → Deploy → copy URL → paste below → push to GitHub
//
const WORKER_URL = ''; // e.g. 'https://email-dnsbl.yourname.workers.dev'

// ─── Constants ────────────────────────────────────────────────────────────────

const PRIVATE_RANGES = [
    /^127\./,           // loopback
    /^10\./,            // RFC 1918
    /^192\.168\./,      // RFC 1918
    /^172\.(1[6-9]|2\d|3[01])\./,  // RFC 1918
    /^169\.254\./,      // link-local
    /^0\.0\.0\.0$/,
    /^::1$/,            // IPv6 loopback
    /^fc/i,             // IPv6 unique local
    /^fd/i,
];

const DNSBL_LIST = [
    { name: 'Spamhaus ZEN',    host: 'zen.spamhaus.org' },
    { name: 'SpamCop',         host: 'bl.spamcop.net' },
    { name: 'Barracuda',       host: 'b.barracudacentral.org' },
    { name: 'UCEProtect L1',   host: 'dnsbl.uceprotect.net' },
    { name: 'PSBL',            host: 'psbl.surriel.com' },
    { name: 'NordSpam',        host: 'dnsbl.nordspam.com' },
];

// ─── Header Parsing ───────────────────────────────────────────────────────────
// RFC 5322 headers are prepended (newest first). Duplicate headers like
// Received: and Authentication-Results: must all be kept, not just the last.

function parseHeaders(rawText) {
    const map = new Map(); // lowercase-name → string[]
    const lines = rawText.split(/\r?\n/);
    let key = null;
    let val = '';

    function commit() {
        if (!key) return;
        const existing = map.get(key) || [];
        existing.push(val.trim());
        map.set(key, existing);
    }

    for (const line of lines) {
        if (/^[ \t]/.test(line)) {
            val += ' ' + line.trim();
        } else {
            commit();
            const colon = line.indexOf(':');
            if (colon > 0) {
                key = line.slice(0, colon).toLowerCase().trim();
                val = line.slice(colon + 1).trim();
            } else {
                key = null;
                val = '';
            }
        }
    }
    commit();

    return {
        get: (name) => map.get(name.toLowerCase()) || [],
        first: (name) => (map.get(name.toLowerCase()) || [])[0] || null,
        raw: rawText,
    };
}

// ─── Received Chain Parsing ───────────────────────────────────────────────────

function isPrivateIP(ip) {
    if (!ip) return true;
    return PRIVATE_RANGES.some(re => re.test(ip));
}

function extractBracketedIPv4(str) {
    const m = str.match(/\[(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\]/);
    return m ? m[1] : null;
}

function parseReceivedHop(raw) {
    const hop = { fromHost: null, fromIP: null, byHost: null, protocol: null, timestamp: null, date: null, raw };
    let value = raw;

    // Timestamp is after the last semicolon
    const semi = value.lastIndexOf(';');
    if (semi !== -1) {
        hop.timestamp = value.slice(semi + 1).trim();
        const d = new Date(hop.timestamp);
        if (!isNaN(d)) hop.date = d;
        value = value.slice(0, semi);
    }

    // Salesforce/ecelerity style: from [IP] ([IP:port] helo=hostname)
    const bracketFromRe = /from\s+\[(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\]\s+\([^)]*helo=(\S+)/i;
    const bracketMatch = value.match(bracketFromRe);
    if (bracketMatch) {
        hop.fromIP = bracketMatch[1];
        hop.fromHost = bracketMatch[2];
    } else {
        // Standard style: from hostname (verified-hostname [IP])
        const stdFromRe = /from\s+(\S+)\s*\(([^)]*)\)/i;
        const stdMatch = value.match(stdFromRe);
        if (stdMatch) {
            hop.fromHost = stdMatch[1].replace(/^\[|\]$/g, '');
            hop.fromIP = extractBracketedIPv4(stdMatch[2]);
            if (!hop.fromIP && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hop.fromHost)) {
                hop.fromIP = hop.fromHost;
            }
        }
    }

    const byMatch = value.match(/\bby\s+(\S+)/i);
    if (byMatch) hop.byHost = byMatch[1].replace(/[;,()]+$/, '');

    const withMatch = value.match(/\bwith\s+(\S+)/i);
    if (withMatch) hop.protocol = withMatch[1];

    return hop;
}

function parseReceivedChain(headers) {
    // Headers are prepended newest-first; reverse gives chronological order
    return headers.get('received').map(parseReceivedHop).reverse();
}

function findOriginatingHop(hops) {
    for (const hop of hops) {
        if (hop.fromIP && !isPrivateIP(hop.fromIP)) return hop;
    }
    return null;
}

// ─── Sender Identity Analysis ─────────────────────────────────────────────────

function parseEmailAddress(raw) {
    if (!raw) return { display: null, email: null, domain: null };
    const angleMatch = raw.match(/<([^>]+)>/);
    let email, display;
    if (angleMatch) {
        email = angleMatch[1].trim();
        display = raw.slice(0, raw.indexOf('<')).trim().replace(/^["']|["']$/g, '') || null;
    } else {
        email = raw.trim();
        display = null;
    }
    const atIdx = email.lastIndexOf('@');
    const domain = atIdx >= 0 ? email.slice(atIdx + 1).toLowerCase() : null;
    return { display, email, domain };
}

function analyzeSenderIdentity(headers) {
    const from = parseEmailAddress(headers.first('from'));
    const returnPath = parseEmailAddress(headers.first('return-path'));
    const replyTo = parseEmailAddress(headers.first('reply-to'));

    const domainMismatch = !!(from.domain && returnPath.domain && from.domain !== returnPath.domain);

    // Flag if the display name contains a domain-like string differing from the actual sending domain
    let displayNameSpoof = false;
    if (from.display && from.domain) {
        const domainInName = from.display.match(/[a-z0-9-]+\.[a-z]{2,}/i);
        if (domainInName && domainInName[0].toLowerCase() !== from.domain) {
            displayNameSpoof = true;
        }
    }

    return { from, returnPath, replyTo, domainMismatch, displayNameSpoof };
}

// ─── Authentication Results ───────────────────────────────────────────────────
// Multiple Authentication-Results headers exist in forwarded/relayed mail.
// Received-SPF (added by the first-contact server) is the most authoritative
// SPF verdict for the originating IP.

function parseAllAuthResults(headers) {
    const result = { spf: null, dkim: null, dmarc: null };

    for (const h of headers.get('authentication-results')) {
        const spfM = h.match(/spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i);
        if (spfM) result.spf = spfM[1].toLowerCase();

        const dkimM = h.match(/dkim=(pass|fail|none|neutral|temperror|permerror)/i);
        if (dkimM) result.dkim = dkimM[1].toLowerCase();

        const dmarcM = h.match(/dmarc=(pass|fail|none)/i);
        if (dmarcM) result.dmarc = dmarcM[1].toLowerCase();
    }

    // Received-SPF gives us the raw SPF check against the originating IP —
    // override any forwarded-chain SPF result with this.
    const receivedSpf = headers.first('received-spf');
    if (receivedSpf) {
        const m = receivedSpf.match(/^(pass|fail|softfail|neutral|none|temperror|permerror)/i);
        if (m) result.spf = m[1].toLowerCase();
    }

    return result;
}

// ─── DNS-over-HTTPS ───────────────────────────────────────────────────────────
// Cloudflare DoH is used for regular DNS (SPF, DMARC).
// Google DoH is used for DNSBL queries — Cloudflare deliberately returns
// NXDOMAIN for DNSBL zones, making every check show "clean" incorrectly.

async function queryDoH(name, type, provider = 'cloudflare') {
    const url = provider === 'google'
        ? `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`
        : `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
    const hdrs = provider === 'cloudflare' ? { 'Accept': 'application/dns-json' } : {};
    try {
        const res = await fetch(url, { headers: hdrs });
        if (!res.ok) return { records: [], status: null, error: `HTTP ${res.status}` };
        const data = await res.json();
        if (data.Status === 3) return { records: [], status: 3, error: null }; // NXDOMAIN
        if (data.Status !== 0) return { records: [], status: data.Status, error: `DNS error ${data.Status}` };
        const records = (data.Answer || []).filter(a => a.type === 16 || a.type === 1).map(a => a.data);
        return { records, status: 0, error: null };
    } catch (err) {
        return { records: [], status: null, error: err.message };
    }
}

async function querySPF(domain) {
    const r = await queryDoH(domain, 'TXT', 'cloudflare');
    return { ...r, records: r.records.filter(s => s.toLowerCase().includes('v=spf1')) };
}

async function queryDMARC(domain) {
    return queryDoH(`_dmarc.${domain}`, 'TXT', 'cloudflare');
}

// ─── RDAP ─────────────────────────────────────────────────────────────────────

async function queryRDAP(ip) {
    try {
        const res = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`);
        if (!res.ok) return { error: `HTTP ${res.status}` };
        const data = await res.json();

        const findEntity = (entities, role) => {
            for (const e of (entities || [])) {
                if ((e.roles || []).includes(role)) return e;
                const found = findEntity(e.entities, role);
                if (found) return found;
            }
            return null;
        };

        const getName = (entity) =>
            entity?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || null;

        const getEmail = (entity) =>
            entity?.vcardArray?.[1]?.find(v => v[0] === 'email')?.[3] || null;

        const registrant = findEntity(data.entities, 'registrant');
        const abuseEntity = findEntity(data.entities, 'abuse');

        const org = getName(registrant) || data.name || data.handle || 'Unknown';
        const abuseEmail = getEmail(abuseEntity);
        const country = data.country || null;

        return { org, abuseEmail, country, network: data.name, raw: data, error: null };
    } catch (err) {
        return { error: err.message, org: null, abuseEmail: null, country: null, raw: null };
    }
}

// ─── DNSBL Checking ───────────────────────────────────────────────────────────

// ─── DNSBL Checking ───────────────────────────────────────────────────────────
// DNSBL checking requires a server-side resolver. Browser JS cannot query DNSBL
// zones directly: Cloudflare's and Google's public DoH APIs do not respond to
// these zones, so all checks silently return clean regardless of the IP's status.
//
// The solution is the included worker.js deployed to Cloudflare Workers (free).
// Set WORKER_URL above to enable this feature.

async function checkAllBlacklists(ip) {
    if (!WORKER_URL) {
        // Return a single placeholder so the UI can show a setup prompt
        return [{ name: '_setup_required', listed: false, error: null }];
    }

    try {
        const res = await fetch(`${WORKER_URL.replace(/\/$/, '')}?ip=${encodeURIComponent(ip)}`);
        if (!res.ok) {
            const text = await res.text().catch(() => `HTTP ${res.status}`);
            throw new Error(`Worker returned ${res.status}: ${text.slice(0, 120)}`);
        }
        const data = await res.json();
        if (!Array.isArray(data)) throw new Error('Unexpected worker response format');
        return data;
    } catch (err) {
        // Return a single error entry so the UI shows what went wrong
        return [{ name: '_worker_error', listed: false, error: err.message }];
    }
}

// ─── Render Helpers ───────────────────────────────────────────────────────────

const AUTH_CONFIG = {
    pass:       { label: 'PASS',       cls: 'auth-pass',       icon: '✅' },
    fail:       { label: 'FAIL',       cls: 'auth-fail',       icon: '❌' },
    softfail:   { label: 'SOFTFAIL',   cls: 'auth-softfail',   icon: '⚠️' },
    neutral:    { label: 'NEUTRAL',    cls: 'auth-neutral',    icon: '➖' },
    none:       { label: 'NONE',       cls: 'auth-none',       icon: '➖' },
    temperror:  { label: 'TEMP ERROR', cls: 'auth-error',      icon: '🔄' },
    permerror:  { label: 'PERM ERROR', cls: 'auth-error',      icon: '❌' },
};

function authConfig(status) {
    return AUTH_CONFIG[status] || { label: status ? status.toUpperCase() : 'UNKNOWN', cls: 'auth-unknown', icon: '❓' };
}

function authBadgeHTML(name, status) {
    const cfg = authConfig(status);
    return `<div class="auth-badge ${cfg.cls}">${cfg.icon} ${name}: ${cfg.label}</div>`;
}

function isAuthBad(spf, dkim, dmarc) {
    const bad = (v) => v && !['pass', 'neutral', 'none'].includes(v);
    return bad(spf) || bad(dkim) || bad(dmarc);
}

// ─── Render Functions ─────────────────────────────────────────────────────────

function renderSpoofAlert(sender, auth) {
    const alert = document.getElementById('spoof-alert');
    const reasons = [];

    if (sender.domainMismatch) {
        reasons.push(`From domain <strong>${escapeHtml(sender.from.domain)}</strong> does not match Return-Path domain <strong>${escapeHtml(sender.returnPath.domain)}</strong>`);
    }
    if (sender.displayNameSpoof) {
        reasons.push(`Display name "<strong>${escapeHtml(sender.from.display)}</strong>" contains a domain inconsistent with the sending address`);
    }
    if (auth.spf === 'fail' || auth.spf === 'softfail') {
        reasons.push(`SPF ${auth.spf.toUpperCase()} — sending IP is not authorized to send for this domain`);
    }
    if (auth.dkim === 'fail') {
        reasons.push('DKIM signature failed verification');
    }

    if (reasons.length === 0) {
        alert.classList.add('hidden');
        return;
    }

    alert.classList.remove('hidden');
    alert.innerHTML = `
        <div class="flex items-start gap-3">
            <span class="text-2xl flex-shrink-0">🚨</span>
            <div>
                <p class="font-bold text-lg mb-1">Spoofing / Authentication Warning</p>
                <ul class="list-disc list-inside space-y-1 text-sm">
                    ${reasons.map(r => `<li>${r}</li>`).join('')}
                </ul>
            </div>
        </div>`;
}

function renderAuthBadges(auth) {
    document.getElementById('auth-badges').innerHTML =
        authBadgeHTML('SPF', auth.spf) +
        authBadgeHTML('DKIM', auth.dkim) +
        authBadgeHTML('DMARC', auth.dmarc);
}

function renderSenderCard(headers, sender) {
    document.getElementById('sender-from-display').textContent = sender.from.display || '';
    document.getElementById('sender-from-email').textContent = sender.from.email || '—';
    document.getElementById('sender-returnpath').textContent = sender.returnPath.email || '—';
    document.getElementById('sender-subject').textContent = decodeHeader(headers.first('subject') || '(no subject)');
    document.getElementById('sender-date').textContent = headers.first('date') || '—';
    document.getElementById('sender-msgid').textContent = headers.first('message-id') || '—';

    // Domain alignment — only static strings go into innerHTML
    const el = document.getElementById('sender-domain-align');
    el.textContent = '';
    if (sender.domainMismatch) {
        el.innerHTML = '❌ <span class="text-red-600 dark:text-red-400 font-semibold">Mismatch — possible spoofing</span>';
    } else if (sender.from.domain && sender.returnPath.domain) {
        el.innerHTML = '✅ <span class="text-green-600 dark:text-green-400">Aligned</span>';
    } else {
        el.textContent = '—';
    }

    if (sender.replyTo.email && sender.replyTo.email !== sender.from.email) {
        document.getElementById('sender-replyto-row').classList.remove('hidden');
        document.getElementById('sender-replyto').textContent = sender.replyTo.email;
    }
}

function renderOriginatingIP(hop, rdap) {
    document.getElementById('origin-ip').textContent = hop.fromIP;
    document.getElementById('origin-hostname').textContent = hop.fromHost || '—';

    if (rdap) {
        document.getElementById('origin-org').textContent = rdap.org || '—';
        document.getElementById('origin-country').textContent = rdap.country || '—';
        document.getElementById('origin-abuse').textContent = rdap.abuseEmail || 'Not found';
        if (rdap.error) {
            document.getElementById('origin-org').textContent = `Error: ${rdap.error}`;
        }
    } else {
        document.getElementById('origin-org').textContent = 'Looking up…';
        document.getElementById('origin-abuse').textContent = 'Looking up…';
    }
}

function renderBlacklists(results) {
    const container = document.getElementById('blacklist-status');

    if (results.length === 1 && results[0].name === '_setup_required') {
        container.innerHTML = `
            <div class="bl-setup-notice">
                <p class="font-semibold mb-1">Blacklist checks require a one-time setup</p>
                <p class="text-xs mb-2">
                    Browser JavaScript cannot query DNSBL zones — major blacklist providers
                    (Spamhaus, SpamCop, etc.) block shared public DNS resolvers. The included
                    <code>worker.js</code> runs on Cloudflare's edge where these queries work.
                </p>
                <ol class="text-xs space-y-1 list-decimal list-inside">
                    <li>Go to <a href="https://dash.cloudflare.com" target="_blank" class="underline">dash.cloudflare.com</a> → Workers &amp; Pages → Create application → Create Worker</li>
                    <li>Paste the contents of <code>worker.js</code> from this repo, click Deploy</li>
                    <li>Copy the Worker URL (e.g. <code>https://email-dnsbl.yourname.workers.dev</code>)</li>
                    <li>Open <code>app.js</code>, set <code>WORKER_URL = 'your-url-here'</code> at the top, push to GitHub</li>
                </ol>
            </div>`;
        return;
    }

    if (results.length === 1 && results[0].name === '_worker_error') {
        container.innerHTML = `<div class="bl-item bl-error">⚠️ Worker error: ${escapeHtml(results[0].error)}</div>`;
        return;
    }

    container.innerHTML = results.map(r => {
        if (r.error) {
            return `<div class="bl-item bl-error">⚠️ ${escapeHtml(r.name)}: ${escapeHtml(r.error)}</div>`;
        }
        return r.listed
            ? `<div class="bl-item bl-listed">🚨 ${escapeHtml(r.name)}: LISTED</div>`
            : `<div class="bl-item bl-clean">✅ ${escapeHtml(r.name)}: Clean</div>`;
    }).join('');
}

function renderHopsTable(hops) {
    const tbody = document.getElementById('hops-table');
    tbody.innerHTML = hops.map((hop, i) => {
        const prev = i > 0 ? hops[i - 1] : null;
        let latency = '—';
        if (hop.date && prev?.date) {
            const diff = Math.round((hop.date - prev.date) / 1000);
            latency = diff >= 0 ? `${diff}s` : `${diff}s ⚠️`;
        }
        const privateFlag = hop.fromIP && isPrivateIP(hop.fromIP) ? ' <span class="text-xs text-gray-400">(internal)</span>' : '';
        const originFlag = i === 0 && hop.fromIP && !isPrivateIP(hop.fromIP) ? ' <span class="text-xs text-green-600 font-semibold">← origin</span>' : '';
        return `<tr class="${i % 2 === 0 ? 'bg-white dark:bg-gray-800' : 'bg-gray-50 dark:bg-gray-750'}">
            <td class="px-3 py-2 text-center">${i + 1}</td>
            <td class="px-3 py-2 font-mono">${escapeHtml(hop.fromIP || '—')}${privateFlag}${originFlag}</td>
            <td class="px-3 py-2">${escapeHtml(hop.fromHost || '—')}</td>
            <td class="px-3 py-2">${escapeHtml(hop.byHost || '—')}</td>
            <td class="px-3 py-2 font-mono text-xs">${escapeHtml(hop.timestamp || '—')}</td>
            <td class="px-3 py-2 text-right">${latency}</td>
        </tr>`;
    }).join('');
}

function renderDNSRecords(spf, dmarc, domain) {
    const spfEl = document.getElementById('dns-spf');
    const dmarcEl = document.getElementById('dns-dmarc');

    if (!domain) {
        spfEl.textContent = 'No sending domain found';
        dmarcEl.textContent = 'No sending domain found';
        return;
    }

    if (spf.error) {
        spfEl.textContent = `Error: ${spf.error}`;
    } else if (spf.records.length === 0) {
        spfEl.textContent = '(no SPF record found)';
    } else {
        spfEl.textContent = spf.records.join('\n');
    }

    if (dmarc.error) {
        dmarcEl.textContent = `Error: ${dmarc.error}`;
    } else if (dmarc.records.length === 0) {
        dmarcEl.textContent = '(no DMARC record found)';
    } else {
        dmarcEl.textContent = dmarc.records.join('\n');
    }
}

function renderRDAPRaw(rdap) {
    const el = document.getElementById('rdap-json');
    if (!rdap || rdap.error) {
        el.textContent = rdap?.error || 'Lookup failed';
    } else {
        el.textContent = JSON.stringify(rdap.raw, null, 2);
    }
}

function setupAbuseButton(ip, headers, sender, abuseEmail) {
    document.getElementById('abuse-report-btn').onclick = () => {
        const to = abuseEmail || 'abuse@example.com';
        const subject = `Abuse Report: ${ip}`;
        const body = [
            `Abuse report for originating IP: ${ip}`,
            '',
            'Email Details:',
            `  From:        ${headers.first('from') || '—'}`,
            `  Return-Path: ${headers.first('return-path') || '—'}`,
            `  To:          ${headers.first('to') || '—'}`,
            `  Subject:     ${headers.first('subject') || '—'}`,
            `  Date:        ${headers.first('date') || '—'}`,
            `  Message-ID:  ${headers.first('message-id') || '—'}`,
            '',
            '--- Raw Headers ---',
            headers.raw,
        ].join('\n');

        window.location.href = `mailto:${encodeURIComponent(to)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    };
}

// ─── UI Utilities ─────────────────────────────────────────────────────────────

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// Basic RFC 2047 encoded-word decode for display
function decodeHeader(str) {
    return str.replace(/=\?([^?]+)\?([BbQq])\?([^?]+)\?=/g, (_, charset, enc, text) => {
        try {
            if (enc.toUpperCase() === 'B') {
                return decodeURIComponent(escape(atob(text)));
            } else {
                return decodeURIComponent(text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (__, h) => '%' + h));
            }
        } catch (_) { return text; }
    });
}

function showError(msg) {
    const div = document.createElement('div');
    div.className = 'error-alert';
    div.innerHTML = `<strong>Error:</strong> ${escapeHtml(msg)}
        <button onclick="this.parentElement.remove()" class="float-right font-bold ml-4">×</button>`;
    document.getElementById('messages').appendChild(div);
}

function showWarning(msg) {
    const div = document.createElement('div');
    div.className = 'warning-alert';
    div.innerHTML = `<strong>Warning:</strong> ${escapeHtml(msg)}
        <button onclick="this.parentElement.remove()" class="float-right font-bold ml-4">×</button>`;
    document.getElementById('messages').appendChild(div);
}

function clearMessages() {
    document.getElementById('messages').innerHTML = '';
}

function showLoading(on) {
    document.getElementById('loading-indicator').classList.toggle('hidden', !on);
    document.getElementById('analyze-btn').disabled = on;
}

function clearResults() {
    document.getElementById('results').classList.add('hidden');
    document.getElementById('spoof-alert').classList.add('hidden');
}

// ─── View Toggle ──────────────────────────────────────────────────────────────

function initViewToggle() {
    document.querySelectorAll('.view-toggle-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const view = btn.dataset.view;
            document.querySelectorAll('.view-toggle-btn').forEach(b => b.classList.toggle('active', b === btn));
            document.getElementById('basic-view').classList.toggle('hidden', view !== 'basic');
            document.getElementById('advanced-view').classList.toggle('hidden', view !== 'advanced');
        });
    });
    document.querySelector('.view-toggle-btn[data-view="basic"]').classList.add('active');
}

// ─── Main Analysis Flow ───────────────────────────────────────────────────────

async function analyzeEmail(rawText) {
    clearMessages();
    clearResults();
    showLoading(true);

    try {
        const headers = parseHeaders(rawText);
        const hops = parseReceivedChain(headers);
        const originHop = findOriginatingHop(hops);
        const sender = analyzeSenderIdentity(headers);
        const auth = parseAllAuthResults(headers);

        // Show results section immediately
        document.getElementById('results').classList.remove('hidden');

        renderAuthBadges(auth);
        renderSpoofAlert(sender, auth);
        renderSenderCard(headers, sender);
        renderHopsTable(hops);
        document.getElementById('raw-headers').textContent = headers.raw;

        if (!originHop) {
            showWarning('No Received headers found — cannot trace originating IP');
            showLoading(false);
            return;
        }

        // Show IP immediately, org/abuse filled in after RDAP returns
        renderOriginatingIP(originHop, null);

        const sendingDomain = sender.returnPath?.domain || sender.from?.domain;
        document.getElementById('dns-spf').textContent = 'Querying…';
        document.getElementById('dns-dmarc').textContent = 'Querying…';
        document.getElementById('blacklist-status').innerHTML = '<div class="text-sm text-gray-500 dark:text-gray-400 p-2">Checking blacklists via DNS…</div>';
        document.getElementById('rdap-json').textContent = 'Loading…';

        const [rdap, spf, dmarc, blResults] = await Promise.all([
            queryRDAP(originHop.fromIP),
            sendingDomain ? querySPF(sendingDomain) : Promise.resolve({ records: [], error: null }),
            sendingDomain ? queryDMARC(sendingDomain) : Promise.resolve({ records: [], error: null }),
            checkAllBlacklists(originHop.fromIP),
        ]);

        renderOriginatingIP(originHop, rdap);
        renderDNSRecords(spf, dmarc, sendingDomain);
        renderBlacklists(blResults);
        renderRDAPRaw(rdap);
        setupAbuseButton(originHop.fromIP, headers, sender, rdap?.abuseEmail);

    } catch (err) {
        showError(`Analysis failed: ${err.message}`);
        console.error(err);
    }

    showLoading(false);
}

// ─── Event Listeners ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initViewToggle();

    document.getElementById('file-input').addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (ev) => { document.getElementById('input-area').value = ev.target.result; };
        reader.onerror = () => showError('Failed to read file');
        reader.readAsText(file);
    });

    document.getElementById('analyze-btn').addEventListener('click', () => {
        const text = document.getElementById('input-area').value.trim();
        if (!text) { showError('Paste email headers or upload a .eml file first'); return; }
        analyzeEmail(text);
    });

    document.getElementById('clear-btn').addEventListener('click', () => {
        document.getElementById('input-area').value = '';
        document.getElementById('file-input').value = '';
        clearMessages();
        clearResults();
    });

    // Keyboard shortcut: Ctrl+Enter to analyze
    document.getElementById('input-area').addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            document.getElementById('analyze-btn').click();
        }
    });
});
