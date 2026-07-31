// Email Header Parser
function parseEmailHeaders(rawText) {
    const lines = rawText.split('\n');
    const headers = {};
    let currentHeader = null;
    let currentValue = '';

    for (let line of lines) {
        if (line[0] === ' ' || line[0] === '\t') {
            currentValue += ' ' + line.trim();
        } else {
            if (currentHeader) {
                headers[currentHeader] = currentValue.trim();
            }
            const colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                currentHeader = line.substring(0, colonIndex).trim();
                currentValue = line.substring(colonIndex + 1).trim();
            } else {
                currentHeader = null;
            }
        }
    }
    if (currentHeader) {
        headers[currentHeader] = currentValue.trim();
    }

    const getHeader = (name) => {
        for (let key in headers) {
            if (key.toLowerCase() === name.toLowerCase()) {
                return headers[key];
            }
        }
        return null;
    };

    return {
        from: getHeader('From') || 'Unknown',
        to: getHeader('To') || 'Unknown',
        subject: getHeader('Subject') || '(no subject)',
        date: getHeader('Date') || 'Unknown',
        messageId: getHeader('Message-ID') || 'Unknown',
        receivedChain: getHeader('Received') || '',
        authenticationResults: getHeader('Authentication-Results') || '',
        rawHeaders: rawText,
        allHeaders: headers
    };
}

function parseReceivedChain(receivedHeader, allHeaders) {
    const receivedList = [];

    for (let key in allHeaders) {
        if (key.toLowerCase() === 'received') {
            const value = allHeaders[key];
            if (Array.isArray(value)) {
                receivedList.push(...value);
            } else {
                receivedList.push(value);
            }
        }
    }

    if (receivedList.length === 0 && receivedHeader) {
        receivedList.push(receivedHeader);
    }

    const hops = [];
    for (let received of receivedList) {
        const hop = parseReceivedHop(received);
        if (hop) {
            hops.push(hop);
        }
    }

    return hops.reverse();
}

function parseReceivedHop(receivedStr) {
    const hop = {
        ip: null,
        ipv6: false,
        hostname: null,
        timestamp: null
    };

    const ipv4Regex = /\b(?:(\d{1,3}\.){3}\d{1,3})\b/;
    const ipv6Regex = /\[?([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\]?/i;

    const ipv4Match = receivedStr.match(ipv4Regex);
    if (ipv4Match) {
        hop.ip = ipv4Match[0];
        hop.ipv6 = false;
    } else {
        const ipv6Match = receivedStr.match(ipv6Regex);
        if (ipv6Match) {
            hop.ip = ipv6Match[0].replace(/[\[\]]/g, '');
            hop.ipv6 = true;
        }
    }

    const hostRegex = /(?:from|by)\s+([^\s\[\]]+)(?:\s|\[|$)/i;
    const hostMatch = receivedStr.match(hostRegex);
    if (hostMatch) {
        hop.hostname = hostMatch[1];
    }

    const dateRegex = /;\s*(\w+,\s+\d+\s+\w+\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4})/;
    const dateMatch = receivedStr.match(dateRegex);
    if (dateMatch) {
        hop.timestamp = dateMatch[1];
        hop.date = new Date(dateMatch[1]);
    }

    return hop.ip ? hop : null;
}

function extractSendingIP(receivedChain) {
    if (!receivedChain || receivedChain.length === 0) {
        return null;
    }
    return receivedChain[0].ip;
}

function parseAuthenticationResults(authResultsHeader) {
    const result = {
        spf: null,
        dkim: null,
        dmarc: null
    };

    if (!authResultsHeader) {
        return result;
    }

    const lower = authResultsHeader.toLowerCase();

    if (lower.includes('spf=pass')) result.spf = 'pass';
    else if (lower.includes('spf=fail')) result.spf = 'fail';
    else if (lower.includes('spf=')) result.spf = 'unknown';

    if (lower.includes('dkim=pass')) result.dkim = 'pass';
    else if (lower.includes('dkim=fail')) result.dkim = 'fail';
    else if (lower.includes('dkim=')) result.dkim = 'unknown';

    if (lower.includes('dmarc=pass')) result.dmarc = 'pass';
    else if (lower.includes('dmarc=fail')) result.dmarc = 'fail';
    else if (lower.includes('dmarc=')) result.dmarc = 'unknown';

    return result;
}

function extractSendingDomain(fromHeader) {
    const emailMatch = fromHeader.match(/<([^>]+)>/);
    const email = emailMatch ? emailMatch[1] : fromHeader;
    const atIndex = email.indexOf('@');
    if (atIndex > 0) {
        return email.substring(atIndex + 1).toLowerCase();
    }
    return null;
}

function calculateLatency(timestamp1, timestamp2) {
    if (!timestamp1 || !timestamp2) return null;
    const date1 = new Date(timestamp1);
    const date2 = new Date(timestamp2);
    if (isNaN(date1) || isNaN(date2)) return null;
    const diffMs = Math.abs(date2 - date1);
    return Math.round(diffMs / 1000);
}

// File Upload Handlers
const fileInput = document.getElementById('file-input');
const inputArea = document.getElementById('input-area');
const analyzeBtn = document.getElementById('analyze-btn');
const clearBtn = document.getElementById('clear-btn');

fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
        inputArea.value = event.target.result;
    };
    reader.onerror = () => {
        showError('Failed to read file');
    };
    reader.readAsText(file);
});

analyzeBtn.addEventListener('click', () => {
    const rawText = inputArea.value.trim();
    if (!rawText) {
        showError('Please paste email headers or upload a file');
        return;
    }
    analyzeEmail(rawText);
});

clearBtn.addEventListener('click', () => {
    inputArea.value = '';
    fileInput.value = '';
    clearResults();
    clearErrors();
});

// UI Utilities
let currentView = 'basic';

function showError(message, isWarning = false) {
    const container = document.getElementById('error-messages');
    const div = document.createElement('div');
    div.className = isWarning ? 'warning-alert' : 'error-alert';

    const strong = document.createElement('strong');
    strong.textContent = isWarning ? 'Warning: ' : 'Error: ';
    div.appendChild(strong);

    const msgSpan = document.createElement('span');
    msgSpan.textContent = message;
    div.appendChild(msgSpan);

    const btn = document.createElement('button');
    btn.textContent = '×';
    btn.className = 'float-right font-bold';
    btn.onclick = () => div.remove();
    div.appendChild(btn);

    container.appendChild(div);
}

function clearErrors() {
    document.getElementById('error-messages').innerHTML = '';
}

function clearResults() {
    document.getElementById('auth-badges').innerHTML = '';
    document.getElementById('sender-from').textContent = '—';
    document.getElementById('sender-to').textContent = '—';
    document.getElementById('sender-subject').textContent = '—';
    document.getElementById('sender-date').textContent = '—';
    document.getElementById('sender-msgid').textContent = '—';
    document.getElementById('sending-ip').textContent = '—';
    document.getElementById('esp-provider').textContent = '—';
    document.getElementById('esp-abuse-email').textContent = '—';
    document.getElementById('blacklist-status').innerHTML = '';
    document.getElementById('hops-table').innerHTML = '';
    document.getElementById('dns-spf').textContent = '';
    document.getElementById('dns-dmarc').textContent = '';
    document.getElementById('rdap-json').textContent = '';
    document.getElementById('raw-headers').textContent = '';
}

document.querySelectorAll('.view-toggle-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
        const newView = e.target.dataset.view;
        currentView = newView;

        document.querySelectorAll('.view-toggle-btn').forEach(b => {
            b.classList.remove('active');
        });
        e.target.classList.add('active');

        document.getElementById('basic-view').classList.toggle('hidden', newView !== 'basic');
        document.getElementById('advanced-view').classList.toggle('hidden', newView !== 'advanced');
    });
});

document.getElementById('view-toggle-basic').classList.add('active');

// DNS-over-HTTPS Functions
async function queryDoH(domain, type = 'TXT') {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;

    try {
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/dns-json'
            }
        });

        if (!response.ok) {
            return { records: [], error: `HTTP ${response.status}` };
        }

        const data = await response.json();

        if (data.Status !== 0) {
            return { records: [], error: `DNS error code ${data.Status}` };
        }

        const records = [];
        if (data.Answer) {
            for (let answer of data.Answer) {
                if (answer.type === 16 || answer.type === 1) {
                    records.push(answer.data);
                }
            }
        }

        return { records: records, error: null };
    } catch (err) {
        return { records: [], error: err.message };
    }
}

async function querySPF(domain) {
    return await queryDoH(domain, 'TXT');
}

async function queryDMARC(domain) {
    const dmarcDomain = `_dmarc.${domain}`;
    return await queryDoH(dmarcDomain, 'TXT');
}

// RDAP Lookup Function
async function queryRDAP(ip) {
    const url = `https://rdap.org/ip/${encodeURIComponent(ip)}`;

    try {
        const response = await fetch(url);

        if (!response.ok) {
            return {
                org: null,
                abuseEmail: null,
                network: null,
                rawJson: null,
                error: `HTTP ${response.status}`
            };
        }

        const data = await response.json();

        let org = null;
        if (data.entities) {
            for (let entity of data.entities) {
                if (entity.roles && entity.roles.includes('registrant')) {
                    org = entity.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || null;
                    break;
                }
            }
        }

        let abuseEmail = null;
        if (data.entities) {
            for (let entity of data.entities) {
                if (entity.roles && entity.roles.includes('abuse')) {
                    const emails = entity.vcardArray?.[1]?.filter(v => v[0] === 'email');
                    if (emails && emails.length > 0) {
                        abuseEmail = emails[0][3];
                        break;
                    }
                }
            }
        }

        let network = null;
        if (data.name) {
            network = data.name;
        }

        return {
            org: org || 'Unknown',
            abuseEmail: abuseEmail || 'abuse@network.org',
            network: network || 'Unknown Network',
            rawJson: data,
            error: null
        };
    } catch (err) {
        return {
            org: null,
            abuseEmail: null,
            network: null,
            rawJson: null,
            error: err.message
        };
    }
}

// DNSBL Functions
async function queryDNSBL(ip, dnsblHost) {
    const reversedIP = reverseIPForDNSBL(ip);
    if (!reversedIP) {
        return { listed: false, response: null, error: 'Invalid IP format' };
    }

    const query = `${reversedIP}.${dnsblHost}`;

    try {
        const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(query)}&type=A`, {
            method: 'GET',
            headers: { 'Accept': 'application/dns-json' }
        });

        if (!response.ok) {
            return { listed: false, response: null, error: `HTTP ${response.status}` };
        }

        const data = await response.json();

        if (data.Status === 3) {
            return { listed: false, response: null, error: null };
        }

        if (data.Answer) {
            for (let answer of data.Answer) {
                if (answer.type === 1 && answer.data.startsWith('127.0.0')) {
                    return { listed: true, response: answer.data, error: null };
                }
            }
        }

        return { listed: false, response: null, error: null };
    } catch (err) {
        return { listed: false, response: null, error: err.message };
    }
}

function reverseIPForDNSBL(ip) {
    if (ip.includes('.')) {
        const octets = ip.split('.');
        if (octets.length !== 4) return null;
        return octets.reverse().join('.');
    }

    if (ip.includes(':')) {
        return reverseIPv6ForDNSBL(ip);
    }

    return null;
}

function reverseIPv6ForDNSBL(ipv6) {
    let expanded = expandIPv6(ipv6);
    if (!expanded) return null;

    const hex = expanded.replace(/:/g, '');
    const nibbles = hex.split('').reverse().join('.');
    return nibbles;
}

function expandIPv6(ipv6) {
    ipv6 = ipv6.replace(/[\[\]]/g, '');

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

async function querySpamhausWorker(ip) {
    const workerUrl = 'https://YOUR-WORKER-SUBDOMAIN.workers.dev';

    try {
        const response = await fetch(workerUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });

        if (!response.ok) {
            return { listed: false, error: `HTTP ${response.status}` };
        }

        const data = await response.json();

        if (data.error) {
            return { listed: false, error: data.error };
        }

        return { listed: data.listed, error: null };
    } catch (err) {
        return { listed: false, error: err.message };
    }
}

const DNSBL_LIST = [
    { name: 'Barracuda Reputation', host: 'b.barracudacentral.org' },
    { name: 'SpamCop', host: 'bl.spamcop.net' },
    { name: 'SORBS', host: 'dnsbl.sorbs.net' },
    { name: 'UCEProtect Level 1', host: 'dnsbl.uceprotect.net' },
    { name: 'PSBL', host: 'psbl.surriel.com' },
    { name: 'WPBL', host: 'wpbl.dnsbl.net' },
    { name: 'NordSpam', host: 'dnsbl.nordspam.com' }
];

// Main Analysis Flow
async function analyzeEmail(rawText) {
    clearErrors();
    clearResults();

    try {
        const emailData = parseEmailHeaders(rawText);

        document.getElementById('sender-from').textContent = emailData.from;
        document.getElementById('sender-to').textContent = emailData.to;
        document.getElementById('sender-subject').textContent = emailData.subject;
        document.getElementById('sender-date').textContent = emailData.date;
        document.getElementById('sender-msgid').textContent = emailData.messageId;
        document.getElementById('raw-headers').textContent = emailData.rawHeaders;

        const receivedChain = parseReceivedChain(emailData.receivedChain, emailData.allHeaders);
        if (!receivedChain || receivedChain.length === 0) {
            showError('No Received headers found — cannot trace email path');
            return;
        }

        renderHopsTable(receivedChain);

        const sendingIP = extractSendingIP(receivedChain);
        if (!sendingIP) {
            showError('Could not extract sending IP from Received chain');
            return;
        }

        document.getElementById('sending-ip').textContent = sendingIP;

        const authResults = parseAuthenticationResults(emailData.authenticationResults);
        renderAuthenticationBadges(authResults);

        const sendingDomain = extractSendingDomain(emailData.from);
        let spfRecords = null;
        let dmarcRecords = null;
        let rdapData = null;

        document.getElementById('dns-spf').textContent = 'Querying...';
        document.getElementById('dns-dmarc').textContent = 'Querying...';
        document.getElementById('rdap-json').textContent = 'Querying...';

        const apiPromises = [
            queryRDAP(sendingIP).then(data => { rdapData = data; }),
            (async () => {
                if (sendingDomain) {
                    spfRecords = await querySPF(sendingDomain);
                    dmarcRecords = await queryDMARC(sendingDomain);
                }
            })()
        ];

        await Promise.all(apiPromises);

        if (rdapData && !rdapData.error) {
            document.getElementById('esp-provider').textContent = rdapData.org || 'Unknown';
            document.getElementById('esp-abuse-email').textContent = rdapData.abuseEmail || 'Unknown';
            document.getElementById('rdap-json').textContent = JSON.stringify(rdapData.rawJson, null, 2);
        } else {
            showWarning(`RDAP lookup failed: ${rdapData?.error || 'Unknown error'}`);
            document.getElementById('esp-provider').textContent = 'Error';
            document.getElementById('rdap-json').textContent = rdapData?.error || 'Lookup failed';
        }

        if (spfRecords) {
            if (spfRecords.error) {
                document.getElementById('dns-spf').textContent = `Error: ${spfRecords.error}`;
            } else {
                document.getElementById('dns-spf').textContent = spfRecords.records.join('\n') || '(no SPF record)';
            }
        }

        if (dmarcRecords) {
            if (dmarcRecords.error) {
                document.getElementById('dns-dmarc').textContent = `Error: ${dmarcRecords.error}`;
            } else {
                document.getElementById('dns-dmarc').textContent = dmarcRecords.records.join('\n') || '(no DMARC record)';
            }
        }

        renderBlacklistStatus('Checking blacklists...');

        const blacklistResults = [];
        for (let dnsbl of DNSBL_LIST) {
            const result = await queryDNSBL(sendingIP, dnsbl.host);
            blacklistResults.push({ name: dnsbl.name, host: dnsbl.host, listed: result.listed, error: result.error });
        }

        const spamhausResult = await querySpamhausWorker(sendingIP);
        blacklistResults.push({
            name: 'Spamhaus ZEN',
            host: 'zen.spamhaus.org',
            listed: spamhausResult.listed,
            error: spamhausResult.error
        });

        renderBlacklistStatus(null, blacklistResults);

        setupAbuseReportButton(sendingIP, emailData, rdapData?.abuseEmail, authResults);

    } catch (err) {
        showError(`Analysis failed: ${err.message}`);
        console.error(err);
    }
}

function renderAuthenticationBadges(authResults) {
    const container = document.getElementById('auth-badges');
    container.innerHTML = '';

    const badges = [
        { label: 'SPF', result: authResults.spf },
        { label: 'DKIM', result: authResults.dkim },
        { label: 'DMARC', result: authResults.dmarc }
    ];

    for (let badge of badges) {
        const div = document.createElement('div');
        const statusClass = badge.result === 'pass' ? 'auth-pass' : badge.result === 'fail' ? 'auth-fail' : 'auth-unknown';
        const statusEmoji = badge.result === 'pass' ? '✅' : badge.result === 'fail' ? '❌' : '❓';
        const statusText = badge.result ? badge.result.toUpperCase() : 'UNKNOWN';

        div.className = `auth-badge ${statusClass}`;
        div.textContent = `${statusEmoji} ${badge.label}: ${statusText}`;
        container.appendChild(div);
    }
}

function renderHopsTable(receivedChain) {
    const tbody = document.getElementById('hops-table');
    tbody.innerHTML = '';

    for (let i = 0; i < receivedChain.length; i++) {
        const hop = receivedChain[i];
        const nextHop = i + 1 < receivedChain.length ? receivedChain[i + 1] : null;
        const latency = nextHop ? calculateLatency(hop.date, nextHop.date) : null;

        const tr = document.createElement('tr');
        const cells = [
            { text: String(i + 1), cls: 'px-3 py-2' },
            { text: hop.ip || '—', cls: 'px-3 py-2 font-mono' },
            { text: hop.hostname || '—', cls: 'px-3 py-2' },
            { text: hop.timestamp || '—', cls: 'px-3 py-2 font-mono' },
            { text: latency ? latency + 's' : '—', cls: 'px-3 py-2 text-right' }
        ];
        for (const { text, cls } of cells) {
            const td = document.createElement('td');
            td.className = cls;
            td.textContent = text;
            tr.appendChild(td);
        }
        tbody.appendChild(tr);
    }
}

function renderBlacklistStatus(loadingText = null, results = null) {
    const container = document.getElementById('blacklist-status');

    if (loadingText) {
        container.innerHTML = `<div class="blacklist-item blacklist-checking">${loadingText}</div>`;
        return;
    }

    container.innerHTML = '';

    if (!results || results.length === 0) {
        container.innerHTML = '<div class="blacklist-item blacklist-clean">✅ No blacklists queried</div>';
        return;
    }

    for (let result of results) {
        const div = document.createElement('div');
        div.className = `blacklist-item ${result.listed ? 'blacklist-listed' : 'blacklist-clean'}`;

        if (result.error) {
            div.textContent = `⚠️ ${result.name}: Error — ${result.error}`;
        } else if (result.listed) {
            div.textContent = `🚨 ${result.name}: LISTED`;
        } else {
            div.textContent = `✅ ${result.name}: Clean`;
        }

        container.appendChild(div);
    }
}

function setupAbuseReportButton(sendingIP, emailData, abuseEmail, authResults) {
    const btn = document.getElementById('abuse-report-btn');

    btn.onclick = () => {
        const subject = `Abuse Report: ${sendingIP}`;
        const body = `Abuse Report for Sending IP: ${sendingIP}

Email Details:
- From: ${emailData.from}
- To: ${emailData.to}
- Subject: ${emailData.subject}
- Date: ${emailData.date}
- Message-ID: ${emailData.messageId}

Authentication Status:
- SPF: ${authResults.spf || 'unknown'}
- DKIM: ${authResults.dkim || 'unknown'}
- DMARC: ${authResults.dmarc || 'unknown'}

---
Raw Email Headers:
${emailData.rawHeaders}`;

        const to = abuseEmail || 'abuse@example.com';
        const mailtoLink = `mailto:${encodeURIComponent(to)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

        window.location.href = mailtoLink;
    };
}

function showWarning(message) {
    showError(message, true);
}