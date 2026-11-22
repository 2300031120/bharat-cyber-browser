import { domainToASCII } from 'node:url';
import { isIP } from 'node:net';

const USER_AGENT = 'BharatCyberSearch/0.1 (local personal research tool)';

function isPublicIp(value, version) {
  if (version === 4) {
    const [a, b] = value.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) || (a === 203 && b === 0));
  }
  const lower = value.toLowerCase();
  if (lower === '::' || lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') ||
      /^fe[89ab]/.test(lower) || lower.startsWith('ff') || lower.startsWith('::ffff:')) return false;
  return true;
}

export function normalizeAssetTarget(input) {
  if (typeof input !== 'string' || input.length > 260) throw Object.assign(new Error('Enter a public domain name or IP address.'), { status: 400 });
  const raw = input.trim();
  const version = isIP(raw);
  if (version) {
    if (!isPublicIp(raw, version)) throw Object.assign(new Error('Use a public IP address for passive lookup.'), { status: 400 });
    return { target: raw.toLowerCase(), type: 'ip' };
  }
  if (!raw || /[\s/@?#:]/.test(raw) || raw.includes('..')) throw Object.assign(new Error('Enter a domain only, without a URL path or scheme.'), { status: 400 });
  const target = domainToASCII(raw.replace(/\.$/, '').toLowerCase());
  const labels = target.split('.');
  if (!target || target.length > 253 || labels.length < 2 || labels.some((label) => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) ||
      target === 'localhost' || target.endsWith('.local') || target.endsWith('.internal') || target.endsWith('.test')) {
    throw Object.assign(new Error('Enter a valid public domain name.'), { status: 400 });
  }
  return { target, type: 'domain' };
}

async function getJson(url, source, maxBytes = 3_000_000) {
  const response = await fetch(url, {
    headers: { 'user-agent': USER_AGENT, accept: 'application/json,application/dns-json' },
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`${source} unavailable`);
  const declaredSize = Number(response.headers.get('content-length') || 0);
  if (declaredSize > maxBytes) throw new Error(`${source} response too large`);
  const text = await response.text();
  if (Buffer.byteLength(text) > maxBytes) throw new Error(`${source} response too large`);
  return JSON.parse(text);
}

function summarizeRdap(value, type, target) {
  return {
    name: value.ldhName || value.name || null,
    handle: value.handle || null,
    country: value.country || null,
    startAddress: value.startAddress || null,
    endAddress: value.endAddress || null,
    type: value.type || null,
    status: Array.isArray(value.status) ? value.status.slice(0, 12) : [],
    events: Array.isArray(value.events) ? value.events.slice(0, 8).map(({ eventAction, eventDate }) => ({ eventAction, eventDate })) : [],
    nameservers: Array.isArray(value.nameservers) ? value.nameservers.slice(0, 30).map((item) => item.ldhName || item.unicodeName).filter(Boolean) : [],
    sourceUrl: `https://rdap.org/${type}/${encodeURIComponent(target)}`
  };
}

export async function lookupAsset(input) {
  const { target, type } = normalizeAssetTarget(input);
  const disclosedTo = type === 'domain' ? ['crt.sh', 'rdap.org', 'Google Public DNS'] : ['rdap.org'];
  const errors = [];
  const output = { target, type, disclosedTo, certificates: [], dns: { A: [], AAAA: [], MX: [], NS: [] }, rdap: null, errors };

  const tasks = [
    { source: 'rdap.org', promise: getJson(`https://rdap.org/${type}/${encodeURIComponent(target)}`, 'RDAP').then((data) => { output.rdap = summarizeRdap(data, type, target); }) }
  ];
  if (type === 'domain') {
    const certQuery = `%.${target}`;
    tasks.push({ source: 'crt.sh', promise: getJson(`https://crt.sh/?q=${encodeURIComponent(certQuery)}&output=json`, 'Certificate Transparency', 5_000_000).then((data) => {
      if (!Array.isArray(data)) throw new Error('Certificate Transparency unavailable');
      const unique = new Map();
      for (const cert of data) {
        const key = String(cert.id || `${cert.name_value}:${cert.not_before}`);
        if (!unique.has(key)) unique.set(key, {
          name: String(cert.name_value || '').slice(0, 600),
          issuer: String(cert.issuer_name || '').slice(0, 220),
          notBefore: cert.not_before || null,
          notAfter: cert.not_after || null,
          sourceUrl: `https://crt.sh/?id=${encodeURIComponent(key)}`
        });
        if (unique.size >= 50) break;
      }
      output.certificates = [...unique.values()];
    }) });
    for (const recordType of ['A', 'AAAA', 'MX', 'NS']) {
      const url = `https://dns.google/resolve?name=${encodeURIComponent(target)}&type=${recordType}`;
      tasks.push({ source: 'Google Public DNS', promise: getJson(url, 'Google Public DNS', 500_000).then((data) => {
        output.dns[recordType] = (data.Answer || []).slice(0, 30).map((item) => ({ type: item.type, ttl: item.TTL, data: String(item.data || '').slice(0, 500) }));
      }) });
    }
  }

  const settled = await Promise.allSettled(tasks.map((task) => task.promise));
  settled.forEach((result, index) => {
    if (result.status === 'rejected') errors.push({ source: tasks[index].source, message: 'This source is temporarily unavailable.' });
  });
  return output;
}
