const form = document.querySelector('#lookupForm');
const queryInput = document.querySelector('#query');
const emptyState = document.querySelector('#emptyState');
const loadingState = document.querySelector('#loadingState');
const errorState = document.querySelector('#errorState');
const results = document.querySelector('#results');
const historyList = document.querySelector('#historyList');
const historyCount = document.querySelector('#historyCount');
const metricTemplate = document.querySelector('#metricTemplate');

const sources = {
  ripe: 'RIPEstat public routing data',
  rdap: 'RDAP public registry data',
  dns: 'Cloudflare DNS-over-HTTPS + Google Public DNS',
  geo: 'IPwho.is geolocation data',
};

function classify(value) {
  const input = value.trim().replace(/^https?:\/\//i, '').replace(/\/$/, '');
  if (/^https?:\/\//i.test(value) || /[/?#]/.test(input)) return { error: 'URLs are not accepted. Enter only a hostname, IP address, or AS number.' };
  if (/^AS\d+$/i.test(input) || /^\d+$/.test(input)) return { type: 'asn', value: `AS${input.replace(/^AS/i, '')}` };
  if (isIPv4(input)) return { type: 'ip', value: input, version: 'IPv4' };
  if (isIPv6(input)) return { type: 'ip', value: input, version: 'IPv6' };
  if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(input)) return { type: 'domain', value: input.toLowerCase() };
  return { error: 'Enter a valid public IPv4, IPv6, fully-qualified domain, or ASN (for example, AS13335).' };
}

function isIPv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255 && String(Number(part)) === part);
}

function isIPv6(value) {
  if (!value.includes(':') || value.includes(':::')) return false;
  const [left = '', right = ''] = value.split('::');
  if (value.split('::').length > 2) return false;
  const validSide = (side) => !side || side.split(':').every((part) => /^[0-9a-f]{1,4}$/i.test(part));
  const count = (left ? left.split(':').length : 0) + (right ? right.split(':').length : 0);
  return validSide(left) && validSide(right) && (value.includes('::') ? count < 8 : count === 8);
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { Accept: 'application/json', ...(options.headers || {}) } });
  if (!response.ok) throw new Error(`Source request failed (${response.status}).`);
  return response.json();
}

function fulfilled(result, fallback = {}) { return result.status === 'fulfilled' ? result.value : fallback; }
function clean(value, fallback = 'Unavailable') { return value === undefined || value === null || value === '' ? fallback : String(value); }
function eventValue(events, action) { return events?.find((event) => event.eventAction === action)?.eventDate; }
function entityName(entities, role) {
  const entity = entities?.find((item) => item.roles?.includes(role));
  const fn = entity?.vcardArray?.[1]?.find((field) => field[0] === 'fn');
  return fn?.[3] || entity?.handle || 'Unavailable';
}
function sourceState(results) { return results.filter((result) => result.status === 'fulfilled').length; }

function registryDomain(domain) {
  const labels = domain.toLowerCase().split('.');
  if (labels.length <= 2) return domain;
  const countrySecondLevel = new Set(['ac', 'co', 'com', 'edu', 'gov', 'net', 'org']);
  return countrySecondLevel.has(labels.at(-2)) && labels.at(-1).length === 2 ? labels.slice(-3).join('.') : labels.slice(-2).join('.');
}

async function resolveDns(name, type) {
  const providers = [
    ['Cloudflare DoH', `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, { headers: { Accept: 'application/dns-json' } }],
    ['Google Public DNS', `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, {}],
  ];
  const attempts = await Promise.allSettled(providers.map(async ([provider, url, options]) => ({ provider, data: await fetchJson(url, options) })));
  const success = attempts.find((attempt) => attempt.status === 'fulfilled');
  if (!success) throw new Error(`No DNS provider returned a response for ${type}.`);
  return { type, answers: success.value.data.Answer || [], provider: success.value.provider };
}

async function lookupDomainRdap(domain) {
  const candidates = [...new Set([domain, registryDomain(domain)])];
  const attempts = await Promise.allSettled(candidates.map((candidate) => fetchJson(`https://rdap.org/domain/${encodeURIComponent(candidate)}`)));
  const successIndex = attempts.findIndex((attempt) => attempt.status === 'fulfilled');
  return successIndex === -1 ? { data: {}, queriedDomain: registryDomain(domain), available: false } : { data: attempts[successIndex].value, queriedDomain: candidates[successIndex], available: true };
}

async function lookupIp(ip) {
  const encoded = encodeURIComponent(ip);
  const sourceResults = await Promise.allSettled([
    fetchJson(`https://stat.ripe.net/data/network-info/data.json?resource=${encoded}`),
    fetchJson(`https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${encoded}`),
    fetchJson(`https://rdap.org/ip/${encoded}`),
    fetchJson(`https://ipwho.is/${encoded}`),
  ]);
  const [network, abuse, rdap, geo] = sourceResults;
  const networkData = fulfilled(network).data || {};
  const rdapData = fulfilled(rdap);
  const abuseData = fulfilled(abuse).data || {};
  const geoData = fulfilled(geo);
  const connection = geoData.connection || {};
  const sourceCount = sourceState(sourceResults);
  return {
    kind: 'IP address',
    metrics: [
      ['ADDRESS FAMILY', ip.includes(':') ? 'IPv6' : 'IPv4', 'Local validation'],
      ['ROUTED PREFIX', networkData.prefix || rdapData.handle || 'Unavailable', 'Routing / RDAP'],
      ['ORIGIN ASN', networkData.asns?.[0] ? `AS${networkData.asns[0]}` : connection.asn ? `AS${connection.asn}` : 'Unavailable', 'Routing / geolocation'],
      ['RISK CLASSIFICATION', 'Not assessed', 'Provider integration required'],
    ],
    details: [
      ['Input address', ip], ['Routed prefix', networkData.prefix || 'Unavailable'],
      ['Origin ASN(s)', networkData.asns?.map((asn) => `AS${asn}`).join(', ') || (connection.asn ? `AS${connection.asn}` : 'Unavailable')],
      ['Network operator', connection.org || connection.isp || rdapData.name || 'Unavailable'],
      ['ISP / domain', connection.isp || connection.domain || 'Unavailable'],
      ['Registry handle', rdapData.handle || 'Unavailable'], ['Network name', rdapData.name || rdapData.type || 'Unavailable'],
      ['Country', rdapData.country || 'Unavailable'], ['Abuse contact', abuseData.abuse_contacts?.join(', ') || 'Unavailable'],
      ['Geolocation', [geoData.city, geoData.region, geoData.country].filter(Boolean).join(', ') || 'Unavailable'],
      ['Coordinates', geoData.latitude && geoData.longitude ? `${geoData.latitude}, ${geoData.longitude}` : 'Unavailable'],
      ['Timezone', geoData.timezone?.id || geoData.timezone?.current_time || 'Unavailable'],
      ['Registry type', rdapData.type || 'Unavailable'], ['Last registry update', eventValue(rdapData.events, 'last changed') || 'Unavailable'],
      ['Available sources', `${sourceCount}/4 responded`], ['Sources', `${sources.ripe}; ${sources.rdap}; ${sources.geo}`],
    ],
    dns: null,
  };
}

async function lookupAsn(asn) {
  const number = asn.replace('AS', '');
  const sourceResults = await Promise.allSettled([
    fetchJson(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${number}`),
    fetchJson(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${number}`),
    fetchJson(`https://stat.ripe.net/data/routing-status/data.json?resource=AS${number}`),
  ]);
  const overview = fulfilled(sourceResults[0]).data || {};
  const prefixes = fulfilled(sourceResults[1]).data?.prefixes || [];
  const routing = fulfilled(sourceResults[2]).data || {};
  return {
    kind: 'Autonomous system',
    metrics: [
      ['AUTONOMOUS SYSTEM', asn, sources.ripe], ['ANNOUNCED', overview.announced ? 'Yes' : 'No', 'RIPEstat overview'],
      ['HOLDER', overview.holder || 'Unavailable', sources.ripe], ['RISK CLASSIFICATION', 'Not assessed', 'Provider integration required'],
    ],
    details: [
      ['ASN', asn], ['Holder', overview.holder || 'Unavailable'], ['Announced', overview.announced ? 'Yes' : 'No'],
      ['Announced prefixes', prefixes.length || 'Unavailable'], ['Sample prefixes', prefixes.slice(0, 5).map((item) => item.prefix || item).join(', ') || 'Unavailable'],
      ['Block status', overview.block?.resource || 'Unavailable'], ['Routing visibility', routing.visibility || routing.status || 'Unavailable'],
      ['Source availability', `${sourceState(sourceResults)}/3 RIPEstat datasets responded`], ['Source', sources.ripe],
    ],
    dns: null,
  };
}

async function lookupDomain(domain) {
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT'];
  const [recordResults, rdapResult] = await Promise.all([Promise.allSettled(types.map((type) => resolveDns(domain, type))), lookupDomainRdap(domain)]);
  const dns = types.map((type, index) => recordResults[index].status === 'fulfilled' ? recordResults[index].value : { type, answers: [], provider: 'No provider response' });
  const rdap = rdapResult.data;
  const status = rdap.status?.join(', ') || 'Unavailable';
  const nameservers = rdap.nameservers?.map((server) => server.ldhName || server.unicodeName).filter(Boolean).join(', ');
  return {
    kind: 'Domain name',
    metrics: [
      ['DOMAIN', domain, 'Local validation'], ['REGISTRY STATUS', status, sources.rdap],
      ['A RECORDS', String(dns.find((record) => record.type === 'A').answers.length), sources.dns],
      ['RISK CLASSIFICATION', 'Not assessed', 'Provider integration required'],
    ],
    details: [
      ['Lookup hostname', domain], ['Registry domain queried', rdapResult.queriedDomain], ['Registry handle', rdap.handle || 'Unavailable'], ['Status', status],
      ['Registrar', entityName(rdap.entities, 'registrar')], ['Registrant', 'Not displayed — registry personal data is intentionally minimized'],
      ['Registered', eventValue(rdap.events, 'registration') || 'Unavailable'], ['Last changed', eventValue(rdap.events, 'last changed') || 'Unavailable'],
      ['Expires', eventValue(rdap.events, 'expiration') || 'Unavailable'], ['Authoritative nameservers', nameservers || 'Unavailable'],
      ['DNSSEC delegation', clean(rdap.secureDNS?.delegation)], ['DNS record types available', `${dns.filter((record) => record.provider !== 'No provider response').length}/5 responded`],
      ['RDAP registry source', rdapResult.available ? 'Responded' : 'Unavailable for this registry domain'], ['Sources', `${sources.dns}; ${sources.rdap}`],
    ],
    dns,
  };
}

function setView(state) {
  emptyState.classList.toggle('hidden', state !== 'empty');
  loadingState.classList.toggle('hidden', state !== 'loading');
  results.classList.toggle('hidden', state !== 'results');
  errorState.classList.add('hidden');
}

function renderMetric(label, value, note) {
  const node = metricTemplate.content.cloneNode(true);
  node.querySelector('.eyebrow').textContent = label;
  node.querySelector('strong').textContent = value;
  node.querySelector('small').textContent = note;
  return node;
}

function renderBrief(query, brief) {
  document.querySelector('#resultQuery').textContent = query;
  document.querySelector('#resultMeta').textContent = `${brief.kind} · collected ${new Date().toLocaleString()} · public data sources`;
  const metrics = document.querySelector('#summaryGrid'); metrics.replaceChildren();
  brief.metrics.forEach((metric) => metrics.append(renderMetric(...metric)));
  const list = document.querySelector('#networkData'); list.replaceChildren();
  brief.details.forEach(([label, value]) => { const row = document.createElement('div'); row.innerHTML = `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`; list.append(row); });
  const dnsPanel = document.querySelector('#dnsPanel');
  dnsPanel.classList.toggle('hidden', !brief.dns);
  if (brief.dns) { const dnsData = document.querySelector('#dnsData'); dnsData.replaceChildren(); brief.dns.forEach(({ type, answers, provider }) => { const card = document.createElement('div'); card.className = 'dns-record'; card.innerHTML = `<b>${type} · ${answers.length} record${answers.length === 1 ? '' : 's'}</b><p>${answers.length ? answers.map((answer) => escapeHtml(answer.data)).join('<br>') : 'No public answer returned'}<br><em>${escapeHtml(provider)}</em></p>`; dnsData.append(card); }); }
}

function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[char]); }

function getHistory() { try { return JSON.parse(localStorage.getItem('sentinel-atlas-history') || '[]'); } catch { return []; } }
function renderHistory() { const history = getHistory(); historyCount.textContent = `${history.length} ${history.length === 1 ? 'entry' : 'entries'}`; historyList.replaceChildren(); if (!history.length) { historyList.innerHTML = '<p class="muted">No local lookups recorded in this session.</p>'; return; } history.forEach((entry) => { const row = document.createElement('div'); row.className = 'history-row'; row.innerHTML = `<div><b>${escapeHtml(entry.value)}</b><span> · ${escapeHtml(entry.type)}</span></div><span>${escapeHtml(entry.time)}</span>`; historyList.append(row); }); }
function saveHistory(item) { const history = getHistory().filter((entry) => entry.value !== item.value); history.unshift({ ...item, time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }); localStorage.setItem('sentinel-atlas-history', JSON.stringify(history.slice(0, 8))); renderHistory(); }

form.addEventListener('submit', async (event) => {
  event.preventDefault(); const parsed = classify(queryInput.value);
  if (parsed.error) { errorState.textContent = parsed.error; errorState.classList.remove('hidden'); results.classList.add('hidden'); emptyState.classList.add('hidden'); return; }
  setView('loading'); document.querySelector('#lookupButton').disabled = true;
  try { const brief = parsed.type === 'ip' ? await lookupIp(parsed.value) : parsed.type === 'domain' ? await lookupDomain(parsed.value) : await lookupAsn(parsed.value); renderBrief(parsed.value, brief); saveHistory(parsed); setView('results'); }
  catch (error) { errorState.textContent = `Unable to complete this live lookup. ${error.message} Check your connection or try again later.`; errorState.classList.remove('hidden'); setView('empty'); }
  finally { document.querySelector('#lookupButton').disabled = false; }
});

document.querySelectorAll('[data-example]').forEach((button) => button.addEventListener('click', () => { queryInput.value = button.dataset.example; queryInput.focus(); }));
document.querySelector('#clearHistory').addEventListener('click', () => { localStorage.removeItem('sentinel-atlas-history'); renderHistory(); });
document.querySelector('#copyBrief').addEventListener('click', async () => { const title = document.querySelector('#resultQuery').textContent; const details = [...document.querySelectorAll('#networkData div')].map((row) => `${row.querySelector('dt').textContent}: ${row.querySelector('dd').textContent}`).join('\n'); try { await navigator.clipboard.writeText(`Sentinel Atlas assessment: ${title}\n${details}\n\nVPN/proxy classification: Not assessed without an approved provider.`); document.querySelector('#copyBrief').textContent = 'Copied'; setTimeout(() => { document.querySelector('#copyBrief').textContent = 'Copy brief'; }, 1800); } catch { /* Clipboard access can be denied by the browser. */ } });
renderHistory();
