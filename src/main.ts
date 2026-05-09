import './style.css';
import { parseCertificate, type ParsedCertificate } from './smimea/certificateParser';
import { relativeCloudflareName, smimeaOwnerName, splitEmailAddress } from './smimea/emailHash';
import { generateSmimeaRecord, type MatchingType, type Selector, type Usage } from './smimea/smimeaRecord';
import { checkDns, type ResolverCheck } from './smimea/dnsCheck';
import { cloudflareCurl, cloudflareRecordBody, createCloudflareRecord, type CloudflareMode } from './smimea/cloudflareApi';

interface AppState { cert?: ParsedCertificate; fqdn?: string; cfName?: string; content?: string; apiJson?: string; dig?: string; }
const state: AppState = {};

const app = document.querySelector<HTMLDivElement>('#app')!;
app.innerHTML = `
<header class="hero"><div><p class="eyebrow">RFC 8162 · S/MIME Discovery</p><h1>SMIMEA DNS Record Generator</h1><p>Erzeuge lokal im Browser einen SMIMEA Record aus E-Mail-Adresse und S/MIME-Zertifikat. Optional kannst du den Record über Cloudflare anlegen und per DNS-over-HTTPS prüfen.</p></div><button id="theme" class="ghost">🌙/☀️</button></header>
<main class="grid">
<section class="card span"><h2>1 · E-Mail & Zertifikat</h2><div class="form-grid"><label>E-Mail-Adresse<input id="email" type="email" placeholder="dion@kitsos.net"></label><label>Manuelle DNS-Zone (optional)<input id="zone" placeholder="kitsos.net"></label><label>S/MIME-Zertifikat<input id="cert" type="file" accept=".pem,.crt,.cer,.der,.txt"></label></div><p class="hint">Alle Berechnungen laufen clientseitig. Zertifikat und E-Mail werden nicht an fremde Server gesendet, außer du startest Cloudflare oder DoH explizit.</p><div id="certWarnings"></div></section>
<section class="card"><h2>Zertifikat</h2><div id="certInfo" class="kv muted">Noch kein Zertifikat geladen.</div></section>
<section class="card"><h2>Status</h2><div id="cards" class="status-grid"></div></section>
<section class="card span"><h2>2 · SMIMEA Optionen</h2><p class="notice">Für S/MIME Discovery ist <b>3 0 0</b> empfohlen: das vollständige End-Entity-Zertifikat wird veröffentlicht, sodass Absender den Public Key direkt finden können.</p><div class="form-grid three"><label>Usage<select id="usage"><option value="3">3 = DANE-EE</option><option value="0">0 = PKIX-TA</option><option value="1">1 = PKIX-EE</option><option value="2">2 = DANE-TA</option></select></label><label>Selector<select id="selector"><option value="0">0 = Full certificate</option><option value="1">1 = SubjectPublicKeyInfo</option></select></label><label>Matching Type<select id="matching"><option value="0">0 = Full data / no hash</option><option value="1">1 = SHA-256</option><option value="2">2 = SHA-512</option></select></label></div><button id="generate" class="primary">SMIMEA generieren</button></section>
<section class="card span"><h2>3 · Output</h2><div class="outputs"><label>Vollständiger FQDN<textarea id="fqdn" readonly></textarea><button data-copy="fqdn">Copy FQDN</button></label><label>Cloudflare Name relativ zur Zone<textarea id="cfName" readonly></textarea><button data-copy="cfName">Copy Cloudflare Name</button></label><label>SMIMEA Content<textarea id="content" readonly></textarea><button data-copy="content">Copy Record Content</button></label><label>dig command<textarea id="dig" readonly></textarea><button data-copy="dig">Copy dig command</button></label><label>Cloudflare API JSON<textarea id="apiJson" readonly></textarea><button data-copy="apiJson">Copy Cloudflare API JSON</button></label></div></section>
<section class="card"><h2>4 · Create in Cloudflare</h2><p class="warn">Ein Cloudflare API Token im Browser ist sensibel. Nutze am besten ein eingeschränktes Token nur für diese Zone. Empfohlen: API Token statt Global API Key. Permissions: Zone:Read, DNS:Edit, optional Account:Read.</p><div class="form-grid"><label>API Token<input id="cfToken" type="password" autocomplete="off"></label><label>Account Name/ID (optional)<input id="cfAccount" placeholder="nur zur Dokumentation"></label><label>Zone Name<input id="cfZone" placeholder="kitsos.net"></label><label>Zone ID (optional)<input id="cfZoneId"></label><label>TTL<input id="ttl" type="number" min="60" value="300"></label><label>Modus<select id="mode"><option value="upsert">Upsert / create or update</option><option value="create">Create only</option><option value="recreate">Delete and recreate</option></select></label></div><label class="check"><input id="remember" type="checkbox"> Token lokal merken (localStorage) — unsicherer als Session</label><button id="cfRun" class="primary">Bei Cloudflare ausführen</button><pre id="cfStatus"></pre><details><summary>Manual Mode / curl</summary><pre id="curl"></pre><p>Falls der Browser CORS blockiert: öffne Cloudflare Dashboard → DNS → Records → Add record → Typ SMIMEA → Name und Content aus dieser App übernehmen.</p></details></section>
<section class="card"><h2>5 · DNSSEC & DoH Check</h2><button id="dnsRun" class="primary">DNS prüfen</button><div id="dnsStatus" class="resolver-grid"></div><p class="hint">Bei fehlendem Record: FQDN, Hash, Zone und Cloudflare Record-Typ prüfen, TTL/Propagation abwarten und DNSSEC aktivieren.</p></section>
</main><div id="toast" class="toast"></div>`;

const $ = <T extends HTMLElement>(id: string) => document.querySelector<T>(`#${id}`)!;
const email = $('email') as HTMLInputElement, zone = $('zone') as HTMLInputElement, cert = $('cert') as HTMLInputElement;
const usage = $('usage') as HTMLSelectElement, selector = $('selector') as HTMLSelectElement, matching = $('matching') as HTMLSelectElement;

function toast(msg: string) { const el = $('toast'); el.textContent = msg; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 1800); }
function setOutput(id: 'fqdn' | 'cfName' | 'content' | 'apiJson' | 'dig', value = '') { state[id] = value; ($(id) as HTMLTextAreaElement).value = value; }
function escapeHtml(s: string) { return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!)); }
function yesNo(value: boolean) { return value ? '✅ Ja' : '⚠️ Nein'; }

function renderStatus() {
  const certOk = Boolean(state.cert && state.cert.notAfter > new Date() && state.cert.notBefore < new Date());
  const mail = email.value.trim().toLowerCase();
  const mailOk = Boolean(state.cert?.emails.includes(mail));
  $('cards').innerHTML = [
    ['Zertifikat gültig', state.cert ? yesNo(certOk) : '–'], ['E-Mail in SAN', state.cert ? yesNo(mailOk) : '–'], ['SMIMEA generiert', state.content ? '✅ Ja' : '–'], ['Cloudflare API', $('cfStatus').textContent || '–'], ['DNSSEC Status', 'über AD-Flag im DoH Check'],
  ].map(([a,b]) => `<div class="status"><b>${a}</b><span>${escapeHtml(b)}</span></div>`).join('');
}

function renderCert() {
  if (!state.cert) return;
  const c = state.cert;
  $('certInfo').innerHTML = `<b>Subject</b><pre>${escapeHtml(c.subject)}</pre><b>Issuer</b><pre>${escapeHtml(c.issuer)}</pre><b>Serial</b><span>${escapeHtml(c.serialNumber)}</span><b>Gültig</b><span>${c.notBefore.toLocaleString()} – ${c.notAfter.toLocaleString()}</span><b>Public Key</b><span>${escapeHtml(c.publicKeyAlgorithm)}</span><b>Signatur</b><span>${escapeHtml(c.signatureAlgorithm)}</span><b>SAN RFC822Name</b><span>${escapeHtml(c.emails.join(', ') || 'Keine gefunden')}</span><b>Key Usage</b><span>${escapeHtml(c.keyUsage.join(', ') || '–')}</span><b>Extended Key Usage</b><span>${escapeHtml(c.extendedKeyUsage.join(', ') || '–')}</span><b>SHA-256</b><code>${c.sha256Fingerprint}</code><b>SHA-512</b><code>${c.sha512Fingerprint}</code>`;
  const mailWarn = email.value && !c.emails.includes(email.value.trim().toLowerCase()) ? ['Die eingegebene E-Mail-Adresse ist nicht als RFC822Name/SAN im Zertifikat enthalten.'] : [];
  $('certWarnings').innerHTML = [...c.warnings, ...mailWarn].map((w) => `<p class="warn">${escapeHtml(w)}</p>`).join('');
  renderStatus();
}

async function generate() {
  if (!state.cert) throw new Error('Bitte zuerst ein Zertifikat hochladen.');
  const fqdn = await smimeaOwnerName(email.value);
  const zoneName = zone.value.trim() || splitEmailAddress(email.value).domain;
  const cfName = relativeCloudflareName(fqdn, zoneName);
  const result = await generateSmimeaRecord(state.cert.der, state.cert.spki, { usage: Number(usage.value) as Usage, selector: Number(selector.value) as Selector, matchingType: Number(matching.value) as MatchingType });
  setOutput('fqdn', fqdn); setOutput('cfName', cfName); setOutput('content', result.content);
  setOutput('dig', `dig +dnssec ${fqdn} SMIMEA`);
  setOutput('apiJson', JSON.stringify(cloudflareRecordBody(fqdn, result.content, Number(($('ttl') as HTMLInputElement).value || 300)), null, 2));
  $('curl').textContent = cloudflareCurl('<CF_API_TOKEN>', ($('cfZoneId') as HTMLInputElement).value || '<ZONE_ID>', JSON.parse(state.apiJson!));
  renderStatus();
}

cert.addEventListener('change', async () => { try { const file = cert.files?.[0]; if (!file) return; state.cert = await parseCertificate(await file.arrayBuffer(), file.name); renderCert(); } catch (e) { toast(e instanceof Error ? e.message : 'Zertifikat konnte nicht gelesen werden.'); } });
email.addEventListener('input', renderCert);
$('generate').addEventListener('click', () => generate().catch((e) => toast(e.message)));
$('theme').addEventListener('click', () => document.documentElement.classList.toggle('light'));
document.querySelectorAll<HTMLButtonElement>('[data-copy]').forEach((button) => button.addEventListener('click', async () => { const id = button.dataset.copy!; await navigator.clipboard.writeText(($(id) as HTMLTextAreaElement).value); toast('Copied'); }));
$('remember').addEventListener('change', () => { const token = ($('cfToken') as HTMLInputElement).value; if (($('remember') as HTMLInputElement).checked && token) localStorage.setItem('cfToken', token); else localStorage.removeItem('cfToken'); });
($('cfToken') as HTMLInputElement).value = localStorage.getItem('cfToken') || '';
$('cfRun').addEventListener('click', async () => { try { if (!state.fqdn || !state.content) await generate(); const result = await createCloudflareRecord({ token: ($('cfToken') as HTMLInputElement).value, zoneName: ($('cfZone') as HTMLInputElement).value || zone.value || splitEmailAddress(email.value).domain, zoneId: ($('cfZoneId') as HTMLInputElement).value, ttl: Number(($('ttl') as HTMLInputElement).value || 300), mode: ($('mode') as HTMLSelectElement).value as CloudflareMode }, state.fqdn!, state.content!); $('cfStatus').textContent = result.message; $('curl').textContent = result.curl; renderStatus(); } catch (e) { toast(e instanceof Error ? e.message : 'Cloudflare fehlgeschlagen.'); } });
$('dnsRun').addEventListener('click', async () => { if (!state.fqdn || !state.content) return toast('Bitte zuerst SMIMEA generieren.'); $('dnsStatus').innerHTML = 'Prüfe…'; const results = await checkDns(state.fqdn, state.content); $('dnsStatus').innerHTML = results.map(renderResolver).join(''); });
function renderResolver(r: ResolverCheck) { return `<div class="resolver ${r.ok ? 'ok' : 'bad'}"><h3>${r.resolver}</h3><p>${escapeHtml(r.message)}</p><p>Status: ${r.status ?? '–'} · TTL: ${r.ttl ?? '–'} · AD: ${yesNo(r.ad)} · RRSIG: ${yesNo(r.hasRrsig)}</p>${!r.ad ? '<p class="warn">Record gefunden, aber DNSSEC-validierte Antwort nicht bestätigt.</p>' : ''}<pre>${escapeHtml(r.answers.join('\n') || 'Keine Antwort')}</pre></div>`; }
renderStatus();
