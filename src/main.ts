import './style.css';
import { parseCertificate, type ParsedCertificate } from './smimea/certificateParser';
import { relativeCloudflareName, smimeaOwnerName, splitEmailAddress } from './smimea/emailHash';
import { generateSmimeaRecord, parseSmimeaContent, type MatchingType, type Selector, type Usage } from './smimea/smimeaRecord';
import { certificateDerFromSmimeaAnswer, checkDns, type ResolverCheck } from './smimea/dnsCheck';
import { cloudflareCurl, cloudflareRecordBody, createCloudflareRecord, type CloudflareMode } from './smimea/cloudflareApi';

interface GeneratedRecord {
  email: string;
  fqdn: string;
  cfName: string;
  content: string;
  dig: string;
  apiJson: string;
}

interface AppState {
  cert?: ParsedCertificate;
  checkedCert?: ParsedCertificate;
  checkedCertDer?: Uint8Array;
  records: GeneratedRecord[];
}

const state: AppState = { records: [] };

const app = document.querySelector<HTMLDivElement>('#app')!;
app.innerHTML = `
<header class="app-header">
  <a class="brand" href="/generator" aria-label="SMIMEA Generator"><span class="brand-mark">S</span><span><b>SMIMEA</b><small>Generator & Check</small></span></a>
  <nav class="nav" aria-label="Hauptnavigation">
    <a href="/check" data-route-link="check">Record Check</a>
    <a href="/generator" data-route-link="generator">Generator</a>
    <a href="/publish" data-route-link="publish">Cloudflare</a>
  </nav>
</header>
<main>
  <section class="page" data-page="check" id="checkPage">
    <div class="page-head">
      <p class="kicker">Separate Check-Seite</p>
      <h1>Record prüfen und Zertifikat herunterladen</h1>
      <p class="lede">E-Mail-Adresse eingeben, SMIMEA Owner Name berechnen lassen und veröffentlichte Records per DNS-over-HTTPS prüfen.</p>
      <details><summary>Was wird geprüft?</summary><p>Die App fragt Cloudflare und Google ab, vergleicht optional erwarteten Content und dekodiert bei Full-Certificate-Records (<code>3 0 0</code>) das Zertifikat direkt aus DNS. Bei Hash-Records kann kein Zertifikat rekonstruiert werden.</p></details>
    </div>
    <div class="card primary-card">
      <div class="form-grid"><label>E-Mail-Adresse<input id="checkEmail" placeholder="<email-address>" autocomplete="off"></label><label>Manueller FQDN (optional)<input id="checkFqdn" placeholder="<hash>._smimecert.<mail-domain>"></label><label class="wide">Erwarteter SMIMEA Content (optional)<textarea id="checkContent" placeholder="3 0 0 ..."></textarea></label></div>
      <button id="dnsRun" class="primary">Record prüfen</button>
    </div>
    <div id="checkOwner" class="result muted">Noch kein Check ausgeführt.</div>
    <div id="dnsStatus" class="resolver-grid"></div>
    <section class="card"><h2>Zertifikat aus DNS</h2><div id="publishedCert" class="kv muted">Noch kein Zertifikat aus DNS gelesen.</div></section>
  </section>

  <section class="page" data-page="generator" id="generatorPage">
    <div class="page-head">
      <p class="kicker">Generator</p>
      <h1>Aus Zertifikat Records erzeugen</h1>
      <p class="lede">Minimaler Ablauf: Zertifikat hochladen, SAN-Adressen auswählen, Records erzeugen.</p>
      <details><summary>Hinweise zur Empfehlung 3 0 0</summary><p>Für S/MIME Discovery ist <code>3 0 0</code> praktisch, weil das vollständige End-Entity-Zertifikat im DNS veröffentlicht wird und Sender den Public Key direkt finden können.</p></details>
    </div>
    <div class="split">
      <section class="card"><p class="step">1</p><h2>Zertifikat hochladen</h2><div class="form-grid single"><label>S/MIME-Zertifikat<input id="cert" type="file" accept=".pem,.crt,.cer,.der,.txt"></label><label>DNS-Zone überschreiben (optional)<input id="zone" placeholder="<zone-name>"></label></div><div id="certWarnings"></div></section>
      <aside class="card"><h2>Status</h2><div id="cards" class="status-grid"></div></aside>
    </div>
    <section class="card"><p class="step">2</p><h2>SAN-Adressen auswählen</h2><div id="emailChoices" class="choice-list muted">Nach dem Upload erscheinen hier die gefundenen E-Mail-Adressen.</div></section>
    <section class="card"><p class="step">3</p><h2>Record-Format</h2><div class="form-grid three"><label>Usage<select id="usage"><option value="3">3 = DANE-EE</option><option value="0">0 = PKIX-TA</option><option value="1">1 = PKIX-EE</option><option value="2">2 = DANE-TA</option></select></label><label>Selector<select id="selector"><option value="0">0 = Full certificate</option><option value="1">1 = SubjectPublicKeyInfo</option></select></label><label>Matching Type<select id="matching"><option value="0">0 = Full data / no hash</option><option value="1">1 = SHA-256</option><option value="2">2 = SHA-512</option></select></label></div><button id="generate" class="primary">Records erzeugen</button></section>
    <section class="card"><h2>Output</h2><div id="outputs" class="outputs muted">Noch keine Records erzeugt.</div></section>
    <section class="card"><details><summary>Zertifikatsdetails anzeigen</summary><div id="certInfo" class="kv muted">Noch kein Zertifikat geladen.</div></details></section>
  </section>

  <section class="page" data-page="publish" id="publishPage">
    <div class="page-head">
      <p class="kicker">Cloudflare</p>
      <h1>Records veröffentlichen</h1>
      <p class="lede">Erzeuge zuerst Records im Generator. Danach kannst du sie via Cloudflare Pages Function veröffentlichen oder den curl-Fallback nutzen.</p>
      <details><summary>Warum gibt es einen Proxy?</summary><p>Direkte Browser-Aufrufe an die Cloudflare API können durch CORS blockiert werden. Auf Cloudflare Pages nutzt diese App deshalb die Same-Origin Function <code>/api/cloudflare-dns</code>. Tokens werden nicht hardcodiert und nur für den aktuellen Request verwendet.</p></details>
    </div>
    <section class="card"><div class="form-grid three"><label>API Token<input id="cfToken" type="password" autocomplete="off"></label><label>Zone Name<input id="cfZone" placeholder="<zone-name>"></label><label>Zone ID (optional)<input id="cfZoneId"></label><label>TTL<input id="ttl" type="number" min="60" value="300"></label><label>Modus<select id="mode"><option value="upsert">Upsert / create or update</option><option value="create">Create only</option><option value="recreate">Delete and recreate</option></select></label><label>Transport<select id="cfTransport"><option value="proxy">Cloudflare Pages Function</option><option value="direct">Direkt aus dem Browser (CORS-riskant)</option></select></label></div><label class="check"><input id="remember" type="checkbox"> Token lokal merken (localStorage)</label><button id="cfRun" class="primary">Bei Cloudflare ausführen</button><pre id="cfStatus"></pre><details open><summary>curl-Fallback und manuelle Anlage</summary><pre id="curl">Noch keine Records erzeugt.</pre><p>Die API-Notiz wird automatisch als <code>SMIMEA for &lt;selected-email&gt;</code> gesetzt.</p></details></section>
  </section>
</main><div id="toast" class="toast"></div>`;

const $ = <T extends HTMLElement>(id: string) => document.querySelector<T>(`#${id}`)!;
const zone = $('zone') as HTMLInputElement;
const cert = $('cert') as HTMLInputElement;
const usage = $('usage') as HTMLSelectElement;
const selector = $('selector') as HTMLSelectElement;
const matching = $('matching') as HTMLSelectElement;

function toast(msg: string) { const el = $('toast'); el.textContent = msg; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 2200); }
function escapeHtml(s: string) { return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!)); }
function yesNo(value: boolean) { return value ? 'Ja' : 'Nein'; }
function selectedEmails(): string[] { return [...document.querySelectorAll<HTMLInputElement>('[name="sanEmail"]:checked')].map((input) => input.value); }
function defaultZoneFor(email: string): string { return zone.value.trim() || splitEmailAddress(email).domain; }

type Route = 'check' | 'generator' | 'publish';
const routes: Route[] = ['check', 'generator', 'publish'];

function route(): Route {
  const segment = location.pathname.replace(/\/+$/, '').split('/').filter(Boolean).pop();
  if (segment && routes.includes(segment as Route)) return segment as Route;
  return 'generator';
}

function routePath(target: Route): string { return `/${target}`; }

function navigate(target: Route) {
  history.pushState({}, '', routePath(target));
  renderRoute();
}

function renderRoute() {
  const active = route();
  document.querySelectorAll<HTMLElement>('[data-page]').forEach((page) => page.hidden = page.dataset.page !== active);
  document.querySelectorAll<HTMLAnchorElement>('[data-route-link]').forEach((link) => link.classList.toggle('active', link.dataset.routeLink === active));
}

function certDetails(c: ParsedCertificate): string {
  return `<b>Subject</b><pre>${escapeHtml(c.subject)}</pre><b>Issuer</b><pre>${escapeHtml(c.issuer)}</pre><b>Serial</b><span>${escapeHtml(c.serialNumber)}</span><b>Gültig</b><span>${c.notBefore.toLocaleString()} – ${c.notAfter.toLocaleString()}</span><b>Public Key</b><span>${escapeHtml(c.publicKeyAlgorithm)}</span><b>Signatur</b><span>${escapeHtml(c.signatureAlgorithm)}</span><b>SAN RFC822Name</b><span>${escapeHtml(c.emails.join(', ') || 'Keine gefunden')}</span><b>Key Usage</b><span>${escapeHtml(c.keyUsage.join(', ') || '–')}</span><b>Extended Key Usage</b><span>${escapeHtml(c.extendedKeyUsage.join(', ') || '–')}</span><b>SHA-256</b><code>${c.sha256Fingerprint}</code><b>SHA-512</b><code>${c.sha512Fingerprint}</code>`;
}

function renderStatus() {
  const certOk = Boolean(state.cert && state.cert.notAfter > new Date() && state.cert.notBefore < new Date());
  $('cards').innerHTML = [
    ['Zertifikat', state.cert ? 'geladen' : 'offen'],
    ['Zeitlich gültig', state.cert ? yesNo(certOk) : '–'],
    ['SAN-Adressen', state.cert ? String(state.cert.emails.length) : '–'],
    ['Ausgewählt', String(selectedEmails().length)],
    ['Records', state.records.length ? String(state.records.length) : '–'],
    ['DNS-Zertifikat', state.checkedCert ? 'gelesen' : '–'],
  ].map(([a,b]) => `<div class="status"><span>${escapeHtml(b)}</span><small>${escapeHtml(a)}</small></div>`).join('');
}

function renderCert() {
  if (!state.cert) return;
  const c = state.cert;
  $('certInfo').innerHTML = certDetails(c);
  $('certWarnings').innerHTML = [...c.warnings, ...(c.emails.length ? [] : ['Keine RFC822Name/SAN-E-Mail-Adresse im Zertifikat gefunden.'])].map((w) => `<p class="warn">${escapeHtml(w)}</p>`).join('');
  $('emailChoices').innerHTML = c.emails.length ? c.emails.map((mail) => `<label class="check"><input name="sanEmail" type="checkbox" value="${escapeHtml(mail)}" checked> ${escapeHtml(mail)}</label>`).join('') : '<p class="warn">Keine auswählbaren SAN-E-Mail-Adressen gefunden.</p>';
  document.querySelectorAll<HTMLInputElement>('[name="sanEmail"]').forEach((input) => input.addEventListener('change', renderStatus));
  renderStatus();
}

async function buildRecord(email: string): Promise<GeneratedRecord> {
  const fqdn = await smimeaOwnerName(email);
  const cfName = relativeCloudflareName(fqdn, defaultZoneFor(email));
  const result = await generateSmimeaRecord(state.cert!.der, state.cert!.spki, { usage: Number(usage.value) as Usage, selector: Number(selector.value) as Selector, matchingType: Number(matching.value) as MatchingType });
  const body = cloudflareRecordBody(fqdn, result.content, Number(($('ttl') as HTMLInputElement).value || 300), email);
  return { email, fqdn, cfName, content: result.content, dig: `dig +dnssec ${fqdn} SMIMEA`, apiJson: JSON.stringify(body, null, 2) };
}

async function generate() {
  if (!state.cert) throw new Error('Bitte zuerst ein Zertifikat hochladen.');
  const emails = selectedEmails();
  if (!emails.length) throw new Error('Bitte mindestens eine SAN-E-Mail-Adresse auswählen.');
  state.records = await Promise.all(emails.map(buildRecord));
  renderOutputs();
  renderCurlCommands();
  renderStatus();
}

function recordBlock(record: GeneratedRecord, index: number): string {
  return `<details class="record" open><summary>${escapeHtml(record.email)}</summary><label>FQDN<textarea id="fqdn-${index}" readonly>${escapeHtml(record.fqdn)}</textarea><button data-copy="fqdn-${index}">Copy</button></label><label>Cloudflare Name<textarea id="cfName-${index}" readonly>${escapeHtml(record.cfName)}</textarea><button data-copy="cfName-${index}">Copy</button></label><label>SMIMEA Content<textarea id="content-${index}" readonly>${escapeHtml(record.content)}</textarea><button data-copy="content-${index}">Copy</button></label><details><summary>dig und Cloudflare JSON</summary><label>dig command<textarea id="dig-${index}" readonly>${escapeHtml(record.dig)}</textarea><button data-copy="dig-${index}">Copy</button></label><label>Cloudflare API JSON<textarea id="apiJson-${index}" readonly>${escapeHtml(record.apiJson)}</textarea><button data-copy="apiJson-${index}">Copy</button></label></details></details>`;
}

function renderOutputs() {
  $('outputs').classList.remove('muted');
  $('outputs').innerHTML = state.records.map(recordBlock).join('');
  bindCopyButtons();
}

function renderCurlCommands() {
  if (!state.records.length) {
    $('curl').textContent = 'Noch keine Records erzeugt.';
    return;
  }
  const zoneId = ($('cfZoneId') as HTMLInputElement).value.trim() || '<ZONE_ID>';
  $('curl').textContent = state.records.map((record) => `# ${record.email}\n${cloudflareCurl('<CF_API_TOKEN>', zoneId, JSON.parse(record.apiJson))}`).join('\n\n');
}

function bindCopyButtons() {
  document.querySelectorAll<HTMLButtonElement>('[data-copy]').forEach((button) => button.addEventListener('click', async () => {
    const id = button.dataset.copy!;
    await navigator.clipboard.writeText((document.getElementById(id) as HTMLTextAreaElement).value);
    toast('Copied');
  }));
}

function downloadBytes(bytes: Uint8Array, filename: string) {
  const url = URL.createObjectURL(new Blob([bytes.slice().buffer as ArrayBuffer], { type: 'application/pkix-cert' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

async function checkRecordByEmailOrFqdn() {
  const email = ($('checkEmail') as HTMLInputElement).value.trim();
  const manualFqdn = ($('checkFqdn') as HTMLInputElement).value.trim();
  const manualContent = ($('checkContent') as HTMLTextAreaElement).value.trim();
  const fqdn = manualFqdn || (email ? await smimeaOwnerName(email) : '');
  if (!fqdn) throw new Error('Bitte E-Mail-Adresse oder FQDN eintragen.');

  $('checkOwner').classList.remove('muted');
  $('checkOwner').innerHTML = `<b>Owner Name</b><pre>${escapeHtml(fqdn)}</pre>${email ? `<b>dig</b><pre>dig +dnssec ${escapeHtml(fqdn)} SMIMEA</pre>` : ''}`;
  $('dnsStatus').innerHTML = 'Prüfe…';
  $('publishedCert').classList.add('muted');
  $('publishedCert').textContent = 'Noch kein Zertifikat aus DNS gelesen.';
  state.checkedCert = undefined;
  state.checkedCertDer = undefined;

  const results = await checkDns(fqdn, manualContent);
  $('dnsStatus').innerHTML = `<section class="resolver"><h3>${escapeHtml(email || 'Manueller FQDN')} · ${escapeHtml(fqdn)}</h3>${results.map(renderResolver).join('')}</section>`;

  const firstAnswer = results.flatMap((result) => result.answers).find(Boolean);
  if (!firstAnswer) {
    $('publishedCert').innerHTML = '<p class="warn">Kein SMIMEA Record gefunden; deshalb kann kein Zertifikat aus DNS angezeigt werden.</p>';
    return;
  }

  const parsed = parseSmimeaContent(firstAnswer);
  const der = certificateDerFromSmimeaAnswer(firstAnswer);
  if (!der || !parsed) {
    $('publishedCert').innerHTML = '<p class="warn">Der veröffentlichte Record enthält nicht das vollständige Zertifikat. Download ist nur für Selector 0 und Matching Type 0 möglich, typischerweise <code>3 0 0</code>.</p>';
    return;
  }

  try {
    state.checkedCertDer = der.slice();
    state.checkedCert = await parseCertificate(state.checkedCertDer.buffer as ArrayBuffer, 'dns.der');
    $('publishedCert').classList.remove('muted');
    $('publishedCert').innerHTML = `<div class="download-row"><div><b>Record</b><pre>${escapeHtml(firstAnswer)}</pre></div><button id="downloadDnsCert" class="secondary">Zertifikat herunterladen (.der)</button></div><b>Hinweis</b><span>Aus DNS gelesen: Usage ${parsed.usage}, Selector ${parsed.selector}, Matching Type ${parsed.matchingType}</span>${certDetails(state.checkedCert)}`;
    $('downloadDnsCert').addEventListener('click', () => downloadBytes(state.checkedCertDer!, 'smimea-certificate.der'));
  } catch (error) {
    $('publishedCert').innerHTML = `<p class="warn">Record gefunden, aber Zertifikat konnte nicht gelesen werden: ${escapeHtml(error instanceof Error ? error.message : 'Unbekannter Fehler')}</p>`;
  } finally {
    renderStatus();
  }
}

cert.addEventListener('change', async () => {
  try {
    const file = cert.files?.[0];
    if (!file) return;
    state.cert = await parseCertificate(await file.arrayBuffer(), file.name);
    state.records = [];
    $('outputs').innerHTML = 'Noch keine Records erzeugt.';
    renderCert();
  } catch (e) {
    toast(e instanceof Error ? e.message : 'Zertifikat konnte nicht gelesen werden.');
  }
});

$('generate').addEventListener('click', () => generate().catch((e) => toast(e.message)));
$('remember').addEventListener('change', () => { const token = ($('cfToken') as HTMLInputElement).value; if (($('remember') as HTMLInputElement).checked && token) localStorage.setItem('cfToken', token); else localStorage.removeItem('cfToken'); });
($('cfToken') as HTMLInputElement).value = localStorage.getItem('cfToken') || '';

$('cfRun').addEventListener('click', async () => {
  try {
    if (!state.records.length) await generate();
    renderCurlCommands();
    const transport = ($('cfTransport') as HTMLSelectElement).value as 'proxy' | 'direct';
    $('cfStatus').textContent = transport === 'proxy' ? 'Cloudflare Pages Function wird ausgeführt…' : 'Direkte Cloudflare Browser-API wird ausgeführt…';
    const results = [];
    for (const record of state.records) {
      const result = await createCloudflareRecord({ token: ($('cfToken') as HTMLInputElement).value, zoneName: ($('cfZone') as HTMLInputElement).value || defaultZoneFor(record.email), zoneId: ($('cfZoneId') as HTMLInputElement).value, ttl: Number(($('ttl') as HTMLInputElement).value || 300), mode: ($('mode') as HTMLSelectElement).value as CloudflareMode, transport }, record.fqdn, record.content, record.email);
      results.push(`${record.email}: ${result.message}`);
      if (result.curl) $('curl').textContent = `${$('curl').textContent}\n\n# Fallback for ${record.email}\n${result.curl}`;
    }
    $('cfStatus').textContent = results.join('\n');
    renderStatus();
  } catch (e) {
    toast(e instanceof Error ? e.message : 'Cloudflare fehlgeschlagen.');
  }
});

$('dnsRun').addEventListener('click', () => checkRecordByEmailOrFqdn().catch((e) => toast(e.message)));
document.querySelectorAll<HTMLAnchorElement>('[data-route-link]').forEach((link) => link.addEventListener('click', (event) => {
  event.preventDefault();
  navigate(link.dataset.routeLink as Route);
}));
document.querySelector<HTMLAnchorElement>('.brand')?.addEventListener('click', (event) => {
  event.preventDefault();
  navigate('generator');
});
window.addEventListener('popstate', renderRoute);

function renderResolver(r: ResolverCheck) { return `<div class="resolver ${r.ok ? 'ok' : 'bad'}"><h3>${r.resolver}</h3><p>${escapeHtml(r.message)}</p><p>Status: ${r.status ?? '–'} · TTL: ${r.ttl ?? '–'} · AD: ${yesNo(r.ad)} · RRSIG: ${yesNo(r.hasRrsig)}</p>${!r.ad && r.answers.length ? '<p class="warn">Record gefunden, aber DNSSEC-validierte Antwort nicht bestätigt.</p>' : ''}<pre>${escapeHtml(r.answers.join('\n') || 'Keine Antwort')}</pre></div>`; }

renderRoute();
renderStatus();
