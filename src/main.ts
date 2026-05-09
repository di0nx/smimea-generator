import './style.css';
import { parseCertificate, type ParsedCertificate } from './smimea/certificateParser';
import { relativeCloudflareName, smimeaOwnerName, splitEmailAddress } from './smimea/emailHash';
import { generateSmimeaRecord, type MatchingType, type Selector, type Usage } from './smimea/smimeaRecord';
import { checkDns, type ResolverCheck } from './smimea/dnsCheck';
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
  records: GeneratedRecord[];
}

const state: AppState = { records: [] };

const app = document.querySelector<HTMLDivElement>('#app')!;
app.innerHTML = `
<header class="hero"><div><p class="eyebrow">RFC 8162 · S/MIME Discovery</p><h1>SMIMEA DNS Record Generator</h1><p>Einfacher Ablauf: Zertifikat hochladen, SAN-E-Mail-Adressen auswählen, Records erzeugen oder bereits veröffentlichte Records prüfen. Alles läuft lokal im Browser; nur Cloudflare/API und DNS-Checks senden die dafür nötigen Record-Daten an die gewählten Dienste.</p></div><button id="theme" class="ghost">🌙/☀️</button></header>
<main class="grid">
<section class="card span"><h2>1 · Zertifikat hochladen</h2><div class="form-grid"><label>S/MIME-Zertifikat<input id="cert" type="file" accept=".pem,.crt,.cer,.der,.txt"></label><label>Manuelle DNS-Zone (optional)<input id="zone" placeholder="example.org"></label></div><p class="hint">Die App liest die RFC822Name/SAN-E-Mail-Adressen aus dem Zertifikat. Wähle eine oder mehrere Adressen aus, für die SMIMEA Records erstellt oder geprüft werden sollen.</p><div id="certWarnings"></div></section>
<section class="card"><h2>Zertifikat</h2><div id="certInfo" class="kv muted">Noch kein Zertifikat geladen.</div></section>
<section class="card"><h2>Status</h2><div id="cards" class="status-grid"></div></section>
<section class="card span"><h2>2 · E-Mail-Adressen aus SAN auswählen</h2><div id="emailChoices" class="choice-list muted">Nach dem Upload erscheinen hier die im Zertifikat gefundenen E-Mail-Adressen.</div></section>
<section class="card span"><h2>3 · SMIMEA Records erzeugen</h2><p class="notice">Für S/MIME Discovery ist <b>3 0 0</b> empfohlen: das vollständige End-Entity-Zertifikat wird veröffentlicht, sodass Absender den Public Key direkt finden können.</p><div class="form-grid three"><label>Usage<select id="usage"><option value="3">3 = DANE-EE</option><option value="0">0 = PKIX-TA</option><option value="1">1 = PKIX-EE</option><option value="2">2 = DANE-TA</option></select></label><label>Selector<select id="selector"><option value="0">0 = Full certificate</option><option value="1">1 = SubjectPublicKeyInfo</option></select></label><label>Matching Type<select id="matching"><option value="0">0 = Full data / no hash</option><option value="1">1 = SHA-256</option><option value="2">2 = SHA-512</option></select></label></div><button id="generate" class="primary">Records für ausgewählte Adressen erzeugen</button></section>
<section class="card span"><h2>4 · Output</h2><div id="outputs" class="outputs muted">Noch keine Records erzeugt.</div></section>
<section class="card"><h2>5 · Optional: in Cloudflare erstellen</h2><p class="warn">Ein Cloudflare API Token im Browser ist sensibel. Nutze ein eingeschränktes API Token nur für die betroffene Zone. Permissions: Zone:Read und DNS:Edit.</p><div class="form-grid"><label>API Token<input id="cfToken" type="password" autocomplete="off"></label><label>Zone Name<input id="cfZone" placeholder="example.org"></label><label>Zone ID (optional)<input id="cfZoneId"></label><label>TTL<input id="ttl" type="number" min="60" value="300"></label><label>Modus<select id="mode"><option value="upsert">Upsert / create or update</option><option value="create">Create only</option><option value="recreate">Delete and recreate</option></select></label></div><label class="check"><input id="remember" type="checkbox"> Token lokal merken (localStorage) — unsicherer als Session</label><button id="cfRun" class="primary">Ausgewählte Records bei Cloudflare ausführen</button><pre id="cfStatus"></pre><details><summary>Manual Mode / curl</summary><pre id="curl"></pre><p>Falls der Browser CORS blockiert: Cloudflare Dashboard → DNS → Records → Add record → Typ SMIMEA → Name und Content aus dieser App übernehmen.</p></details></section>
<section class="card"><h2>6 · Check-Modus für bestehende Records</h2><p class="hint">Nutze diesen Modus, wenn der Record bereits erstellt wurde. Mit hochgeladenem Zertifikat werden die erwarteten Werte aus den ausgewählten SAN-Adressen geprüft. Ohne Zertifikat kannst du FQDN und erwarteten Content manuell eintragen.</p><div class="form-grid"><label>Manueller FQDN (optional)<input id="checkFqdn" placeholder="<hash>._smimecert.example.org"></label><label>Erwarteter SMIMEA Content (optional)<textarea id="checkContent" placeholder="3 0 0 ..."></textarea></label></div><button id="dnsRun" class="primary">DNS prüfen</button><div id="dnsStatus" class="resolver-grid"></div><p class="hint">Bei fehlendem Record: FQDN, Hash, Zone und Record-Typ prüfen, TTL/Propagation abwarten und DNSSEC aktivieren.</p></section>
</main><div id="toast" class="toast"></div>`;

const $ = <T extends HTMLElement>(id: string) => document.querySelector<T>(`#${id}`)!;
const zone = $('zone') as HTMLInputElement;
const cert = $('cert') as HTMLInputElement;
const usage = $('usage') as HTMLSelectElement;
const selector = $('selector') as HTMLSelectElement;
const matching = $('matching') as HTMLSelectElement;

function toast(msg: string) { const el = $('toast'); el.textContent = msg; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 1800); }
function escapeHtml(s: string) { return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!)); }
function yesNo(value: boolean) { return value ? '✅ Ja' : '⚠️ Nein'; }
function selectedEmails(): string[] { return [...document.querySelectorAll<HTMLInputElement>('[name="sanEmail"]:checked')].map((input) => input.value); }
function defaultZoneFor(email: string): string { return zone.value.trim() || splitEmailAddress(email).domain; }

function renderStatus() {
  const certOk = Boolean(state.cert && state.cert.notAfter > new Date() && state.cert.notBefore < new Date());
  $('cards').innerHTML = [
    ['Zertifikat geladen', state.cert ? '✅ Ja' : '–'],
    ['Zertifikat zeitlich gültig', state.cert ? yesNo(certOk) : '–'],
    ['SAN E-Mail-Adressen', state.cert ? String(state.cert.emails.length) : '–'],
    ['Ausgewählt', String(selectedEmails().length)],
    ['Records erzeugt', state.records.length ? `✅ ${state.records.length}` : '–'],
  ].map(([a,b]) => `<div class="status"><b>${a}</b><span>${escapeHtml(b)}</span></div>`).join('');
}

function renderCert() {
  if (!state.cert) return;
  const c = state.cert;
  $('certInfo').innerHTML = `<b>Subject</b><pre>${escapeHtml(c.subject)}</pre><b>Issuer</b><pre>${escapeHtml(c.issuer)}</pre><b>Serial</b><span>${escapeHtml(c.serialNumber)}</span><b>Gültig</b><span>${c.notBefore.toLocaleString()} – ${c.notAfter.toLocaleString()}</span><b>Public Key</b><span>${escapeHtml(c.publicKeyAlgorithm)}</span><b>Signatur</b><span>${escapeHtml(c.signatureAlgorithm)}</span><b>SAN RFC822Name</b><span>${escapeHtml(c.emails.join(', ') || 'Keine gefunden')}</span><b>Key Usage</b><span>${escapeHtml(c.keyUsage.join(', ') || '–')}</span><b>Extended Key Usage</b><span>${escapeHtml(c.extendedKeyUsage.join(', ') || '–')}</span><b>SHA-256</b><code>${c.sha256Fingerprint}</code><b>SHA-512</b><code>${c.sha512Fingerprint}</code>`;
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
  const first = state.records[0];
  $('curl').textContent = cloudflareCurl('<CF_API_TOKEN>', ($('cfZoneId') as HTMLInputElement).value || '<ZONE_ID>', JSON.parse(first.apiJson));
  renderStatus();
}

function recordBlock(record: GeneratedRecord, index: number): string {
  return `<details class="record" open><summary>${escapeHtml(record.email)}</summary><label>Vollständiger FQDN<textarea id="fqdn-${index}" readonly>${escapeHtml(record.fqdn)}</textarea><button data-copy="fqdn-${index}">Copy FQDN</button></label><label>Cloudflare Name relativ zur Zone<textarea id="cfName-${index}" readonly>${escapeHtml(record.cfName)}</textarea><button data-copy="cfName-${index}">Copy Name</button></label><label>SMIMEA Content<textarea id="content-${index}" readonly>${escapeHtml(record.content)}</textarea><button data-copy="content-${index}">Copy Content</button></label><label>dig command<textarea id="dig-${index}" readonly>${escapeHtml(record.dig)}</textarea><button data-copy="dig-${index}">Copy dig</button></label><label>Cloudflare API JSON<textarea id="apiJson-${index}" readonly>${escapeHtml(record.apiJson)}</textarea><button data-copy="apiJson-${index}">Copy JSON</button></label></details>`;
}

function renderOutputs() {
  $('outputs').classList.remove('muted');
  $('outputs').innerHTML = state.records.map(recordBlock).join('');
  bindCopyButtons();
}

function bindCopyButtons() {
  document.querySelectorAll<HTMLButtonElement>('[data-copy]').forEach((button) => button.addEventListener('click', async () => {
    const id = button.dataset.copy!;
    await navigator.clipboard.writeText((document.getElementById(id) as HTMLTextAreaElement).value);
    toast('Copied');
  }));
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
$('theme').addEventListener('click', () => document.documentElement.classList.toggle('light'));
$('remember').addEventListener('change', () => { const token = ($('cfToken') as HTMLInputElement).value; if (($('remember') as HTMLInputElement).checked && token) localStorage.setItem('cfToken', token); else localStorage.removeItem('cfToken'); });
($('cfToken') as HTMLInputElement).value = localStorage.getItem('cfToken') || '';

$('cfRun').addEventListener('click', async () => {
  try {
    if (!state.records.length) await generate();
    $('cfStatus').textContent = 'Cloudflare wird ausgeführt…';
    const results = [];
    for (const record of state.records) {
      const result = await createCloudflareRecord({ token: ($('cfToken') as HTMLInputElement).value, zoneName: ($('cfZone') as HTMLInputElement).value || defaultZoneFor(record.email), zoneId: ($('cfZoneId') as HTMLInputElement).value, ttl: Number(($('ttl') as HTMLInputElement).value || 300), mode: ($('mode') as HTMLSelectElement).value as CloudflareMode }, record.fqdn, record.content, record.email);
      results.push(`${record.email}: ${result.message}`);
      $('curl').textContent = result.curl;
    }
    $('cfStatus').textContent = results.join('\n');
    renderStatus();
  } catch (e) {
    toast(e instanceof Error ? e.message : 'Cloudflare fehlgeschlagen.');
  }
});

$('dnsRun').addEventListener('click', async () => {
  const manualFqdn = ($('checkFqdn') as HTMLInputElement).value.trim();
  const manualContent = ($('checkContent') as HTMLTextAreaElement).value.trim();
  const checks = manualFqdn ? [{ email: 'Manuell', fqdn: manualFqdn, content: manualContent }] : state.records;
  if (!checks.length) return toast('Bitte erst Records erzeugen oder manuelle Check-Daten eintragen.');
  $('dnsStatus').innerHTML = 'Prüfe…';
  const all = await Promise.all(checks.map(async (record) => ({ record, results: await checkDns(record.fqdn, record.content) })));
  $('dnsStatus').innerHTML = all.map(({ record, results }) => `<section class="resolver"><h3>${escapeHtml(record.email)} · ${escapeHtml(record.fqdn)}</h3>${results.map(renderResolver).join('')}</section>`).join('');
});

function renderResolver(r: ResolverCheck) { return `<div class="resolver ${r.ok ? 'ok' : 'bad'}"><h3>${r.resolver}</h3><p>${escapeHtml(r.message)}</p><p>Status: ${r.status ?? '–'} · TTL: ${r.ttl ?? '–'} · AD: ${yesNo(r.ad)} · RRSIG: ${yesNo(r.hasRrsig)}</p>${!r.ad ? '<p class="warn">Record gefunden, aber DNSSEC-validierte Antwort nicht bestätigt.</p>' : ''}<pre>${escapeHtml(r.answers.join('\n') || 'Keine Antwort')}</pre></div>`; }
renderStatus();
