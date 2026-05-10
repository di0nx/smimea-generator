export type CloudflareMode = 'create' | 'upsert' | 'recreate';
export type CloudflareTransport = 'proxy' | 'direct';
export interface CloudflareConfig { token: string; zoneName: string; zoneId?: string; ttl: number; mode: CloudflareMode; transport?: CloudflareTransport }
export interface CloudflareResult { ok: boolean; message: string; curl: string; response?: unknown }

const API = 'https://api.cloudflare.com/client/v4';
const PROXY = '/api/cloudflare-dns';

interface CloudflareEnvelope<T = unknown> { success?: boolean; errors?: unknown[]; result?: T }

function headers(token: string): HeadersInit { return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }; }
function mask(message: string, token: string): string { return token ? message.split(token).join(`${token.slice(0, 4)}…${token.slice(-4)}`) : message; }

export function cloudflareRecordBody(fqdn: string, content: string, ttl: number, email?: string) {
  const [usage, selector, matching_type, ...hexParts] = content.trim().split(/\s+/);
  const certificate = hexParts.join('');
  return {
    type: 'SMIMEA',
    name: fqdn,
    content,
    ttl,
    data: { usage: Number(usage), selector: Number(selector), matching_type: Number(matching_type), certificate },
    ...(email ? { comment: `SMIMEA for ${email}` } : {}),
  };
}

export function cloudflareCurl(tokenPlaceholder: string, zoneId: string, body: object, method = 'POST', recordId = ''): string {
  const url = `${API}/zones/${zoneId || '<ZONE_ID>'}/dns_records${recordId ? `/${recordId}` : ''}`;
  return `curl -X ${method} "${url}" \\\n  -H "Authorization: Bearer ${tokenPlaceholder}" \\\n  -H "Content-Type: application/json" \\\n  --data '${JSON.stringify(body)}'`;
}

async function cfFetch<T = unknown>(path: string, token: string, init: RequestInit = {}, transport: CloudflareTransport = 'proxy'): Promise<CloudflareEnvelope<T>> {
  const method = init.method ?? 'GET';
  const body = typeof init.body === 'string' ? init.body : init.body ? String(init.body) : undefined;
  const requestInit: RequestInit = { method, headers: headers(token), body };
  const response = transport === 'direct'
    ? await fetch(`${API}${path}`, requestInit)
    : await fetch(PROXY, { method: 'POST', headers: headers(token), body: JSON.stringify({ path, method, body }) });
  const json = await response.json().catch(() => ({})) as CloudflareEnvelope;
  if (!response.ok || json.success === false) {
    if (transport === 'proxy' && response.status === 404) throw new Error('Cloudflare Pages Function /api/cloudflare-dns nicht gefunden. Auf Cloudflare Pages mit functions/ deployen oder curl nutzen.');
    throw new Error(JSON.stringify(json.errors?.length ? json.errors : json));
  }
  return json as CloudflareEnvelope<T>;
}

export async function createCloudflareRecord(config: CloudflareConfig, fqdn: string, content: string, email?: string): Promise<CloudflareResult> {
  const body = cloudflareRecordBody(fqdn, content, config.ttl, email);
  const curl = cloudflareCurl('<CF_API_TOKEN>', config.zoneId || '<ZONE_ID>', body);
  const transport = config.transport ?? 'proxy';
  try {
    if (!config.token) throw new Error('Bitte Cloudflare API Token eintragen.');
    let zoneId = config.zoneId;
    if (!zoneId) {
      if (!config.zoneName) throw new Error('Bitte Zone Name oder Zone ID eintragen.');
      const zones = await cfFetch<{ id: string }[]>(`/zones?name=${encodeURIComponent(config.zoneName)}`, config.token, {}, transport);
      if (!zones.result?.length) throw new Error('Keine Zone gefunden.');
      if (zones.result.length > 1) throw new Error('Mehrere Zonen gefunden; bitte Zone ID angeben.');
      zoneId = zones.result[0].id;
    }
    const resolvedZoneId = zoneId as string;
    const existing = await cfFetch<{ id: string }[]>(`/zones/${resolvedZoneId}/dns_records?type=SMIMEA&name=${encodeURIComponent(fqdn)}`, config.token, {}, transport);
    const records = existing.result ?? [];
    if (config.mode === 'create' && records.length) throw new Error('Record existiert bereits; Upsert wählen oder manuell löschen.');
    if (config.mode === 'recreate') await Promise.all(records.map((record) => cfFetch(`/zones/${resolvedZoneId}/dns_records/${record.id}`, config.token, { method: 'DELETE' }, transport)));
    const recordId = config.mode === 'upsert' ? records[0]?.id : undefined;
    const result = await cfFetch(`/zones/${resolvedZoneId}/dns_records${recordId ? `/${recordId}` : ''}`, config.token, { method: recordId ? 'PUT' : 'POST', body: JSON.stringify(body) }, transport);
    return { ok: true, message: recordId ? 'Cloudflare Record aktualisiert.' : 'Cloudflare Record erstellt.', response: result.result, curl: cloudflareCurl('<CF_API_TOKEN>', resolvedZoneId, body, recordId ? 'PUT' : 'POST', recordId || '') };
  } catch (error) {
    const raw = error instanceof TypeError
      ? (transport === 'proxy' ? 'Cloudflare Pages Function /api/cloudflare-dns nicht erreichbar. Auf Cloudflare Pages deployen oder curl nutzen.' : 'Cloudflare API im Browser nicht erreichbar (CORS). Bitte Cloudflare-Pages-Proxy oder curl nutzen.')
      : error instanceof Error ? error.message : 'Cloudflare API Fehler.';
    return { ok: false, message: mask(raw, config.token), curl };
  }
}
