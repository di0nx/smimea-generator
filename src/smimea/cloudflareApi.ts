export type CloudflareMode = 'create' | 'upsert' | 'recreate';
export interface CloudflareConfig { token: string; zoneName: string; zoneId?: string; ttl: number; mode: CloudflareMode }
export interface CloudflareResult { ok: boolean; message: string; curl: string; response?: unknown }

const API = 'https://api.cloudflare.com/client/v4';

function headers(token: string): HeadersInit { return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }; }
function mask(message: string, token: string): string { return token ? message.split(token).join(`${token.slice(0, 4)}…${token.slice(-4)}`) : message; }

export function cloudflareRecordBody(fqdn: string, content: string, ttl: number) {
  const [usage, selector, matching_type, ...hexParts] = content.trim().split(/\s+/);
  const certificate = hexParts.join('');
  return {
    type: 'SMIMEA',
    name: fqdn,
    content,
    ttl,
    data: { usage: Number(usage), selector: Number(selector), matching_type: Number(matching_type), certificate },
  };
}

export function cloudflareCurl(tokenPlaceholder: string, zoneId: string, body: object, method = 'POST', recordId = ''): string {
  const url = `${API}/zones/${zoneId || '<ZONE_ID>'}/dns_records${recordId ? `/${recordId}` : ''}`;
  return `curl -X ${method} "${url}" \\\n  -H "Authorization: Bearer ${tokenPlaceholder}" \\\n  -H "Content-Type: application/json" \\\n  --data '${JSON.stringify(body)}'`;
}

async function cfFetch(path: string, token: string, init: RequestInit = {}) {
  const response = await fetch(`${API}${path}`, { ...init, headers: { ...headers(token), ...(init.headers ?? {}) } });
  const json = await response.json().catch(() => ({}));
  if (!response.ok || json.success === false) throw new Error(JSON.stringify(json.errors ?? json));
  return json;
}

export async function createCloudflareRecord(config: CloudflareConfig, fqdn: string, content: string): Promise<CloudflareResult> {
  const body = cloudflareRecordBody(fqdn, content, config.ttl);
  const curl = cloudflareCurl('<CF_API_TOKEN>', config.zoneId || '<ZONE_ID>', body);
  try {
    let zoneId = config.zoneId;
    if (!zoneId) {
      const zones = await cfFetch(`/zones?name=${encodeURIComponent(config.zoneName)}`, config.token);
      if (!zones.result?.length) throw new Error('Keine Zone gefunden.');
      if (zones.result.length > 1) throw new Error('Mehrere Zonen gefunden; bitte Zone ID angeben.');
      zoneId = zones.result[0].id;
    }
    const resolvedZoneId = zoneId as string;
    const existing = await cfFetch(`/zones/${resolvedZoneId}/dns_records?type=SMIMEA&name=${encodeURIComponent(fqdn)}`, config.token);
    const records = existing.result ?? [];
    if (config.mode === 'create' && records.length) throw new Error('Record existiert bereits; Upsert wählen oder manuell löschen.');
    if (config.mode === 'recreate') await Promise.all(records.map((record: { id: string }) => cfFetch(`/zones/${resolvedZoneId}/dns_records/${record.id}`, config.token, { method: 'DELETE' })));
    const recordId = config.mode === 'upsert' ? records[0]?.id as string | undefined : undefined;
    const result = await cfFetch(`/zones/${resolvedZoneId}/dns_records${recordId ? `/${recordId}` : ''}`, config.token, { method: recordId ? 'PUT' : 'POST', body: JSON.stringify(body) });
    return { ok: true, message: recordId ? 'Cloudflare Record aktualisiert.' : 'Cloudflare Record erstellt.', response: result.result, curl: cloudflareCurl('<CF_API_TOKEN>', resolvedZoneId, body, recordId ? 'PUT' : 'POST', recordId || '') };
  } catch (error) {
    const raw = error instanceof TypeError ? 'Cloudflare API im Browser nicht erreichbar (mögliches CORS-Problem). Bitte curl-Befehl lokal nutzen.' : error instanceof Error ? error.message : 'Cloudflare API Fehler.';
    return { ok: false, message: mask(raw, config.token), curl };
  }
}
