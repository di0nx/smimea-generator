export function splitEmailAddress(email: string): { localPart: string; domain: string } {
  const trimmed = email.trim();
  const at = trimmed.lastIndexOf('@');
  if (at <= 0 || at === trimmed.length - 1) throw new Error('Bitte eine gültige E-Mail-Adresse eingeben.');
  return { localPart: trimmed.slice(0, at), domain: trimmed.slice(at + 1).toLowerCase() };
}

export function bytesToHex(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return [...view].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2) throw new Error('Hex-Daten haben eine ungerade Länge.');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function sha(algorithm: 'SHA-256' | 'SHA-512', data: ArrayBuffer | Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
  return new Uint8Array(await crypto.subtle.digest(algorithm, bytes as BufferSource));
}

export async function localPartHash(localPart: string): Promise<string> {
  return bytesToHex((await sha('SHA-256', localPart)).slice(0, 28));
}

export async function smimeaOwnerName(email: string): Promise<string> {
  const { localPart, domain } = splitEmailAddress(email);
  return `${await localPartHash(localPart)}._smimecert.${domain}`;
}

export function relativeCloudflareName(fqdn: string, zoneName: string): string {
  const cleanFqdn = fqdn.replace(/\.$/, '').toLowerCase();
  const cleanZone = zoneName.trim().replace(/^\.+|\.+$/g, '').toLowerCase();
  if (!cleanZone) return cleanFqdn;
  if (cleanFqdn === cleanZone) return '@';
  const suffix = `.${cleanZone}`;
  if (!cleanFqdn.endsWith(suffix)) throw new Error('Der FQDN liegt nicht innerhalb der angegebenen DNS-Zone.');
  return cleanFqdn.slice(0, -suffix.length);
}
