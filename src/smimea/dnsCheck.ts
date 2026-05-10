import { bytesToHex, hexToBytes } from './emailHash';
import { parseSmimeaContent } from './smimeaRecord';

export interface ResolverCheck {
  resolver: 'Cloudflare' | 'Google';
  ok: boolean;
  status: number | null;
  ad: boolean;
  hasRrsig: boolean;
  ttl?: number;
  answers: string[];
  matchesExpected: boolean;
  message: string;
}

interface DoHAnswer { name: string; type: number; TTL: number; data: string }
interface DoHResponse { Status: number; AD?: boolean; Answer?: DoHAnswer[] }

const SMIMEA_TYPE = 53;
const RRSIG_TYPE = 46;
const CLASS_IN = 1;
const TYPE_OPT = 41;
const AD_FLAG = 0x0020;
const DO_FLAG = 0x8000;

export function certificateDerFromSmimeaAnswer(content: string): Uint8Array | null {
  const parsed = parseSmimeaContent(content);
  if (!parsed || parsed.selector !== 0 || parsed.matchingType !== 0) return null;
  return hexToBytes(parsed.hex);
}

export function parseDohResponse(json: DoHResponse, expectedContent = ''): Omit<ResolverCheck, 'resolver'> {
  const answers = json.Answer ?? [];
  const smimeaAnswers = answers.filter((answer) => answer.type === SMIMEA_TYPE).map((answer) => answer.data);
  return summarizeDnsResult(json.Status, Boolean(json.AD), answers.some((answer) => answer.type === RRSIG_TYPE), smimeaAnswers, answers.find((answer) => answer.type === SMIMEA_TYPE)?.TTL, expectedContent);
}

function summarizeDnsResult(status: number, ad: boolean, hasRrsig: boolean, smimeaAnswers: string[], ttl: number | undefined, expectedContent = ''): Omit<ResolverCheck, 'resolver'> {
  const expected = expectedContent ? parseSmimeaContent(expectedContent) : null;
  const matchesExpected = expected ? smimeaAnswers.some((answer) => {
    const parsed = parseSmimeaContent(answer);
    return parsed && parsed.usage === expected.usage && parsed.selector === expected.selector && parsed.matchingType === expected.matchingType && parsed.hex === expected.hex;
  }) : smimeaAnswers.length > 0;
  const ok = status === 0 && smimeaAnswers.length > 0 && matchesExpected;
  return {
    ok,
    status,
    ad,
    hasRrsig,
    ttl,
    answers: smimeaAnswers,
    matchesExpected,
    message: ok ? (expected ? 'Record gefunden und exakt passend.' : 'SMIMEA Record gefunden.') : smimeaAnswers.length ? 'SMIMEA Record gefunden, aber Inhalt weicht ab.' : 'Kein SMIMEA Record in der Antwort gefunden.',
  };
}

async function queryJson(url: string, resolver: ResolverCheck['resolver'], expectedContent = ''): Promise<ResolverCheck> {
  try {
    const response = await fetch(url, { headers: { Accept: 'application/dns-json' } });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return { resolver, ...parseDohResponse(await response.json(), expectedContent) };
  } catch (error) {
    return { resolver, ok: false, status: null, ad: false, hasRrsig: false, answers: [], matchesExpected: false, message: error instanceof Error ? error.message : 'DNS-Abfrage fehlgeschlagen.' };
  }
}

function writeUint16(out: number[], value: number) { out.push((value >> 8) & 0xff, value & 0xff); }
function writeUint32(out: number[], value: number) { out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff); }

export function buildDnsQuery(name: string, type = SMIMEA_TYPE): Uint8Array {
  const out: number[] = [];
  writeUint16(out, 0x534d); // deterministic ID: "SM"
  writeUint16(out, 0x0100); // recursion desired
  writeUint16(out, 1); // QDCOUNT
  writeUint16(out, 0); // ANCOUNT
  writeUint16(out, 0); // NSCOUNT
  writeUint16(out, 1); // ARCOUNT with EDNS(0) OPT for DNSSEC DO bit
  for (const label of name.replace(/\.$/, '').split('.')) {
    const bytes = new TextEncoder().encode(label);
    out.push(bytes.length, ...bytes);
  }
  out.push(0);
  writeUint16(out, type);
  writeUint16(out, CLASS_IN);
  out.push(0); // root owner name for OPT
  writeUint16(out, TYPE_OPT);
  writeUint16(out, 1232); // UDP payload size
  writeUint32(out, DO_FLAG);
  writeUint16(out, 0);
  return Uint8Array.from(out);
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function readUint16(bytes: Uint8Array, offset: number): number { return (bytes[offset] << 8) | bytes[offset + 1]; }
function readUint32(bytes: Uint8Array, offset: number): number { return ((bytes[offset] * 2 ** 24) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3]) >>> 0; }

function readName(bytes: Uint8Array, offset: number): { name: string; offset: number } {
  const labels: string[] = [];
  let cursor = offset;
  let nextOffset = offset;
  let jumped = false;
  for (let safety = 0; safety < bytes.length; safety += 1) {
    const length = bytes[cursor];
    if ((length & 0xc0) === 0xc0) {
      const pointer = ((length & 0x3f) << 8) | bytes[cursor + 1];
      if (!jumped) nextOffset = cursor + 2;
      cursor = pointer;
      jumped = true;
      continue;
    }
    if (length === 0) {
      if (!jumped) nextOffset = cursor + 1;
      return { name: labels.join('.'), offset: nextOffset };
    }
    const start = cursor + 1;
    labels.push(new TextDecoder().decode(bytes.slice(start, start + length)));
    cursor = start + length;
    if (!jumped) nextOffset = cursor;
  }
  throw new Error('DNS name compression loop detected.');
}

export function parseDnsMessage(bytes: Uint8Array, expectedContent = ''): Omit<ResolverCheck, 'resolver'> {
  if (bytes.length < 12) throw new Error('DNS response too short.');
  const flags = readUint16(bytes, 2);
  const status = flags & 0x000f;
  const ad = Boolean(flags & AD_FLAG);
  const qdCount = readUint16(bytes, 4);
  const anCount = readUint16(bytes, 6);
  let offset = 12;
  for (let i = 0; i < qdCount; i += 1) {
    offset = readName(bytes, offset).offset + 4;
  }
  const answers: string[] = [];
  let ttl: number | undefined;
  let hasRrsig = false;
  for (let i = 0; i < anCount; i += 1) {
    const name = readName(bytes, offset);
    offset = name.offset;
    const type = readUint16(bytes, offset);
    offset += 2;
    offset += 2; // class
    const recordTtl = readUint32(bytes, offset);
    offset += 4;
    const rdLength = readUint16(bytes, offset);
    offset += 2;
    const rdata = bytes.slice(offset, offset + rdLength);
    offset += rdLength;
    if (type === SMIMEA_TYPE && rdata.length >= 3) {
      answers.push(`${rdata[0]} ${rdata[1]} ${rdata[2]} ${bytesToHex(rdata.slice(3))}`);
      ttl ??= recordTtl;
    }
    if (type === RRSIG_TYPE) hasRrsig = true;
  }
  return summarizeDnsResult(status, ad, hasRrsig, answers, ttl, expectedContent);
}

async function queryWire(name: string, resolver: ResolverCheck['resolver'], expectedContent = ''): Promise<ResolverCheck> {
  try {
    const response = await fetch(`https://dns.google/dns-query?dns=${base64Url(buildDnsQuery(name))}`, { headers: { Accept: 'application/dns-message' } });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return { resolver, ...parseDnsMessage(new Uint8Array(await response.arrayBuffer()), expectedContent) };
  } catch (error) {
    return { resolver, ok: false, status: null, ad: false, hasRrsig: false, answers: [], matchesExpected: false, message: error instanceof Error ? error.message : 'DNS-Abfrage fehlgeschlagen.' };
  }
}

export async function checkDns(fqdn: string, expectedContent = ''): Promise<ResolverCheck[]> {
  const cleanName = fqdn.replace(/\.$/, '');
  const name = encodeURIComponent(cleanName);
  return Promise.all([
    queryJson(`https://cloudflare-dns.com/dns-query?name=${name}&type=SMIMEA&do=1`, 'Cloudflare', expectedContent),
    queryWire(cleanName, 'Google', expectedContent),
  ]);
}
