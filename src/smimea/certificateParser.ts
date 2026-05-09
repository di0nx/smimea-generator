import { X509Certificate } from '@peculiar/x509';
import { bytesToHex, sha } from './emailHash';

export interface ParsedCertificate {
  certificate: X509Certificate;
  der: Uint8Array;
  spki: Uint8Array;
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  publicKeyAlgorithm: string;
  signatureAlgorithm: string;
  emails: string[];
  keyUsage: string[];
  extendedKeyUsage: string[];
  sha256Fingerprint: string;
  sha512Fingerprint: string;
  warnings: string[];
}

const PEM_CERT_RE = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
const OIDS: Record<string, string> = {
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.10045.2.1': 'ECDSA',
  '1.2.840.10040.4.1': 'DSA',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
};

export function pemToDer(pem: string): Uint8Array {
  const match = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  if (!match) throw new Error('Keine PEM-Zertifikatsdaten gefunden.');
  const b64 = match[1].replace(/\s+/g, '');
  const binary = atob(b64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function extractCertificateBlobs(input: string | Uint8Array): { der: Uint8Array; count: number } {
  if (input instanceof Uint8Array) return { der: input, count: 1 };
  const matches = [...input.matchAll(PEM_CERT_RE)];
  if (matches.length > 0) return { der: pemToDer(matches[0][0]), count: matches.length };
  const trimmed = input.trim();
  try {
    return { der: pemToDer(trimmed), count: 1 };
  } catch {
    const binary = atob(trimmed.replace(/\s+/g, ''));
    return { der: Uint8Array.from(binary, (char) => char.charCodeAt(0)), count: 1 };
  }
}

function derLength(bytes: Uint8Array, offset: number): { length: number; header: number } {
  const first = bytes[offset];
  if (first < 0x80) return { length: first, header: 1 };
  const count = first & 0x7f;
  let length = 0;
  for (let i = 0; i < count; i += 1) length = (length << 8) | bytes[offset + 1 + i];
  return { length, header: 1 + count };
}

function derElementEnd(bytes: Uint8Array, offset: number): number {
  const len = derLength(bytes, offset + 1);
  return offset + 1 + len.header + len.length;
}

function derChildren(bytes: Uint8Array, seqOffset = 0): number[] {
  if (bytes[seqOffset] !== 0x30) throw new Error('ASN.1 SEQUENCE erwartet.');
  const len = derLength(bytes, seqOffset + 1);
  const start = seqOffset + 1 + len.header;
  const end = start + len.length;
  const out: number[] = [];
  for (let offset = start; offset < end; offset = derElementEnd(bytes, offset)) out.push(offset);
  return out;
}

export function extractSubjectPublicKeyInfo(certDer: Uint8Array): Uint8Array {
  const certChildren = derChildren(certDer, 0);
  const tbs = certDer.slice(certChildren[0], derElementEnd(certDer, certChildren[0]));
  const tbsChildren = derChildren(tbs, 0);
  const versionOffset = tbs[tbsChildren[0]] === 0xa0 ? 1 : 0;
  const spkiOffset = tbsChildren[versionOffset + 5];
  return tbs.slice(spkiOffset, derElementEnd(tbs, spkiOffset));
}

function oidName(oid: string | undefined): string { return oid ? `${OIDS[oid] ?? oid}` : 'Unbekannt'; }
function linesFromName(value: string): string { return value.replace(/, /g, '\n'); }

function getEmails(certificate: X509Certificate): string[] {
  const emails = new Set<string>();
  for (const ext of certificate.extensions) {
    if (ext.type === '2.5.29.17') {
      const text = ext.toString();
      for (const match of text.matchAll(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi)) emails.add(match[0].toLowerCase());
    }
  }
  const subjectText = certificate.subject.toString();
  for (const match of subjectText.matchAll(/(?:E|emailAddress)=([^,\n]+)/gi)) emails.add(match[1].trim().toLowerCase());
  return [...emails];
}

function extensionValues(certificate: X509Certificate, oid: string): string[] {
  const ext = certificate.extensions.find((item) => item.type === oid);
  if (!ext) return [];
  return ext.toString().split(/[,\n]/).map((part) => part.trim()).filter(Boolean);
}

export async function parseCertificate(fileData: ArrayBuffer, fileName = ''): Promise<ParsedCertificate> {
  const looksText = /\.(pem|crt|cer|txt)$/i.test(fileName);
  let input: string | Uint8Array = new Uint8Array(fileData);
  if (looksText || new TextDecoder().decode(fileData.slice(0, 32)).includes('BEGIN')) input = new TextDecoder().decode(fileData);
  const { der, count } = extractCertificateBlobs(input);
  const derCopy = new Uint8Array(der);
  const certificate = new X509Certificate(derCopy.buffer);
  const spki = extractSubjectPublicKeyInfo(der);
  const warnings = count > 1 ? [`Die Datei enthält ${count} Zertifikate. Verwendet wird das erste Zertifikat; bitte prüfen, ob es das End-Entity-Zertifikat ist.`] : [];
  return {
    certificate,
    der,
    spki,
    subject: linesFromName(certificate.subject),
    issuer: linesFromName(certificate.issuer),
    serialNumber: certificate.serialNumber,
    notBefore: certificate.notBefore,
    notAfter: certificate.notAfter,
    publicKeyAlgorithm: certificate.publicKey.algorithm.name || 'Unbekannt',
    signatureAlgorithm: certificate.signatureAlgorithm.name || 'Unbekannt',
    emails: getEmails(certificate),
    keyUsage: extensionValues(certificate, '2.5.29.15'),
    extendedKeyUsage: extensionValues(certificate, '2.5.29.37'),
    sha256Fingerprint: bytesToHex(await sha('SHA-256', der)),
    sha512Fingerprint: bytesToHex(await sha('SHA-512', der)),
    warnings,
  };
}
