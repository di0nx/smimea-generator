import { describe, expect, it } from 'vitest';
import { extractCertificateBlobs, pemToDer } from './certificateParser';
import { bytesToHex, localPartHash, relativeCloudflareName } from './emailHash';
import { generateSmimeaRecord } from './smimeaRecord';
import { cloudflareRecordBody } from './cloudflareApi';
import { certificateDerFromSmimeaAnswer, parseDohResponse } from './dnsCheck';

const SAMPLE_PEM = `-----BEGIN CERTIFICATE-----
AQIDBAUG
-----END CERTIFICATE-----`;

describe('RFC 8162 local-part hashing', () => {
  it('uses the first 28 bytes of SHA-256 over the exact local-part', async () => {
    await expect(localPartHash('local')).resolves.toBe('25bf8e1a2393f1108d37029b3df5593236c755742ec93465bbafa9b2');
  });
});

describe('certificate input helpers', () => {
  it('converts PEM to DER bytes', () => {
    expect(bytesToHex(pemToDer(SAMPLE_PEM))).toBe('010203040506');
  });

  it('uses the first certificate and reports the bundle size', () => {
    const result = extractCertificateBlobs(`${SAMPLE_PEM}\n${SAMPLE_PEM}`);
    expect(result.count).toBe(2);
    expect(bytesToHex(result.der)).toBe('010203040506');
  });
});

describe('SMIMEA generation', () => {
  const der = new Uint8Array([1, 2, 3, 4, 5, 6]);
  const spki = new Uint8Array([9, 8, 7]);

  it('generates default 3 0 0 records with full DER certificate hex', async () => {
    const record = await generateSmimeaRecord(der, spki, { usage: 3, selector: 0, matchingType: 0 });
    expect(record.content).toBe('3 0 0 010203040506');
  });

  it('supports SHA-256 matching', async () => {
    const record = await generateSmimeaRecord(der, spki, { usage: 3, selector: 0, matchingType: 1 });
    expect(record.content).toBe('3 0 1 7192385c3c0605de55bb9476ce1d90748190ecb32a8eed7f5207b30cf6a1fe89');
  });

  it('supports SHA-512 matching over SubjectPublicKeyInfo', async () => {
    const record = await generateSmimeaRecord(der, spki, { usage: 3, selector: 1, matchingType: 2 });
    expect(record.content).toBe('3 1 2 a3449c0cca5460244aa2fef7c809c5cd0148ef078e24ca004a07f6686c5cae04373d38df93d593e10cc68cdc627086b8ce69e467d8b9a5da5bb094f057a6e6f1');
  });
});

describe('Cloudflare relative name calculation', () => {
  it('returns the owner name relative to the zone', () => {
    expect(relativeCloudflareName('abc._smimecert.mail.example.org', 'example.org')).toBe('abc._smimecert.mail');
  });
});

describe('DoH response parsing', () => {
  it('detects exact SMIMEA answers', () => {
    const parsed = parseDohResponse({ Status: 0, AD: true, Answer: [{ name: 'x', type: 53, TTL: 300, data: '3 0 0 0102' }, { name: 'x', type: 46, TTL: 300, data: 'sig' }] }, '3 0 0 0102');
    expect(parsed.ok).toBe(true);
    expect(parsed.hasRrsig).toBe(true);
    expect(parsed.ttl).toBe(300);
  });

  it('can check for an existing SMIMEA answer without expected content', () => {
    const parsed = parseDohResponse({ Status: 0, AD: false, Answer: [{ name: 'x', type: 53, TTL: 120, data: '3 0 0 0102' }] });
    expect(parsed.ok).toBe(true);
    expect(parsed.message).toBe('SMIMEA Record gefunden.');
  });

  it('extracts DER bytes from full-certificate SMIMEA answers only', () => {
    expect(bytesToHex(certificateDerFromSmimeaAnswer('3 0 0 0102')!)).toBe('0102');
    expect(certificateDerFromSmimeaAnswer('3 0 1 0102')).toBeNull();
  });
});

describe('Cloudflare API record body', () => {
  it('adds the selected email address as record comment', () => {
    const selectedEmail = ['user', 'example.org'].join('@');
    expect(cloudflareRecordBody('abc._smimecert.example.org', '3 0 0 0102', 300, selectedEmail)).toMatchObject({
      comment: `SMIMEA for ${selectedEmail}`,
    });
  });
});
