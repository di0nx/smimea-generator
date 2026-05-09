import { bytesToHex, sha } from './emailHash';

export type Usage = 0 | 1 | 2 | 3;
export type Selector = 0 | 1;
export type MatchingType = 0 | 1 | 2;

export interface SmimeaOptions { usage: Usage; selector: Selector; matchingType: MatchingType }
export interface SmimeaRecordResult { content: string; certificateDataHex: string; selectedDataHex: string }

export async function selectedCertificateData(der: Uint8Array, spki: Uint8Array, selector: Selector): Promise<Uint8Array> {
  return selector === 0 ? der : spki;
}

export async function matchingData(data: Uint8Array, matchingType: MatchingType): Promise<Uint8Array> {
  if (matchingType === 0) return data;
  return sha(matchingType === 1 ? 'SHA-256' : 'SHA-512', data);
}

export async function generateSmimeaRecord(der: Uint8Array, spki: Uint8Array, options: SmimeaOptions): Promise<SmimeaRecordResult> {
  const selected = await selectedCertificateData(der, spki, options.selector);
  const matched = await matchingData(selected, options.matchingType);
  const certificateDataHex = bytesToHex(matched);
  return {
    content: `${options.usage} ${options.selector} ${options.matchingType} ${certificateDataHex}`,
    certificateDataHex,
    selectedDataHex: bytesToHex(selected),
  };
}

export function parseSmimeaContent(content: string): { usage: number; selector: number; matchingType: number; hex: string } | null {
  const normalized = content.replace(/\"/g, '').trim().replace(/\s+/g, ' ');
  const match = normalized.match(/^(\d+)\s+(\d+)\s+(\d+)\s+([0-9a-fA-F\s]+)$/);
  if (!match) return null;
  return { usage: Number(match[1]), selector: Number(match[2]), matchingType: Number(match[3]), hex: match[4].replace(/\s+/g, '').toLowerCase() };
}
