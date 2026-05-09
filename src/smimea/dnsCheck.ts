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

export function parseDohResponse(json: DoHResponse, expectedContent: string): Omit<ResolverCheck, 'resolver'> {
  const answers = json.Answer ?? [];
  const smimeaAnswers = answers.filter((answer) => answer.type === SMIMEA_TYPE).map((answer) => answer.data);
  const expected = parseSmimeaContent(expectedContent);
  const matchesExpected = Boolean(expected && smimeaAnswers.some((answer) => {
    const parsed = parseSmimeaContent(answer);
    return parsed && parsed.usage === expected.usage && parsed.selector === expected.selector && parsed.matchingType === expected.matchingType && parsed.hex === expected.hex;
  }));
  const ok = json.Status === 0 && smimeaAnswers.length > 0 && matchesExpected;
  return {
    ok,
    status: json.Status,
    ad: Boolean(json.AD),
    hasRrsig: answers.some((answer) => answer.type === RRSIG_TYPE),
    ttl: answers.find((answer) => answer.type === SMIMEA_TYPE)?.TTL,
    answers: smimeaAnswers,
    matchesExpected,
    message: ok ? 'Record gefunden und exakt passend.' : smimeaAnswers.length ? 'SMIMEA Record gefunden, aber Inhalt weicht ab.' : 'Kein SMIMEA Record in der Antwort gefunden.',
  };
}

async function query(url: string, resolver: ResolverCheck['resolver'], expectedContent: string): Promise<ResolverCheck> {
  try {
    const response = await fetch(url, { headers: { Accept: 'application/dns-json' } });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return { resolver, ...parseDohResponse(await response.json(), expectedContent) };
  } catch (error) {
    return { resolver, ok: false, status: null, ad: false, hasRrsig: false, answers: [], matchesExpected: false, message: error instanceof Error ? error.message : 'DNS-Abfrage fehlgeschlagen.' };
  }
}

export async function checkDns(fqdn: string, expectedContent: string): Promise<ResolverCheck[]> {
  const name = encodeURIComponent(fqdn.replace(/\.$/, ''));
  return Promise.all([
    query(`https://cloudflare-dns.com/dns-query?name=${name}&type=SMIMEA&do=1`, 'Cloudflare', expectedContent),
    query(`https://dns.google/resolve?name=${name}&type=SMIMEA&do=1`, 'Google', expectedContent),
  ]);
}
