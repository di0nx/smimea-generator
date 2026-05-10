const CLOUDFLARE_API = 'https://api.cloudflare.com/client/v4';

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

export async function onRequestOptions(): Promise<Response> {
  return new Response(null, { status: 204 });
}

export async function onRequestPost(context: { request: Request }): Promise<Response> {
  const token = context.request.headers.get('authorization');
  if (!token?.startsWith('Bearer ')) return json({ success: false, errors: [{ message: 'Missing Cloudflare API token.' }] }, 401);

  let payload: { path?: string; method?: string; body?: string };
  try {
    payload = await context.request.json();
  } catch {
    return json({ success: false, errors: [{ message: 'Invalid JSON body.' }] }, 400);
  }

  const path = payload.path ?? '';
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('://')) {
    return json({ success: false, errors: [{ message: 'Invalid Cloudflare API path.' }] }, 400);
  }

  const method = (payload.method ?? 'GET').toUpperCase();
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    return json({ success: false, errors: [{ message: 'Unsupported method.' }] }, 405);
  }

  const response = await fetch(`${CLOUDFLARE_API}${path}`, {
    method,
    headers: {
      authorization: token,
      'content-type': 'application/json',
    },
    body: ['GET', 'HEAD'].includes(method) ? undefined : payload.body,
  });

  return new Response(response.body, {
    status: response.status,
    headers: {
      'content-type': response.headers.get('content-type') ?? 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}
