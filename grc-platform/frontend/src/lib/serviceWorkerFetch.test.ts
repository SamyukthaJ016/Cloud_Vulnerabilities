import { readFileSync } from 'node:fs';
import { URL as NodeURL } from 'node:url';
import { runInNewContext } from 'node:vm';
import { describe, expect, it, vi } from 'vitest';

const workerSource = readFileSync(new NodeURL('../../public/sw.js', import.meta.url), 'utf8');

function worker(network: () => Promise<Response>) {
  const entries = new Map<string, Response>();
  const key = (request: { url: string } | string) => typeof request === 'string' ? request : request.url;
  const cache = {
    match: vi.fn(async request => entries.get(key(request))?.clone()),
    put: vi.fn(async (request, response) => { entries.set(key(request), response); }),
  };
  const listeners: Record<string, (event: unknown) => void> = {};
  const fetch = vi.fn(network);
  runInNewContext(workerSource, {
    self: { location: { origin: 'https://grc.example' }, addEventListener: (name: string, listener: (event: unknown) => void) => { listeners[name] = listener; } },
    caches: { open: async () => cache }, fetch, Response, URL,
  });
  async function request(path: string, mode = 'navigate') {
    let result: Promise<Response> | undefined;
    const background: Promise<unknown>[] = [];
    listeners.fetch({ request: { url: `https://grc.example${path}`, method: 'GET', mode },
      respondWith: (response: Promise<Response>) => { result = response; },
      waitUntil: (promise: Promise<unknown>) => { background.push(promise); },
    });
    const response = await result!;
    await Promise.all(background);
    return response;
  }
  return { request, entries, cache, fetch };
}

describe('Deployment-safe GRC page caching', () => {
  it('loads the current HTML instead of a cached shell referencing removed chunks', async () => {
    const app = worker(async () => new Response('current deployment'));
    app.entries.set('https://grc.example/dashboard', new Response('old deployment'));
    expect(await (await app.request('/dashboard')).text()).toBe('current deployment');
    expect(app.fetch).toHaveBeenCalledWith(expect.anything(), { cache: 'no-store' });
    expect(await app.entries.get('https://grc.example/dashboard')!.text()).toBe('current deployment');
  });

  it('uses the saved shell only when the network is unavailable', async () => {
    const app = worker(async () => { throw new Error('offline'); });
    app.entries.set('/index.html', new Response('offline shell'));
    expect(await (await app.request('/dashboard')).text()).toBe('offline shell');
  });

  it('keeps fingerprinted JavaScript cached without a background request', async () => {
    const app = worker(async () => new Response('network'));
    app.entries.set('https://grc.example/static/app-hash.js', new Response('cached script'));
    expect(await (await app.request('/static/app-hash.js', 'cors')).text()).toBe('cached script');
    expect(app.fetch).not.toHaveBeenCalled();
  });

  it('does not replace a server error with a stale healthy page', async () => {
    const app = worker(async () => new Response('unavailable', { status: 503 }));
    app.entries.set('https://grc.example/dashboard', new Response('old deployment'));
    expect((await app.request('/dashboard')).status).toBe(503);
    expect(app.cache.put).not.toHaveBeenCalled();
  });
});
