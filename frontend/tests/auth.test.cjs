const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { webcrypto } = require('node:crypto');
const vm = require('node:vm');

async function page(path = '/login', query = '') {
  const storage = new Map();
  const redirects = [];
  const calls = [];
  const window = {
    location: { origin: 'http://localhost:8000', pathname: path, href: `http://localhost:8000${path}${query}`, assign: value => redirects.push(value), replace: value => redirects.push(value) },
    sessionStorage: { getItem: key => storage.get(key), setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) },
    crypto: webcrypto, btoa: value => Buffer.from(value, 'binary').toString('base64'), atob: value => Buffer.from(value, 'base64').toString('binary'),
    history: { replaceState() {} },
    fetch: async (url, init) => {
      calls.push([url, init]);
      return { ok: true, json: async () => ({ enabled: true, url: 'http://localhost:8081', realm: 'test', client_id: 'cloudguard-frontend' }) };
    },
  };
  const context = { window, document: { documentElement: { dataset: {} }, readyState: 'loading', addEventListener() {} }, Request, Headers, URL, URLSearchParams, TextEncoder, Uint8Array, console };
  vm.runInNewContext(readFileSync(require.resolve('../cloudguard-ui.js'), 'utf8'), context);
  if (!query) await window.cloudguardAccountReady;
  return { window, redirects, calls, storage };
}

test('public signup remains visible without a token', async () => {
  const { redirects, window } = await page('/signup');
  assert.equal(window.cloudguardAccount.enabled, true);
  assert.deepEqual(redirects, []);
});

test('Google uses Keycloak with PKCE and a fixed local callback', async () => {
  const { window, redirects, storage } = await page();
  void window.cloudguardAccount.login({ google: true });
  for (let i = 0; !redirects.length && i < 200; i++) await new Promise(resolve => setTimeout(resolve, 5));
  const url = new URL(redirects[0]);
  assert.equal(url.searchParams.get('kc_idp_hint'), 'google');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('redirect_uri'), 'http://localhost:8000/login');
  assert.equal(url.searchParams.get('state'), storage.get('cloudguard.oidc.state'));
  assert.ok(url.searchParams.get('code_challenge'));
});

test('email signup uses the registration endpoint and safely encodes email', async () => {
  const { window, redirects } = await page('/signup');
  void window.cloudguardAccount.login({ register: true, email: 'name+test@example.test' });
  for (let i = 0; !redirects.length && i < 200; i++) await new Promise(resolve => setTimeout(resolve, 5));
  const url = new URL(redirects[0]);
  assert.ok(url.pathname.endsWith('/registrations'));
  assert.equal(url.searchParams.get('login_hint'), 'name+test@example.test');
  assert.equal(url.searchParams.get('kc_idp_hint'), null);
});

test('a callback without the original state cannot exchange its code', async () => {
  const { redirects, calls } = await page('/login', '?code=forged&state=foreign');
  for (let i = 0; !redirects.length && i < 200; i++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(calls.filter(([url]) => String(url).endsWith('/token')).length, 0);
});
