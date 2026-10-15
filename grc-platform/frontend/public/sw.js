/* global self, caches, fetch, Response, URL */
/**
 * GigaChad GRC Service Worker
 * Provides offline caching and improved performance
 */

const CACHE_NAME = 'gigachad-grc-v2';
const STATIC_CACHE = 'gigachad-static-v2';
const API_CACHE = 'gigachad-api-v2';

// Static assets to cache on install
const STATIC_ASSETS = ['/', '/index.html', '/manifest.json', '/logo.png', '/silent-check-sso.html'];

// API endpoints to cache (GET requests only)
const CACHEABLE_API_PATTERNS = [
  /\/api\/frameworks/,
  /\/api\/dashboard\/summary/,
  /\/api\/users\/me/,
  /\/api\/risks/,
  /\/api\/bcdr\/dashboard/,
  /\/api\/employee-compliance\/metrics/,
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    })
  );
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME && name !== STATIC_CACHE && name !== API_CACHE)
          .map((name) => caches.delete(name))
      );
    })
  );
  self.clients.claim();
});

// Fetch event - serve from cache, fallback to network
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip external requests
  if (!url.origin.includes(self.location.origin)) {
    return;
  }

  // Handle API requests
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(handleApiRequest(request));
    return;
  }

  // HTML must come from the current deployment: old shells reference removed chunks.
  if (request.mode === 'navigate' || url.pathname.endsWith('.html')) {
    event.respondWith(handleNavigationRequest(request));
    return;
  }

  // Fingerprinted static assets can be served from cache.
  event.respondWith(handleStaticRequest(request, event));
});

async function handleNavigationRequest(request) {
  const cache = await caches.open(STATIC_CACHE);
  try {
    const response = await fetch(request, { cache: 'no-store' });
    if (response.ok) await cache.put(request, response.clone()).catch(() => {});
    return response;
  } catch {
    return (await cache.match(request)) || (await cache.match('/index.html')) ||
      new Response('GRC is offline. Reconnect and refresh to continue.', {
        status: 503, headers: { 'Content-Type': 'text/plain' },
      });
  }
}

// Cache-first for static assets
async function handleStaticRequest(request, event) {
  const cache = await caches.open(STATIC_CACHE);
  const cachedResponse = await cache.match(request);

  if (cachedResponse) {
    // Keep non-fingerprinted assets fresh, and keep the worker alive for that update.
    if (!new URL(request.url).pathname.startsWith('/static/')) {
      event.waitUntil(fetchAndCache(request, cache));
    }
    return cachedResponse;
  }

  return fetchAndCache(request, cache);
}

// Network-first for API requests (with cache fallback)
async function handleApiRequest(request) {
  const url = new URL(request.url);
  const isCacheable = CACHEABLE_API_PATTERNS.some((pattern) => pattern.test(url.pathname));

  if (!isCacheable) {
    return fetch(request);
  }

  try {
    const response = await fetch(request);

    if (response.ok) {
      const cache = await caches.open(API_CACHE);
      cache.put(request, response.clone());
    }

    return response;
  } catch {
    // Network failed, try cache
    const cache = await caches.open(API_CACHE);
    const cachedResponse = await cache.match(request);

    if (cachedResponse) {
      return cachedResponse;
    }

    // Return offline response
    return new Response(JSON.stringify({ error: 'Offline', message: 'No cached data available' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

// Fetch and update cache
async function fetchAndCache(request, cache) {
  try {
    const response = await fetch(request);

    if (response.ok) {
      await cache.put(request, response.clone()).catch(() => {});
    }

    return response;
  } catch (error) {
    // Return cached version if available
    const cachedResponse = await cache.match(request);
    if (cachedResponse) {
      return cachedResponse;
    }

    // Return offline page for navigation requests
    if (request.mode === 'navigate') {
      return cache.match('/');
    }

    throw error;
  }
}

// Handle messages from the app
// codeql[js/missing-origin-check] suppressed: Origin validated via event.source.url check below
self.addEventListener('message', (event) => {
  // SECURITY: Validate that the message source is from our own origin
  // In service workers, event.source is a Client object with a url property
  if (event.source) {
    try {
      const sourceUrl = new URL(event.source.url);
      if (sourceUrl.origin !== self.location.origin) {
        self.console.warn(
          '[Security] Received message from unauthorized origin:',
          sourceUrl.origin
        );
        return;
      }
    } catch {
      // If we can't parse the source URL, reject the message
      self.console.warn('[Security] Received message from unknown source');
      return;
    }
  }

  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }

  if (event.data && event.data.type === 'CLEAR_CACHE') {
    caches.keys().then((names) => {
      names.forEach((name) => caches.delete(name));
    });
  }
});
