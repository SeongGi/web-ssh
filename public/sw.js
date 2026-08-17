const CACHE_NAME = 'web-ssh-v10';

// HTML is deliberately NOT precached. `/` and `/index.html` sit behind requireAuth, so
// precaching them while the session is expired stored the *login page* under `/` — after
// signing in the user kept landing back on login. And cache-first navigation served the
// previous deploy's HTML for one whole launch, so a newly shipped feature appeared to be
// missing until the app was reopened.
const ASSETS = [
  '/style.css?v=15',
  '/app.js?v=15',
  '/icon.jpg',
  // Vendored locally: these used to be fetched from unpkg/jsdelivr and then cached
  // here, so one bad CDN response persisted across reloads and deploys.
  '/vendor/lucide.min.js',
  '/vendor/xterm.js',
  '/vendor/xterm.css',
  '/vendor/xterm-addon-fit.js',
  'https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@300;400;500;600;700&display=swap'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) =>
      // Per-asset, not addAll: one flaky CDN used to reject the whole batch, and the
      // swallowed error left install "successful" with an empty cache — while activate
      // had already deleted the previous one.
      Promise.allSettled(
        ASSETS.map((url) => cache.add(url).catch((err) => {
          console.warn('Pre-caching skipped:', url, err && err.message);
        }))
      )
    )
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const request = event.request;

  // Let websockets and API endpoints bypass service worker cache
  if (request.url.includes('/api/') || request.url.includes('/ssh') || request.method !== 'GET') {
    return;
  }

  // Network-first for documents so a deploy takes effect immediately, with the cache
  // only as an offline fallback.
  if (request.mode === 'navigate' || request.destination === 'document') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // Never cache a redirect or an error page — that is how the login page ended
          // up stored as the dashboard.
          if (response.ok && !response.redirected) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => caches.match(request))
    );
    return;
  }

  // Versioned static assets: cache-first with background revalidation.
  event.respondWith(
    caches.match(request).then((cachedResponse) => {
      if (cachedResponse) {
        fetch(request).then((networkResponse) => {
          if (networkResponse.ok && !networkResponse.redirected) {
            caches.open(CACHE_NAME).then((cache) => cache.put(request, networkResponse));
          }
        }).catch(() => {});
        return cachedResponse;
      }
      return fetch(request);
    })
  );
});
