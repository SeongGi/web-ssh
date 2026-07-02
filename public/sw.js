const CACHE_NAME = 'web-ssh-v3';
const ASSETS = [
  '/',
  '/index.html',
  '/login.html',
  '/style.css?v=9',
  '/app.js?v=9',
  '/icon.jpg',
  'https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@300;400;500;600;700&display=swap',
  'https://unpkg.com/lucide@latest',
  'https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css',
  'https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js',
  'https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      // Use no-cors or ignore fail for external assets to prevent block
      return cache.addAll(ASSETS).catch(err => {
        console.warn('Pre-caching warning:', err);
      });
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = event.request.url;

  // Let websockets and API endpoints bypass service worker cache
  if (url.includes('/api/') || url.includes('/ssh') || event.request.method !== 'GET') {
    return;
  }
  
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        // Fetch fresh resource in background to update cache (stale-while-revalidate)
        fetch(event.request).then((networkResponse) => {
          if (networkResponse.status === 200) {
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, networkResponse));
          }
        }).catch(() => {});
        return cachedResponse;
      }
      return fetch(event.request);
    })
  );
});
