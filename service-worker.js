const CACHE_NAME = 'pixelito3d-v7';
const CORE_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/vendor/supabase.js',
  '/icon.png',
  '/favicon.png',
  '/icon-180.png',
  '/icon-192.png',
  '/icon-512.png'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(CORE_ASSETS)).catch(() => {})
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  // Nunca cachear llamadas a Supabase ni otros dominios
  if (url.origin !== self.location.origin) return;

  // Red primero (siempre la versión más nueva); caché solo si no hay internet
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response && response.status === 200) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        }
        return response;
      })
      .catch(() => caches.match(event.request).then((c) => c || caches.match('/index.html')))
  );
});
