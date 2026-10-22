// Pocket Classics Dedicated Service Worker (Standalone Scope /games/)
const CACHE_NAME = 'pocket-classics-v1';
const PRECACHE_URLS = [
    '/games/hub',
    '/games/pocketclassics/css/arcade.css',
    '/games/pocketclassics/manifest.json',
    '/games/pocketclassics/assets/logo-192.png',
    '/games/pocketclassics/assets/logo-512.png',
    '/games/pocketclassics/assets/logo.png',
    '/games/pocketclassics/js/arcade-helper.js',
    '/games/pocketclassics/js/audio-manager.js',
    '/games/pocketclassics/js/theme-manager.js'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(PRECACHE_URLS).catch((err) => {
                console.warn('[SW] Pre-caching non-fatal warning:', err);
            });
        }).then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((name) => {
                    if (name !== CACHE_NAME && name.startsWith('pocket-classics-')) {
                        return caches.delete(name);
                    }
                })
            );
        }).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    const request = event.request;
    // Only handle GET requests within scope
    if (request.method !== 'GET') return;
    
    // Navigation requests
    if (request.mode === 'navigate') {
        event.respondWith(
            fetch(request).catch(() => {
                return caches.match('/games/hub') || caches.match(request);
            })
        );
        return;
    }

    // Static assets: cache first, fallback to network
    event.respondWith(
        caches.match(request).then((cachedResponse) => {
            if (cachedResponse) return cachedResponse;
            return fetch(request).then((networkResponse) => {
                if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
                    const responseToCache = networkResponse.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(request, responseToCache).catch(() => {});
                    });
                }
                return networkResponse;
            }).catch(() => {
                return cachedResponse;
            });
        })
    );
});
