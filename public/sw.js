const CACHE_NAME = 'gplmods-cache-v3';
const urlsToCache = [
  '/',
  '/css/style.css',
  '/js/main.js',
  '/sfx/notification.mp3',
  '/images/icon-192x192.png',
  '/images/icon-512x512.png'
];

// Install event - Cache essential files
self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(urlsToCache).catch(err => console.log('SW Cache error: ', err));
    })
  );
});

// Activate event - Clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch event - Serve from cache, fallback to network
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  // Skip cross-origin or API calls
  if (event.request.url.includes('/api/') || event.request.url.includes('/socket.io/')) return;
  
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});

// ============================================================================
// PUSH EVENT: Background & PWA Dynamic Notifications
// Handles notifications for new uploads, club updates, and admin messages.
// Uses custom tag deduplication so multiple notifications replace gracefully
// instead of filling up the user's notification bar with dozens of pings.
// ============================================================================
self.addEventListener('push', event => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { title: 'GPL Mods Update', body: event.data ? event.data.text() : '' };
  }

  const title = data.title || 'GPL Mods Update';
  const options = {
    body: data.body || 'New content is available on GPL Mods.',
    icon: data.icon || '/images/icon-192x192.png',
    badge: data.badge || '/images/icon-192x192.png',
    image: data.image || undefined,
    sound: '/sfx/notification.mp3', // Custom notification sound effect
    tag: data.tag || ('gplmods-' + (data.category || 'general')), // Category tag prevents flooding
    renotify: false,
    vibrate: [150, 60, 150],
    data: {
      url: data.url || '/',
      category: data.category || 'general',
      sound: data.sound !== false
    }
  };

  // Broadcast to open client tabs/PWA windows so audio plays immediately
  const broadcastPromise = self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
    clients.forEach(client => {
      client.postMessage({
        type: 'GPL_PUSH_RECEIVED',
        payload: data
      });
    });
  });

  const showNotificationPromise = self.registration.showNotification(title, options);
  event.waitUntil(Promise.all([broadcastPromise, showNotificationPromise]));
});

// ============================================================================
// NOTIFICATION CLICK: Focus existing PWA or open URL
// ============================================================================
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url) ? event.notification.data.url : '/';

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
      for (let client of windowClients) {
        if ('focus' in client) {
          if (client.url && client.url.includes(self.registration.scope)) {
            client.navigate(targetUrl);
            return client.focus();
          }
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
    })
  );
});