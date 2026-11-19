/**
 * Sezam Service Worker — offline fallback page (spec 7.2)
 *
 * Strategy: network-first with offline fallback.
 * On install, caches a minimal offline page.
 * On fetch failure, serves the cached offline page.
 */

const CACHE_NAME = 'sezam-offline-v1';
const OFFLINE_URL = '/_offline.html';

const OFFLINE_PAGE = `<!DOCTYPE html>
<html lang="sk">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sezam — Offline</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #1a1c16;
            color: #d4c9a8;
            font-family: 'Crimson Text', Georgia, serif;
        }
        .offline-box {
            text-align: center;
            padding: 2rem;
            max-width: 420px;
        }
        .offline-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.6;
        }
        h1 {
            font-family: 'Cinzel', serif;
            font-size: 1.5rem;
            color: #c8a96e;
            margin-bottom: 1rem;
        }
        p {
            font-size: 1.1rem;
            line-height: 1.6;
            opacity: 0.85;
        }
        .retry-btn {
            display: inline-block;
            margin-top: 1.5rem;
            padding: 0.6rem 1.5rem;
            background: #c8a96e;
            color: #1a1c16;
            border: none;
            border-radius: 4px;
            font-family: 'Cinzel', serif;
            font-size: 0.95rem;
            cursor: pointer;
        }
        .retry-btn:hover { background: #d4b87a; }
    </style>
</head>
<body>
    <div class="offline-box">
        <div class="offline-icon">&#x1F50C;</div>
        <h1>Nie ste online</h1>
        <p>Pripojte sa k sieti a skuste znova.</p>
        <button class="retry-btn" onclick="location.reload()">Skusit znova</button>
    </div>
</body>
</html>`;

// Install: cache the offline page
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            // Store the offline page as a Response in the cache
            const response = new Response(OFFLINE_PAGE, {
                headers: { 'Content-Type': 'text/html; charset=utf-8' },
            });
            return cache.put(OFFLINE_URL, response);
        })
    );
    // Activate immediately without waiting for existing clients to close
    self.skipWaiting();
});

// Activate: clean up old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames
                    .filter((name) => name !== CACHE_NAME)
                    .map((name) => caches.delete(name))
            );
        })
    );
    // Take control of all clients immediately
    self.clients.claim();
});

// Fetch: network-first, offline fallback for navigation requests
self.addEventListener('fetch', (event) => {
    // Only handle navigation requests (HTML pages)
    if (event.request.mode === 'navigate') {
        event.respondWith(
            fetch(event.request).catch(() => {
                return caches.open(CACHE_NAME).then((cache) => {
                    return cache.match(OFFLINE_URL);
                });
            })
        );
    }
    // All other requests (API calls, static assets) pass through normally
});
