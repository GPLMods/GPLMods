# Cloudflare iOS DNS & Store Worker Setup Guide

This directory contains the edge caching worker for the GPLMods iOS Store and DNS profiles API.

---

## ⚡ Architecture Overview

1. **Backend Database & AdminJS (`gplmods.onrender.com`)**:
   - iOS Certificates (`IosCert`) and DNS Profiles (`IosDns`) are managed directly in the GPLMods Admin panel.
   - Any time an Admin creates, updates, or deletes a Certificate or DNS Profile, an automated hook triggers a cache purge to Cloudflare.
   - An explicit **"⚡ Purge Cloudflare Cache"** button is also available in both resources in AdminJS.

2. **Cloudflare Edge Worker (`ios-api-cach.gplmodsofficial.workers.dev`)**:
   - Caches responses using the Cloudflare Cache API for ultra-fast, global delivery without overloading Render backend.
   - Dynamically resolves and matches app icons (e.g. `altstore`, `scarlet`, `esign`, `feather`, `livecontainer`, `trollstore`, etc.) if empty.
   - Purges instantly on demand when receiving a authorized purge signal (`/purge?key=...`).

---

## 🚀 Deployment Instructions

### Option 1: Cloudflare Dashboard (Recommended & Quickest)
1. Go to your [Cloudflare Dashboard](https://dash.cloudflare.com/) -> **Workers & Pages**.
2. Select your worker (e.g. `ios-api-cach`).
3. Click **Quick Edit** (or Edit Code).
4. Copy the entire contents of [`worker.js`](file:///c:/Users/bhatn/GPLMods/cloudflare-worker/worker.js) and paste it into the editor.
5. Click **Deploy**.
6. (Optional) In **Settings** -> **Variables**, add:
   - `PURGE_SECRET`: `gplmods-dns-secret` (or your custom secret)
   - `UPSTREAM_API`: `https://gplmods.onrender.com/api/ios-store`

---

### Option 2: Wrangler CLI
```bash
npm install -g wrangler
wrangler login
wrangler deploy worker.js --name ios-api-cach
```

---

## 🧪 Testing the Purge

- **Manual Purge via Browser/cURL:**
```bash
curl -X POST "https://ios-api-cach.gplmodsofficial.workers.dev/purge?key=gplmods-dns-secret"
```
Or simply visit:
```
https://ios-api-cach.gplmodsofficial.workers.dev/?purge=1&key=gplmods-dns-secret
```

- **Via Admin Panel:**
Navigate to **Mods Management** -> **IosCert** or **IosDns**, then click **"⚡ Purge Cloudflare Cache"** in the top action bar.
