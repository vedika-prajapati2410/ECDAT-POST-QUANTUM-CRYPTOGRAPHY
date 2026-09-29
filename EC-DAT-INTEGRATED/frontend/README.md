# ECDAT

Three.js is a real npm dependency here (bundled by Vite) — not loaded from a CDN,
so it works even on networks that block external script CDNs.

## Run it
    npm install
    npm run dev
Open the localhost URL it prints (usually http://localhost:5173) in a real
browser window (Chrome/Edge) — not VS Code's built-in "Simple Browser" preview,
which often has WebGL disabled.

## Build for production
    npm run build
    npm run preview
