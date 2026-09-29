# ECDAT JS API client

A single dependency-free file (`ecdatClient.js`) that wraps every backend
endpoint, for whoever's building the frontend. Works in the browser
(React, Vite, CRA, plain `<script type="module">`) and in Node 18+.

## Quick start

```js
import { createECDATClient } from "./ecdatClient.js";

const ecdat = createECDATClient({
  baseUrl: "http://localhost:5000",     // no trailing slash
  apiKey: "ecdat-dev-key-change-me",    // must match ECDAT_API_KEYS on the server
});

const scan = await ecdat.scanSample();          // run a scan against the built-in sample data
console.log(scan.agility_score.score);

const risks = await ecdat.getRisk(scan.scan_id);
const pdfBlob = await ecdat.getReportPdfBlob(scan.scan_id);
```

Every method returns a Promise and mirrors an endpoint 1:1 -- see the
JSDoc comments at the top of `ecdatClient.js` for the full method list,
or just read the API reference table in the project root README.

## Error handling

A failed call rejects with an `ECDATApiError` (not a generic `Error`),
carrying `.status` (HTTP status code) and `.details` (the field-level
validation errors, when the server returned any):

```js
import { ECDATApiError } from "./ecdatClient.js";

try {
  await ecdat.createScan(myCbom);
} catch (e) {
  if (e instanceof ECDATApiError && e.status === 422) {
    // e.details is an array like:
    // [{ index: 0, field: "id", message: "'id' is required." }]
    e.details.forEach((d) => console.log(`Row ${d.index}: ${d.message}`));
  }
}
```

## React example

See `ReactUsageExample.jsx` for a couple of copy-from components: a
dashboard that runs a scan on mount and shows the Agility Score, and a
what-if simulator with checkboxes. Not a runnable app on its own --
wire it into your actual project structure.

## Verifying the client itself works

This isn't just a hand-written wrapper -- it has its own integration
test that hits a **real running server**, not mocks:

```bash
# Terminal 1
python3 run.py

# Terminal 2
node client/ecdatClient.test.mjs
```

Expect `22 passed, 0 failed`. Re-run this any time you change `api.py`
to make sure the client still matches the real API surface.

## CORS note

The server already sends permissive CORS headers (`Access-Control-Allow-Origin: *`)
via `app/api.py`'s `add_cors_headers`, so calling it from a frontend dev
server on a different port (e.g. Vite on `:5173` calling Flask on `:5000`)
works out of the box with no proxy config needed.

## Where the API key comes from in a real frontend

Don't hardcode the API key in frontend source that ships to users. For
this hackathon, the common pattern is fine: put it in a `.env` file
(`VITE_ECDAT_API_KEY=...` for Vite, `REACT_APP_ECDAT_API_KEY=...` for
CRA) and read it via `import.meta.env` / `process.env` as shown in
`ReactUsageExample.jsx`. `.env` files should be in your frontend's
`.gitignore` so the key doesn't end up in your repo history.
