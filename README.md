# Analytics Dashboard

Production: <https://download-analytics-dashboard.pages.dev/>

The dashboard is hosted by Cloudflare Pages. `_worker.js` handles authenticated sessions and
proxies report requests to the protected Supabase Edge Function. The browser never receives the
dashboard token, password hash, or Supabase service-role key.

The following values are encrypted Cloudflare Pages production secrets and must never be committed:

- `DASHBOARD_AUTH_JSON`
- `ANALYTICS_DASHBOARD_TOKEN`
- `SESSION_SIGNING_KEY`

Deploy the static page and Worker with Wrangler:

```sh
npx wrangler pages deploy <directory-containing-index-and-worker> \
  --project-name download-analytics-dashboard --branch main
```

## Optional local server

Start the dashboard locally from the repository root:

```sh
python3 analytics-dashboard/server.py
```

Then open `http://127.0.0.1:8765` and sign in. Do not open `index.html` directly.

The local server keeps both secrets out of the browser:

- `.analytics-dashboard-auth.json` contains the authorized email and a salted PBKDF2 password hash.
- `.analytics-dashboard-token` contains the protected Edge Function token.

Both files are ignored by Git. Successful login creates an HttpOnly, SameSite session that expires
after eight hours. Five recent failed attempts from the same client trigger a 15-minute lockout.
