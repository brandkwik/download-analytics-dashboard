# Analytics Dashboard

The dashboard is ready for GitHub Pages. It uses Supabase Auth in the browser and sends the user's
short-lived session token to the protected `download-analytics-report` Edge Function. The public
Supabase anon key in `index.html` is designed for browser use; service-role keys and the legacy
dashboard token must never be committed.

## GitHub Pages

1. Deploy `download-analytics-report` after setting `ANALYTICS_ADMIN_EMAIL` to the authorized email.
2. Create a public GitHub repository containing this directory.
3. In **Settings → Pages**, deploy from the `main` branch and `/ (root)`.
4. Add the resulting Pages URL to Supabase **Authentication → URL Configuration → Redirect URLs**.
5. Open the Pages URL and use **Email me a sign-in link** the first time.

## Optional local server

Start the dashboard locally from the repository root:

```sh
python3 analytics-dashboard/server.py
```

Then open `http://127.0.0.1:8765` and sign in. Do not open `index.html` directly.

The local server keeps both legacy secrets out of the browser:

- `.analytics-dashboard-auth.json` contains the authorized email and a salted PBKDF2 password hash.
- `.analytics-dashboard-token` contains the protected Edge Function token.

Both files are ignored by Git. Successful login creates an HttpOnly, SameSite session that expires
after eight hours. Five failed attempts from the same client trigger a 15-minute lockout.

The hosted page calls the protected Edge Function with a Supabase user session. The Supabase
service-role key is supplied to the function by Supabase and is never stored locally, committed,
or exposed to the browser.
