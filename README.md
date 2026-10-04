# Xcel International Resources

## Run locally

Install Node.js 18 or later, copy `.env.example` to `.env`, then put your Google OAuth web client credentials and Supabase session-pooler URI in `.env`. The server also accepts the existing `GOOGLE CLIENT ID` and `GOOGLE CLIENT SECRET` key names, but underscore-separated names are recommended.

Run:

```powershell
node server.js
```

Open `http://localhost:8000`.

## Supabase user profiles

Add the rotated Postgres connection URI from Supabase to `SUPABASE_CONNECTION_STRING`. Keep it in `.env`; never put it in browser code or commit it. The server validates TLS with Supabase's public CA certificate in `supabase-ca.crt` and writes Google-authenticated users to `public."USERS DATA"`, updating the name for an existing email and inserting a row for a new email.

Run `npm run db:check` to verify the database connection and the `id`, `name`, and `email` columns. This check reads column metadata only; it does not read user rows.

Product, offer, cart, and order data remain browser-local in this MVP. Only authenticated customer profiles are persisted in Supabase.

## Google OAuth setup

In Google Cloud Console, configure the OAuth client as a **Web application**. Add this authorized JavaScript origin:

```text
http://localhost:8000
```

Add this authorized redirect URI:

```text
http://localhost:8000/auth/callback
```

For deployment, set `HOST=0.0.0.0` and `GOOGLE_REDIRECT_URI` to the exact HTTPS callback URL, then register that origin and redirect URI in Google Cloud. Keep `GOOGLE_CLIENT_SECRET` only in the server environment; never put it in browser code or commit `.env`.

The callback exchanges the authorization code on the server and obtains the verified Google profile over HTTPS. Sessions are stored in memory for this MVP and are cleared when the server restarts.