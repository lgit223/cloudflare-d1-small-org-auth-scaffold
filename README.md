# Cloudflare Workers + D1 Club Auth Skeleton

This is a small reusable scaffold for a school club or small organization website that wants Google login, app-managed roles, and Cloudflare Workers hosting without using Cloudflare Access seats.

It is intentionally generic. Replace all placeholder names, domains, routes, and UI with your own organization details.

## Scaffold Status

This repository is a starter scaffold with a generic authentication core. It is still not a complete production application.

It includes:

- a minimal Cloudflare Worker shape
- a D1 schema for users, OAuth identities, roles, sessions, and OAuth transactions
- Google OAuth/OpenID Connect login and callback routes
- PKCE, state, nonce, and temporary OAuth transaction storage
- D1-backed session cookies stored only as hashes
- reusable `requireUser`, `requireRole`, `requireAdmin`, logout, and CSRF helpers
- small example routes for `/api/me` and an admin-only endpoint

You still need to review the code, configure your own Google OAuth web client, replace the example UI, decide your own roles/admin tooling, and test the final app before using it in production.

## What This Setup Is

- Cloudflare Worker-hosted app/API
- Cloudflare D1 database for users, roles, OAuth identities, and sessions
- Google OAuth/OpenID Connect as the identity provider
- App-managed roles such as `applicant`, `member`, `board`, and `admin`
- Cookie sessions stored as hashed tokens in D1
- CSRF protection for authenticated state-changing requests

This avoids the Cloudflare Access free-tier user-seat model because users authenticate through your app, not through Cloudflare Zero Trust Access.

## What This Setup Is Not

This is not a complete club website or a full admin dashboard.

This is not an enterprise security system.

Use this for:

- school clubs
- student organizations
- small volunteer groups
- non-critical dashboards
- basic member areas

Do not use this skeleton as-is for:

- medical records
- financial records
- legal records
- private student records protected by institutional policy
- anything where account compromise would create major harm

## Important Free-Tier Reality Check

This pattern is not limited by a Cloudflare Access 50-user seat count because it does not use Cloudflare Access as the login gate.

That does not mean unlimited in every sense. You are still limited by:

- Cloudflare Workers request limits
- D1 storage limits
- D1 read/write limits
- size of data stored per user
- Google OAuth configuration and abuse controls

For a normal club website with dozens or a few hundred users and modest profile data, this is usually a reasonable free-tier pattern. If you store large images, sensitive files, or heavy logs, consider R2 or a paid plan.

## Security Tradeoffs Compared With Cloudflare Access

Cloudflare Access is safer and more managed in several ways. By using app-managed auth instead, you accept these risks:

- You own OAuth callback security, token validation, session revocation, and cookie settings.
- You own role assignment and admin tooling.
- You do not get Cloudflare Access policies such as device posture, identity provider group enforcement, or Access audit behavior by default.
- Mistakes in your Worker code can weaken authentication.
- Google email domain checks do not prove app roles. Roles must always come from your database.
- Offboarding depends on your user table/session revocation unless you integrate with an external identity process.
- Free-tier D1 limits can be reached if you store too much data, especially base64 images.

For higher-risk applications, prefer Cloudflare Access, an institutional identity system, or a professionally reviewed auth provider.

## Files Included

- `package.json`: minimal scripts and dependencies
- `wrangler.example.jsonc`: example Worker/D1/asset binding configuration
- `.dev.vars.example`: local-only environment variable template
- `migrations/0001_auth_schema.sql`: empty auth schema only, no content
- `src/index.ts`: minimal Worker route skeleton with auth routes and example protected APIs
- `src/auth.ts`: reusable OAuth, session, role, logout, and CSRF helpers
- `tests/auth.test.mjs`: local behavior tests for the auth scaffold

## Setup Steps

1. Copy this folder into a new repository.
2. Rename `wrangler.example.jsonc` to `wrangler.jsonc`.
3. Create a D1 database:

```bash
npx wrangler d1 create club-auth
```

4. Put the returned database id into `wrangler.jsonc`.
5. Copy `.dev.vars.example` to `.dev.vars` for local development.
6. Add production secrets through Wrangler or the Cloudflare dashboard:

```bash
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put SESSION_SECRET
```

7. Apply the schema locally:

```bash
npx wrangler d1 migrations apply club-auth --local
```

8. Apply the schema remotely:

```bash
npx wrangler d1 migrations apply club-auth --remote
```

9. Run tests:

```bash
npm test
```

10. Run locally:

```bash
npm run dev
```

11. Deploy:

```bash
npm run deploy
```

## Required Google OAuth Settings

Create a Google OAuth client with:

- Application type: Web application
- Authorized redirect URI:

```text
https://YOUR_DOMAIN/auth/callback
```

For local development, also add:

```text
http://localhost:8787/auth/callback
```

Only request basic OpenID scopes:

```text
openid email profile
```

Do not request Gmail, Drive, Calendar, Contacts, offline access, or refresh tokens unless you have a real need and understand the review/security implications.

## Environment Variables

Required:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `APP_ORIGIN`
- `SESSION_SECRET`

Optional:

- `ORG_EMAIL_DOMAIN`

`ORG_EMAIL_DOMAIN` can restrict who may create accounts, but it must never grant roles. Roles must come from D1.

## Database Policy

This skeleton includes schema only. It intentionally includes:

- no users
- no sessions
- no roles
- no organization content
- no profile data
- no images

Create your first admin manually, then build or adapt admin tools for ongoing management.

## Temporary Test Route Reminder

This scaffold intentionally does not include `/api/test/*` role-verification routes.

If you add temporary test nodes, test endpoints, debug dashboards, seeded admin bypasses, or demo-only routes while adapting this scaffold, delete them before deployment. Treat temporary access helpers as security liabilities once the app leaves local development.

## Minimum Security Checklist

Before calling a project based on this scaffold production-ready:

- Use `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` cookies in production.
- Store only hashed session tokens in D1.
- Validate Google ID tokens cryptographically with a reputable library.
- Use PKCE, `state`, and `nonce` for OAuth.
- Hash OAuth state before storing it.
- Use D1 prepared statements with bound parameters.
- Never trust roles from JSON, query parameters, localStorage, or hidden fields.
- Keep CSRF protection enabled for `POST`, `PUT`, `PATCH`, and `DELETE`.
- Delete temporary test endpoints before deployment.
- Keep secrets out of Git.
- Run `npm test` and `npm run build` before deployment.
- Add rate limiting or Turnstile if abuse becomes a problem.

## Publishing Note

Before publishing this skeleton publicly, replace placeholder names and review all dependencies, limits, and security assumptions against current Cloudflare and Google documentation.
