import { createRemoteJWKSet, jwtVerify } from 'jose'

export const productionSessionCookieName = '__Host-club_session'
export const developmentSessionCookieName = 'club_session'
export const productionOAuthStateCookieName = '__Host-oauth_state'
export const developmentOAuthStateCookieName = 'club_oauth_state'
export const sessionTtlSeconds = 7 * 24 * 60 * 60
export const sessionIdleTimeoutSeconds = 15 * 60
export const oauthTransactionTtlSeconds = 10 * 60

export type Role = 'applicant' | 'member' | 'board' | 'admin'
export type SessionCookieMode = 'development' | 'production'

export type AuthEnv = {
  DB: D1Database
  APP_ORIGIN: string
  GOOGLE_CLIENT_ID: string
  GOOGLE_CLIENT_SECRET: string
  ORG_EMAIL_DOMAIN?: string
  SESSION_SECRET: string
}

export type AuthenticatedUser = {
  id: string
  displayName: string | null
  roles: Role[]
}

type SessionUserRow = {
  createdAt: number
  userId: string
  displayName: string | null
  userStatus: string
  expiresAt: number
  lastUsedAt: number | null
  revokedAt: number | null
}

type RoleRow = {
  role: string
}

type OAuthTransactionRow = {
  nonce: string
  pkceVerifier: string
  createdAt: number
  expiresAt: number
}

type GoogleProfile = {
  displayName: string | null
  email: string
  subject: string
}

type IdentityUserRow = {
  userId: string
  email: string
  displayName: string | null
  status: string
}

const googleAuthorizationEndpoint = 'https://accounts.google.com/o/oauth2/v2/auth'
const googleTokenEndpoint = 'https://oauth2.googleapis.com/token'
const googleIssuer = ['https://accounts.google.com', 'accounts.google.com']
const googleProvider = 'google'
const googleJwks = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'))
const safeMethods = new Set(['GET', 'HEAD', 'OPTIONS'])
const textEncoder = new TextEncoder()

export class AuthError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message)
  }
}

export async function handleOAuthLogin(env: AuthEnv, ctx?: ExecutionContext) {
  assertOAuthConfig(env)

  const now = currentUnixSeconds()
  const state = randomBase64Url(32)
  const nonce = randomBase64Url(32)
  const pkceVerifier = randomBase64Url(64)
  const pkceChallenge = await sha256Base64Url(pkceVerifier)
  const stateHash = await sha256Base64Url(state)
  const cookieMode = sessionCookieModeFromAppOrigin(env.APP_ORIGIN)

  const cleanup = cleanupExpiredOAuthTransactions(env.DB, now)
  if (ctx) {
    ctx.waitUntil(cleanup)
  } else {
    await cleanup
  }

  await env.DB
    .prepare(
      `INSERT INTO oauth_transactions
        (state_hash, nonce, pkce_verifier, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(stateHash, nonce, pkceVerifier, now, now + oauthTransactionTtlSeconds)
    .run()

  const authorizationUrl = new URL(googleAuthorizationEndpoint)
  authorizationUrl.search = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    code_challenge: pkceChallenge,
    code_challenge_method: 'S256',
    nonce,
    redirect_uri: oauthRedirectUri(env),
    response_type: 'code',
    scope: 'openid email profile',
    state,
  }).toString()

  return redirect(authorizationUrl.toString(), {
    'Set-Cookie': serializeOAuthStateCookie(state, cookieMode),
  })
}

export async function handleOAuthCallback(request: Request, env: AuthEnv, ctx?: ExecutionContext) {
  assertOAuthConfig(env)

  const url = new URL(request.url)
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')
  const cookieMode = sessionCookieModeFromAppOrigin(env.APP_ORIGIN)
  const cookieState = readCookie(request, oauthStateCookieName(cookieMode))

  if (!code || !state) {
    throw new AuthError(400, 'invalid_oauth_callback', 'OAuth callback is missing code or state.')
  }

  if (!cookieState || !(await fixedTimeEqual(state, cookieState))) {
    throw new AuthError(400, 'invalid_oauth_state', 'OAuth state does not match this browser session.')
  }

  const stateHash = await sha256Base64Url(state)
  const now = currentUnixSeconds()
  const transaction = await env.DB
    .prepare(
      `SELECT
        nonce,
        pkce_verifier AS pkceVerifier,
        created_at AS createdAt,
        expires_at AS expiresAt
      FROM oauth_transactions
      WHERE state_hash = ?`,
    )
    .bind(stateHash)
    .first<OAuthTransactionRow>()

  if (!transaction) {
    throw new AuthError(400, 'invalid_oauth_state', 'OAuth state is invalid or already used.')
  }

  await env.DB.prepare('DELETE FROM oauth_transactions WHERE state_hash = ?').bind(stateHash).run()

  const cleanup = cleanupExpiredOAuthTransactions(env.DB, now)
  if (ctx) {
    ctx.waitUntil(cleanup)
  } else {
    await cleanup
  }

  if (transaction.expiresAt <= now) {
    throw new AuthError(400, 'expired_oauth_state', 'OAuth login expired. Please sign in again.')
  }

  const idToken = await exchangeGoogleAuthorizationCode(env, code, transaction.pkceVerifier)
  const profile = await verifyGoogleIdToken(env, idToken, transaction.nonce)
  const user = await ensureGoogleApplicantIdentity(env.DB, profile, now)

  if (user.status !== 'active') {
    throw new AuthError(403, 'account_inactive', 'This account is not active.')
  }

  const sessionToken = await createUserSession(env.DB, user.userId, now)
  const headers = new Headers({
    'Cache-Control': 'no-store',
    Location: new URL('/', env.APP_ORIGIN).toString(),
  })

  headers.append('Set-Cookie', serializeSessionCookie(sessionToken, cookieMode))
  headers.append('Set-Cookie', serializeExpiredOAuthStateCookie(cookieMode))

  return new Response(null, {
    headers,
    status: 303,
  })
}

export async function requireUser(
  request: Request,
  db: D1Database,
  cookieMode: SessionCookieMode,
): Promise<AuthenticatedUser> {
  const sessionToken = readSessionCookie(request, cookieMode)

  if (!sessionToken) {
    throw new AuthError(401, 'authentication_required', 'Authentication is required.')
  }

  const tokenHash = await sha256Base64Url(sessionToken)
  const now = currentUnixSeconds()
  const session = await db
    .prepare(
      `SELECT
        sessions.created_at AS createdAt,
        users.id AS userId,
        users.display_name AS displayName,
        users.status AS userStatus,
        sessions.expires_at AS expiresAt,
        sessions.last_used_at AS lastUsedAt,
        sessions.revoked_at AS revokedAt
      FROM sessions
      INNER JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ?`,
    )
    .bind(tokenHash)
    .first<SessionUserRow>()

  if (!session) {
    throw new AuthError(401, 'invalid_session', 'Session is not valid.')
  }

  if (session.revokedAt !== null) {
    throw new AuthError(401, 'session_revoked', 'Session has been revoked.')
  }

  if (session.expiresAt <= now) {
    throw new AuthError(401, 'session_expired', 'Session has expired.')
  }

  const lastActivityAt = session.lastUsedAt ?? session.createdAt

  if (lastActivityAt <= now - sessionIdleTimeoutSeconds) {
    await db
      .prepare('UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE token_hash = ?')
      .bind(now, tokenHash)
      .run()

    throw new AuthError(401, 'session_idle_timeout', 'Session timed out.')
  }

  if (session.userStatus !== 'active') {
    throw new AuthError(403, 'account_inactive', 'This account is not active.')
  }

  await db
    .prepare('UPDATE sessions SET last_used_at = ? WHERE token_hash = ? AND revoked_at IS NULL')
    .bind(now, tokenHash)
    .run()

  const rolesResult = await db
    .prepare('SELECT role FROM user_roles WHERE user_id = ? ORDER BY role')
    .bind(session.userId)
    .all<RoleRow>()

  return {
    displayName: session.displayName,
    id: session.userId,
    roles: (rolesResult.results ?? []).map((row) => row.role).filter(isRole),
  }
}

export function requireRole(user: AuthenticatedUser, role: Role) {
  if (!user.roles.includes(role)) {
    throw new AuthError(403, 'insufficient_role', 'This account does not have access.')
  }
}

export function requireAnyRole(user: AuthenticatedUser, roles: Role[]) {
  if (!roles.some((role) => user.roles.includes(role))) {
    throw new AuthError(403, 'insufficient_role', 'This account does not have access.')
  }
}

export function requireAdmin(user: AuthenticatedUser) {
  requireRole(user, 'admin')
}

export async function requireCsrfProtection(
  request: Request,
  env: Pick<AuthEnv, 'APP_ORIGIN' | 'SESSION_SECRET'>,
  cookieMode: SessionCookieMode,
) {
  if (safeMethods.has(request.method.toUpperCase())) {
    return
  }

  const sessionToken = readSessionCookie(request, cookieMode)

  if (!sessionToken) {
    return
  }

  const origin = request.headers.get('Origin')
  if (origin !== env.APP_ORIGIN) {
    throw new AuthError(403, 'csrf_origin_invalid', 'Request origin is not allowed.')
  }

  const csrfToken = request.headers.get('X-CSRF-Token')
  if (!csrfToken) {
    throw new AuthError(403, 'csrf_token_missing', 'CSRF token is required.')
  }

  const expectedToken = await createCsrfToken(sessionToken, env)
  if (!(await fixedTimeEqual(csrfToken, expectedToken))) {
    throw new AuthError(403, 'csrf_token_invalid', 'CSRF token is not valid.')
  }
}

export async function createCsrfToken(
  sessionToken: string,
  env: Pick<AuthEnv, 'SESSION_SECRET'>,
) {
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) {
    throw new AuthError(500, 'csrf_not_configured', 'SESSION_SECRET is not configured.')
  }

  const sessionHash = await sha256Base64Url(sessionToken)
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(env.SESSION_SECRET),
    { hash: 'SHA-256', name: 'HMAC' },
    false,
    ['sign'],
  )
  const signature = await crypto.subtle.sign('HMAC', key, textEncoder.encode(`csrf:${sessionHash}`))

  return base64UrlEncode(new Uint8Array(signature))
}

export async function revokeCurrentSession(request: Request, db: D1Database, cookieMode: SessionCookieMode) {
  const sessionToken = readSessionCookie(request, cookieMode)

  if (!sessionToken) {
    return
  }

  const tokenHash = await sha256Base64Url(sessionToken)

  await db
    .prepare('UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE token_hash = ?')
    .bind(currentUnixSeconds(), tokenHash)
    .run()
}

export function serializeSessionCookie(token: string, cookieMode: SessionCookieMode) {
  return serializeCookie(sessionCookieName(cookieMode), token, sessionTtlSeconds, cookieMode)
}

export function serializeExpiredSessionCookie(cookieMode: SessionCookieMode) {
  return serializeCookie(sessionCookieName(cookieMode), '', 0, cookieMode)
}

export function serializeOAuthStateCookie(state: string, cookieMode: SessionCookieMode) {
  return serializeCookie(oauthStateCookieName(cookieMode), state, oauthTransactionTtlSeconds, cookieMode)
}

export function serializeExpiredOAuthStateCookie(cookieMode: SessionCookieMode) {
  return serializeCookie(oauthStateCookieName(cookieMode), '', 0, cookieMode)
}

export function sessionCookieModeFromAppOrigin(appOrigin: string | undefined): SessionCookieMode {
  if (!appOrigin) return 'production'

  try {
    const origin = new URL(appOrigin)

    if (origin.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)) {
      return 'development'
    }
  } catch {
    return 'production'
  }

  return 'production'
}

export function readSessionCookie(request: Request, cookieMode: SessionCookieMode) {
  return readCookie(request, sessionCookieName(cookieMode))
}

export function oauthStateCookieName(cookieMode: SessionCookieMode) {
  return cookieMode === 'production' ? productionOAuthStateCookieName : developmentOAuthStateCookieName
}

export async function sha256Base64Url(value: string) {
  return base64UrlEncode(await sha256Bytes(value))
}

export function currentUnixSeconds() {
  return Math.floor(Date.now() / 1000)
}

function assertOAuthConfig(env: AuthEnv) {
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.APP_ORIGIN) {
    throw new AuthError(500, 'oauth_not_configured', 'Google OAuth is not configured.')
  }
}

async function exchangeGoogleAuthorizationCode(env: AuthEnv, code: string, pkceVerifier: string) {
  const response = await fetch(googleTokenEndpoint, {
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      code,
      code_verifier: pkceVerifier,
      grant_type: 'authorization_code',
      redirect_uri: oauthRedirectUri(env),
    }),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    method: 'POST',
  })

  const payload = await response.json().catch(() => null) as { id_token?: unknown } | null

  if (!response.ok || typeof payload?.id_token !== 'string') {
    throw new AuthError(401, 'oauth_code_exchange_failed', 'Google authorization code exchange failed.')
  }

  return payload.id_token
}

async function verifyGoogleIdToken(env: AuthEnv, idToken: string, expectedNonce: string): Promise<GoogleProfile> {
  const { payload } = await jwtVerify(idToken, googleJwks, {
    audience: env.GOOGLE_CLIENT_ID,
    issuer: googleIssuer,
  })

  if (payload.nonce !== expectedNonce) {
    throw new AuthError(401, 'oauth_nonce_invalid', 'Google ID token nonce is not valid.')
  }

  if (typeof payload.sub !== 'string' || !payload.sub.trim()) {
    throw new AuthError(401, 'oauth_subject_missing', 'Google ID token subject is missing.')
  }

  if (typeof payload.email !== 'string' || !payload.email.trim()) {
    throw new AuthError(403, 'oauth_email_missing', 'Google account email is missing.')
  }

  if (payload.email_verified !== true) {
    throw new AuthError(403, 'oauth_email_unverified', 'Google account email is not verified.')
  }

  const email = payload.email.trim().toLowerCase()
  const allowedDomains = normalizeOrgEmailDomains(env.ORG_EMAIL_DOMAIN)

  if (allowedDomains.length > 0 && !emailMatchesAllowedDomain(email, allowedDomains)) {
    throw new AuthError(403, 'email_domain_not_allowed', 'This email domain is not allowed.')
  }

  return {
    displayName: typeof payload.name === 'string' && payload.name.trim() ? payload.name.trim() : null,
    email,
    subject: payload.sub.trim(),
  }
}

async function ensureGoogleApplicantIdentity(db: D1Database, profile: GoogleProfile, now: number) {
  const existingIdentity = await db
    .prepare(
      `SELECT
        users.id AS userId,
        users.email,
        users.display_name AS displayName,
        users.status
      FROM auth_identities
      INNER JOIN users ON users.id = auth_identities.user_id
      WHERE auth_identities.provider = ?
        AND auth_identities.provider_subject = ?`,
    )
    .bind(googleProvider, profile.subject)
    .first<IdentityUserRow>()

  if (existingIdentity) {
    await db
      .prepare(
        `UPDATE auth_identities
        SET provider_email = ?, updated_at = ?
        WHERE provider = ?
          AND provider_subject = ?`,
      )
      .bind(profile.email, now, googleProvider, profile.subject)
      .run()

    return existingIdentity
  }

  const existingUser = await db
    .prepare(
      `SELECT
        id AS userId,
        email,
        display_name AS displayName,
        status
      FROM users
      WHERE email = ?`,
    )
    .bind(profile.email)
    .first<IdentityUserRow>()

  if (existingUser) {
    await db
      .prepare(
        `INSERT INTO auth_identities
          (id, user_id, provider, provider_subject, provider_email, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(crypto.randomUUID(), existingUser.userId, googleProvider, profile.subject, profile.email, now, now)
      .run()

    return existingUser
  }

  const userId = crypto.randomUUID()

  await db
    .prepare(
      `INSERT INTO users
        (id, email, display_name, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(userId, profile.email, profile.displayName, 'active', now, now)
    .run()

  await db
    .prepare(
      `INSERT INTO auth_identities
        (id, user_id, provider, provider_subject, provider_email, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(crypto.randomUUID(), userId, googleProvider, profile.subject, profile.email, now, now)
    .run()

  await db.prepare('INSERT INTO user_roles (user_id, role) VALUES (?, ?)').bind(userId, 'applicant').run()

  return {
    displayName: profile.displayName,
    email: profile.email,
    status: 'active',
    userId,
  } satisfies IdentityUserRow
}

async function createUserSession(db: D1Database, userId: string, now: number) {
  const token = randomBase64Url(32)
  const tokenHash = await sha256Base64Url(token)

  await db
    .prepare(
      `INSERT INTO sessions
        (id, user_id, token_hash, created_at, expires_at, last_used_at)
      VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(crypto.randomUUID(), userId, tokenHash, now, now + sessionTtlSeconds, now)
    .run()

  return token
}

function cleanupExpiredOAuthTransactions(db: D1Database, now: number) {
  return db.prepare('DELETE FROM oauth_transactions WHERE expires_at <= ?').bind(now).run()
}

function oauthRedirectUri(env: Pick<AuthEnv, 'APP_ORIGIN'>) {
  return new URL('/auth/callback', env.APP_ORIGIN).toString()
}

function normalizeOrgEmailDomains(value: string | undefined) {
  return (value ?? '')
    .split(',')
    .map((domain) => domain.trim().toLowerCase().replace(/^@/u, ''))
    .filter(Boolean)
}

function emailMatchesAllowedDomain(email: string, allowedDomains: string[]) {
  const emailParts = email.toLowerCase().split('@')

  return emailParts.length === 2 && allowedDomains.includes(emailParts[1])
}

function sessionCookieName(cookieMode: SessionCookieMode) {
  return cookieMode === 'production' ? productionSessionCookieName : developmentSessionCookieName
}

function serializeCookie(name: string, value: string, maxAge: number, cookieMode: SessionCookieMode) {
  const attributes = [
    `${name}=${encodeURIComponent(value)}`,
    `Max-Age=${maxAge}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ]

  if (cookieMode === 'production') {
    attributes.push('Secure')
  }

  return attributes.join('; ')
}

function redirect(location: string, extraHeaders?: HeadersInit) {
  const headers = new Headers({
    'Cache-Control': 'no-store',
    Location: location,
  })

  if (extraHeaders) {
    new Headers(extraHeaders).forEach((value, key) => {
      headers.append(key, value)
    })
  }

  return new Response(null, {
    headers,
    status: 302,
  })
}

function readCookie(request: Request, name: string) {
  const cookieHeader = request.headers.get('Cookie')

  if (!cookieHeader) return null

  for (const cookiePart of cookieHeader.split(';')) {
    const [rawName, ...rawValueParts] = cookiePart.trim().split('=')

    if (rawName === name) {
      const rawValue = rawValueParts.join('=')

      try {
        return decodeURIComponent(rawValue)
      } catch {
        return rawValue
      }
    }
  }

  return null
}

function isRole(role: string): role is Role {
  return role === 'applicant' || role === 'member' || role === 'board' || role === 'admin'
}

function randomBase64Url(length: number) {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return base64UrlEncode(bytes)
}

async function fixedTimeEqual(first: string, second: string) {
  const [firstHash, secondHash] = await Promise.all([sha256Bytes(first), sha256Bytes(second)])
  let diff = 0

  for (let index = 0; index < firstHash.length; index += 1) {
    diff |= firstHash[index] ^ secondHash[index]
  }

  return diff === 0
}

async function sha256Bytes(value: string) {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value))
  return new Uint8Array(digest)
}

function base64UrlEncode(bytes: Uint8Array) {
  let binary = ''

  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '')
}
