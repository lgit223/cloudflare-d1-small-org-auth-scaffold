import assert from 'node:assert/strict'
import test from 'node:test'

import worker from '../.tmp-test/src/index.js'
import {
  createCsrfToken,
  developmentOAuthStateCookieName,
  developmentSessionCookieName,
  sha256Base64Url,
} from '../.tmp-test/src/auth.js'

test('GET /auth/login redirects to Google and stores only hashed state', async () => {
  const d1 = createFakeD1()
  const env = createEnv(d1.db)
  const ctx = createExecutionContext()
  const response = await worker.fetch(new Request('http://localhost:8787/auth/login'), env, ctx)

  await Promise.all(ctx.waitUntilPromises)

  assert.equal(response.status, 302)

  const location = new URL(response.headers.get('location'))
  assert.equal(location.hostname, 'accounts.google.com')
  assert.equal(location.pathname, '/o/oauth2/v2/auth')
  assert.equal(location.searchParams.get('response_type'), 'code')
  assert.equal(location.searchParams.get('scope'), 'openid email profile')
  assert.equal(location.searchParams.get('code_challenge_method'), 'S256')
  assert.ok(location.searchParams.get('state'))
  assert.ok(location.searchParams.get('nonce'))
  assert.ok(location.searchParams.get('code_challenge'))
  assert.notEqual(location.searchParams.get('state'), location.searchParams.get('nonce'))

  assert.equal(d1.store.transactions.length, 1)
  assert.equal(d1.store.transactions[0].stateHash, await sha256Base64Url(location.searchParams.get('state')))
  assert.notEqual(d1.store.transactions[0].stateHash, location.searchParams.get('state'))

  const setCookie = response.headers.get('set-cookie')
  assert.ok(setCookie.startsWith(`${developmentOAuthStateCookieName}=`))
  assert.match(setCookie, /HttpOnly/i)
  assert.match(setCookie, /SameSite=Lax/i)
  assert.doesNotMatch(setCookie, /Secure/i)
})

test('GET /auth/callback rejects missing code and state', async () => {
  const d1 = createFakeD1()
  const response = await worker.fetch(
    new Request('http://localhost:8787/auth/callback'),
    createEnv(d1.db),
    createExecutionContext(),
  )
  const body = await response.json()

  assert.equal(response.status, 400)
  assert.equal(body.error, 'invalid_oauth_callback')
})

test('GET /auth/callback rejects state mismatch before token exchange', async () => {
  const d1 = createFakeD1()
  const response = await worker.fetch(
    new Request('http://localhost:8787/auth/callback?code=test-code&state=state-a', {
      headers: {
        Cookie: `${developmentOAuthStateCookieName}=state-b`,
      },
    }),
    createEnv(d1.db),
    createExecutionContext(),
  )
  const body = await response.json()

  assert.equal(response.status, 400)
  assert.equal(body.error, 'invalid_oauth_state')
})

test('GET /auth/callback rejects unknown or reused state', async () => {
  const d1 = createFakeD1()
  const response = await worker.fetch(
    new Request('http://localhost:8787/auth/callback?code=test-code&state=state-a', {
      headers: {
        Cookie: `${developmentOAuthStateCookieName}=state-a`,
      },
    }),
    createEnv(d1.db),
    createExecutionContext(),
  )
  const body = await response.json()

  assert.equal(response.status, 400)
  assert.equal(body.error, 'invalid_oauth_state')
})

test('GET /api/me returns only safe user fields', async () => {
  const scenario = await createAuthenticatedScenario({ role: 'member' })
  const response = await requestPath(scenario, '/api/me')
  const body = await response.json()

  assert.equal(response.status, 200)
  assert.deepEqual(body, {
    displayName: 'Example User',
    id: 'user-1',
    roles: ['member'],
  })
  assert.equal('tokenHash' in body, false)
  assert.equal('email' in body, false)
})

test('admin example route uses server-loaded role checks', async () => {
  const applicantScenario = await createAuthenticatedScenario({ role: 'applicant' })
  const applicantResponse = await requestPath(applicantScenario, '/api/admin/example')
  const applicantBody = await applicantResponse.json()

  assert.equal(applicantResponse.status, 403)
  assert.equal(applicantBody.error, 'insufficient_role')

  const adminScenario = await createAuthenticatedScenario({ role: 'admin' })
  const adminResponse = await requestPath(adminScenario, '/api/admin/example')
  const adminBody = await adminResponse.json()

  assert.equal(adminResponse.status, 200)
  assert.equal(adminBody.ok, true)
})

test('POST /auth/logout requires CSRF and revokes the D1 session', async () => {
  const scenario = await createAuthenticatedScenario({ role: 'member' })
  const missingCsrfResponse = await requestPath(scenario, '/auth/logout', { method: 'POST' })
  const missingCsrfBody = await missingCsrfResponse.json()

  assert.equal(missingCsrfResponse.status, 403)
  assert.equal(missingCsrfBody.error, 'csrf_origin_invalid')
  assert.equal(scenario.d1.store.sessions[0].revokedAt, null)

  const csrfToken = await createCsrfToken(scenario.sessionToken, scenario.env)
  const response = await requestPath(scenario, '/auth/logout', {
    headers: {
      Origin: scenario.env.APP_ORIGIN,
      'X-CSRF-Token': csrfToken,
    },
    method: 'POST',
  })
  const body = await response.json()

  assert.equal(response.status, 200)
  assert.deepEqual(body, { ok: true })
  assert.ok(scenario.d1.store.sessions[0].revokedAt)
  assert.match(response.headers.get('set-cookie'), /Max-Age=0/i)
})

test('temporary test endpoints are not included in the scaffold', async () => {
  const scenario = await createAuthenticatedScenario({ role: 'admin' })
  const response = await requestPath(scenario, '/api/test/admin')
  const body = await response.json()

  assert.equal(response.status, 404)
  assert.equal(body.error, 'not_found')
})

async function createAuthenticatedScenario({ role }) {
  const sessionToken = 'test-session-token'
  const now = Math.floor(Date.now() / 1000)
  const d1 = createFakeD1({
    roles: [{ role, userId: 'user-1' }],
    sessions: [
      {
        createdAt: now,
        expiresAt: now + 3600,
        id: 'session-1',
        lastUsedAt: now,
        revokedAt: null,
        tokenHash: await sha256Base64Url(sessionToken),
        userId: 'user-1',
      },
    ],
    users: [
      {
        displayName: 'Example User',
        id: 'user-1',
        status: 'active',
      },
    ],
  })
  const env = createEnv(d1.db)

  return {
    d1,
    env,
    sessionToken,
  }
}

function requestPath(scenario, path, { headers = {}, method = 'GET' } = {}) {
  return worker.fetch(
    new Request(`http://localhost:8787${path}`, {
      headers: {
        Cookie: `${developmentSessionCookieName}=${encodeURIComponent(scenario.sessionToken)}`,
        ...headers,
      },
      method,
    }),
    scenario.env,
    createExecutionContext(),
  )
}

function createEnv(db) {
  return {
    APP_ORIGIN: 'http://localhost:8787',
    ASSETS: {
      fetch: async () => new Response('<h1>Example site</h1>', {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      }),
    },
    DB: db,
    GOOGLE_CLIENT_ID: 'example-client-id.apps.googleusercontent.com',
    GOOGLE_CLIENT_SECRET: 'example-client-secret',
    ORG_EMAIL_DOMAIN: '',
    SESSION_SECRET: 'test-session-secret-with-at-least-32-bytes',
  }
}

function createExecutionContext() {
  const waitUntilPromises = []

  return {
    waitUntil(promise) {
      waitUntilPromises.push(Promise.resolve(promise))
    },
    waitUntilPromises,
  }
}

function createFakeD1({ roles = [], sessions = [], transactions = [], users = [] } = {}) {
  const store = {
    roles: roles.map((role) => ({ ...role })),
    sessions: sessions.map((session) => ({ ...session })),
    transactions: transactions.map((transaction) => ({ ...transaction })),
    users: users.map((user) => ({ ...user })),
  }

  return {
    db: {
      prepare(sql) {
        return createFakePreparedStatement(sql, store)
      },
    },
    store,
  }
}

function createFakePreparedStatement(sql, store) {
  return {
    bind(...params) {
      return {
        async all() {
          if (/SELECT\s+role\s+FROM\s+user_roles/iu.test(sql)) {
            const [userId] = params

            return {
              results: store.roles
                .filter((role) => role.userId === userId)
                .map((role) => ({ role: role.role })),
              success: true,
            }
          }

          throw new Error(`Unhandled fake D1 all SQL: ${sql}`)
        },
        async first() {
          if (/FROM\s+oauth_transactions/iu.test(sql)) {
            const [stateHash] = params
            const transaction = store.transactions.find((item) => item.stateHash === stateHash)

            return transaction
              ? {
                  createdAt: transaction.createdAt,
                  expiresAt: transaction.expiresAt,
                  nonce: transaction.nonce,
                  pkceVerifier: transaction.pkceVerifier,
                }
              : null
          }

          if (/FROM\s+sessions/iu.test(sql) && /INNER\s+JOIN\s+users/iu.test(sql)) {
            const [tokenHash] = params
            const session = store.sessions.find((item) => item.tokenHash === tokenHash)

            if (!session) return null

            const user = store.users.find((item) => item.id === session.userId)

            return user
              ? {
                  createdAt: session.createdAt,
                  displayName: user.displayName,
                  expiresAt: session.expiresAt,
                  lastUsedAt: session.lastUsedAt,
                  revokedAt: session.revokedAt,
                  userId: user.id,
                  userStatus: user.status,
                }
              : null
          }

          throw new Error(`Unhandled fake D1 first SQL: ${sql}`)
        },
        async run() {
          if (/INSERT\s+INTO\s+oauth_transactions/iu.test(sql)) {
            store.transactions.push({
              createdAt: params[3],
              expiresAt: params[4],
              nonce: params[1],
              pkceVerifier: params[2],
              stateHash: params[0],
            })
          } else if (/DELETE\s+FROM\s+oauth_transactions\s+WHERE\s+expires_at\s+<=/iu.test(sql)) {
            const [now] = params
            store.transactions = store.transactions.filter((transaction) => transaction.expiresAt > now)
          } else if (/DELETE\s+FROM\s+oauth_transactions\s+WHERE\s+state_hash\s+=/iu.test(sql)) {
            const [stateHash] = params
            store.transactions = store.transactions.filter((transaction) => transaction.stateHash !== stateHash)
          } else if (/UPDATE\s+sessions\s+SET\s+last_used_at/iu.test(sql)) {
            const [lastUsedAt, tokenHash] = params
            const session = store.sessions.find((item) => item.tokenHash === tokenHash)

            if (session && session.revokedAt === null) {
              session.lastUsedAt = lastUsedAt
            }
          } else if (/UPDATE\s+sessions\s+SET\s+revoked_at/iu.test(sql)) {
            const [revokedAt, tokenHash] = params
            const session = store.sessions.find((item) => item.tokenHash === tokenHash)

            if (session && session.revokedAt === null) {
              session.revokedAt = revokedAt
            }
          } else {
            throw new Error(`Unhandled fake D1 run SQL: ${sql}`)
          }

          return {
            success: true,
          }
        },
      }
    },
  }
}
