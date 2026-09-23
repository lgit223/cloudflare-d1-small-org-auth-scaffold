import {
  AuthError,
  type AuthEnv,
  createCsrfToken,
  handleOAuthCallback,
  handleOAuthLogin,
  readSessionCookie,
  requireAdmin,
  requireCsrfProtection,
  requireUser,
  revokeCurrentSession,
  serializeExpiredSessionCookie,
  sessionCookieModeFromAppOrigin,
} from './auth.js'

type Env = AuthEnv & {
  ASSETS: Fetcher
}

const jsonHeaders = {
  'Cache-Control': 'no-store',
  'Content-Type': 'application/json; charset=utf-8',
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url)
    const cookieMode = sessionCookieModeFromAppOrigin(env.APP_ORIGIN)

    try {
      await requireCsrfProtection(request, env, cookieMode)

      if (url.pathname === '/auth/login' && request.method === 'GET') {
        return await handleOAuthLogin(env, ctx)
      }

      if (url.pathname === '/auth/callback' && request.method === 'GET') {
        return await handleOAuthCallback(request, env, ctx)
      }

      if (url.pathname === '/auth/logout' && request.method === 'POST') {
        await revokeCurrentSession(request, env.DB, cookieMode)
        return json({ ok: true }, 200, {
          'Set-Cookie': serializeExpiredSessionCookie(cookieMode),
        })
      }

      if (url.pathname === '/api/csrf-token' && request.method === 'GET') {
        await requireUser(request, env.DB, cookieMode)

        const sessionToken = readSessionCookie(request, cookieMode)
        if (!sessionToken) {
          throw new AuthError(401, 'authentication_required', 'Authentication is required.')
        }

        return json({ csrfToken: await createCsrfToken(sessionToken, env) })
      }

      if (url.pathname === '/api/me' && request.method === 'GET') {
        const user = await requireUser(request, env.DB, cookieMode)

        return json({
          displayName: user.displayName,
          id: user.id,
          roles: user.roles,
        })
      }

      if (url.pathname === '/api/admin/example' && request.method === 'GET') {
        const user = await requireUser(request, env.DB, cookieMode)
        requireAdmin(user)

        return json({ ok: true, message: 'Admin-only example route.' })
      }

      if (!url.pathname.startsWith('/api/') && !url.pathname.startsWith('/auth/')) {
        return env.ASSETS.fetch(request)
      }

      return json({ error: 'not_found', message: 'Route not found.' }, 404)
    } catch (error) {
      if (error instanceof AuthError) {
        return json({ error: error.code, message: error.message }, error.status)
      }

      console.error(
        JSON.stringify({
          event: 'request_failed',
          message: error instanceof Error ? error.message : 'Unknown Worker error',
          path: url.pathname,
        }),
      )

      return json({ error: 'internal_error', message: 'Unexpected server error.' }, 500)
    }
  },
} satisfies ExportedHandler<Env>

function json(data: unknown, status = 200, extraHeaders?: HeadersInit) {
  const headers = new Headers(jsonHeaders)

  if (extraHeaders) {
    new Headers(extraHeaders).forEach((value, key) => {
      headers.append(key, value)
    })
  }

  return new Response(JSON.stringify(data), {
    headers,
    status,
  })
}
