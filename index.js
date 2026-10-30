/**
 * auth-cookie-guard — keep the local Host's launch cookies from locking a
 * profile out of the desktop welcome handshake.
 *
 * ## The failure this repairs
 *
 * The Host binds an OS-assigned port on every start, and the browser-session
 * cookie is named after that authority:
 * `dsh-auth-<base64url(sha256(host:port))>` (dsh-client-connection/lib/index.js:277,
 * :335-337). Browsers store cookies per host and never per port, so every start
 * leaves one more ~173-character cookie for `127.0.0.1` with a 30-day
 * `Max-Age`, and nothing ever removes one.
 *
 * The Host builds its listener without a header-budget override —
 * `createServer(listener)` at dsh-host-webserver/lib/index.js:412 — so Node's
 * default `maxHeaderSize` of 16384 bytes governs. Around the 71st start the
 * `Cookie` header alone is 16184 bytes; the next handshake appends one more
 * cookie and reaches 16411 bytes, Node answers `431`, the desktop client reads
 * that as `desktop welcome: Web authentication failed`, and the profile stays
 * locked out because the jar only grows: the welcome page is never reached to
 * prune it, and there is no other code path that removes cookies.
 *
 * ## What this plugin does
 *
 * 1. Raises the listener's header budget (`maxHeaderBytes`, 64 KiB by default).
 *    Node reads `server.maxHeaderSize` per connection, so assigning it on the
 *    live server takes effect immediately — including for the handshake that
 *    would otherwise be answered with 431.
 * 2. Retires stale launch cookies on every request. Minted names are
 *    `dsh-auth-<43 base64url characters>` and their payload carries
 *    `issuedAt`, which is enough to rank them without the signing secret.
 *    Everything older than the newest `keep` is deleted in the browser jar
 *    with `Max-Age=0`, so the jar shrinks at the first successful handshake
 *    instead of growing without bound.
 *
 * Neither half is sufficient alone, which is why both are installed: raising the
 * budget only postpones the wall (~350 starts instead of ~72), and pruning alone
 * can never run, because a connection rejected with 431 never reaches the
 * listener.
 *
 * ## What it deliberately does not do
 *
 * It never renames, re-signs, or rewrites a cookie it keeps, and it never
 * touches a cookie whose name is not the exact minted shape — a future format
 * change degrades to "budget raised, nothing retired" rather than to a broken
 * session. It also keeps the cookie belonging to the current authority even
 * when that cookie is older than `keep`, so the running instance cannot delete
 * the very cookie it is authenticating with.
 */

import { createHash } from 'node:crypto'

/** Loader display name. */
export const name = 'auth-cookie-guard'

/** The listener this plugin guards; the service is live before it applies. */
export const inject = ['webServer']

/** Prefix of the launch cookies minted by the Host. */
const PREFIX = 'dsh-auth-'

/** Exactly the minted shape: the prefix plus a sha256 digest in base64url. */
const MINTED = /^dsh-auth-[A-Za-z0-9_-]{43}$/

/** Defaults, overridable from the profile patch row. */
const DEFAULTS = {
  maxHeaderBytes: 64 * 1024,
  keep: 4,
}

/** Bounds that keep a misconfiguration from disabling either guard. */
const LIMITS = {
  maxHeaderBytes: [16 * 1024, 1024 * 1024],
  keep: [1, 64],
}

/** Attributes that delete a cookie for its exact host and path. */
const EXPIRATION = 'Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'

/** Cap per response so a huge jar cannot produce an unbounded reply. */
const MAX_RETIRE_PER_RESPONSE = 128

/**
 * Guard the local listener.
 *
 * @param ctx - plugin context; `webServer` is the live service.
 * @param config - optional `{ maxHeaderBytes, keep }` overrides.
 */
export function apply(ctx, config = {}) {
  const webServer = ctx.webServer
  const server = webServer?.server

  if (server === void 0) {
    ctx.logger?.warn('auth-cookie-guard: webServer has no listener yet, nothing to guard')
    return
  }

  const maxHeaderBytes = bounded(config.maxHeaderBytes, DEFAULTS.maxHeaderBytes, LIMITS.maxHeaderBytes)
  const keep = bounded(config.keep, DEFAULTS.keep, LIMITS.keep)

  // Node reads this per connection, so the value applies to connections that
  // have not been accepted yet — the handshake we are trying to rescue.
  const previous = server.maxHeaderSize
  server.maxHeaderSize = maxHeaderBytes

  // The cookie this process just minted is the newest one, but keeping it by
  // name also covers a clock that moved backwards between two starts. The name
  // is resolved per request exactly as the Host resolves it, so a page opened on
  // `localhost` instead of `127.0.0.1` still protects the cookie it is using.
  const protocol = originProtocol(webServer)
  const bound = cookieNameOf(protocol, boundHost(webServer))

  /**
   * Delete the launch cookies this instance will never authenticate on the
   * response that answers the current request.
   *
   * @param req - incoming request carrying the browser jar.
   * @param res - response being prepared; deletions are merged when it writes
   *   its headers, so an object-form `writeHead` cannot replace them.
   */
  function retire(req, res) {
    const header = req.headers.cookie
    if (typeof header !== 'string' || !header.includes(PREFIX)) return

    const entries = []
    for (const segment of header.split(';')) {
      const at = segment.indexOf('=')
      if (at === -1) continue
      const name = segment.slice(0, at).trim()
      if (!MINTED.test(name)) continue
      const claim = readClaim(segment.slice(at + 1).trim())
      entries.push({ name, issuedAt: claim?.issuedAt ?? 0 })
    }
    if (entries.length === 0) return

    const ranked = [...entries].sort((left, right) => right.issuedAt - left.issuedAt)
    const retained = new Set(ranked.slice(0, keep).map((entry) => entry.name))
    const current = cookieNameOf(protocol, req.headers.host) ?? bound
    if (current !== undefined) retained.add(current)

    const stale = entries.filter((entry) => !retained.has(entry.name))
    if (stale.length === 0) return

    const lines = stale
      .slice(0, MAX_RETIRE_PER_RESPONSE)
      .map((entry) => `${entry.name}=; ${EXPIRATION}`)
    armCookies(res, lines)
    ctx.logger?.info?.(
      `auth-cookie-guard: retired ${String(lines.length)} launch cookie(s), kept ${String(retained.size)}`,
    )
  }

  ctx.effect(() => {
    server.prependListener('request', retire)
    return () => {
      server.removeListener('request', retire)
      if (server.maxHeaderSize === maxHeaderBytes) server.maxHeaderSize = previous
    }
  })

  ctx.logger?.info?.(
    `auth-cookie-guard: listener header budget ${String(maxHeaderBytes)} bytes, keeping ${String(keep)} launch cookie(s)`,
  )
}

/**
 * Name an authority's cookie exactly as the Host does.
 *
 * `requestAudience` keeps the bare authority for plain HTTP and the full origin
 * for TLS, so the name follows the same rule.
 *
 * @param protocol - the listener's protocol, `'http:'` or `'https:'`.
 * @param host - the authority (`host:port`) from the request or the bind.
 * @returns the cookie name, or `undefined` when the authority is unreadable.
 */
function cookieNameOf(protocol, host) {
  if (typeof host !== 'string' || host === '') return undefined
  try {
    const url = new URL(`${protocol}//${host}`)
    const authority = protocol === 'https:' ? url.origin : url.host
    return PREFIX + createHash('sha256').update(authority).digest('base64url')
  } catch {
    return undefined
  }
}

/**
 * Read the authority the listener is bound to, as a fallback for requests that
 * carry no Host header.
 *
 * @param webServer - the live service, used only for its bound origin.
 * @returns `host:port`, or `undefined` when the origin is unreadable.
 */
function boundHost(webServer) {
  try {
    return new URL(webServer.getOrigin()).host
  } catch {
    return undefined
  }
}

/**
 * Read the protocol the listener actually serves, from its own origin.
 *
 * The cookie name keeps the bare authority for plain HTTP and the full origin
 * for TLS, so the protocol has to match the Host's view rather than a guess.
 *
 * @param webServer - the live service.
 * @returns `'http:'` or `'https:'`; plain HTTP when the origin is unreadable.
 */
function originProtocol(webServer) {
  try {
    return new URL(webServer.getOrigin()).protocol
  } catch {
    return 'http:'
  }
}

/**
 * Read the unverified payload of a minted cookie just far enough to rank it.
 *
 * The signature is not checked on purpose: this value is only used to decide
 * which of the caller's own cookies to drop, never to authenticate anything.
 *
 * @param value - the cookie value.
 * @returns `{ issuedAt }`, or `undefined` when the value is not a claim.
 */
function readClaim(value) {
  const parts = value.split('.')
  if (parts.length !== 3 || (parts[0] !== 'v1' && parts[0] !== 'v2')) return undefined
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
    if (payload === null || typeof payload !== 'object') return undefined
    const issuedAt = typeof payload.issuedAt === 'number' ? payload.issuedAt : 0
    return { issuedAt }
  } catch {
    return undefined
  }
}

/**
 * Symbol key holding a response's queued `Set-Cookie` deletions.
 *
 * @type {symbol}
 */
const COOKIES = Symbol('auth-cookie-guard.cookies')

/**
 * Queue `Set-Cookie` deletions until the response commits its headers.
 *
 * The welcome handshake answers with `res.writeHead(303, { 'set-cookie': … })`.
 * Node replaces every existing value of a header named in that object, so a
 * deletion appended beforehand is silently lost. Keeping the lines here and
 * merging them inside this response's own `writeHead` puts them on the same
 * response for all three call shapes — object, flat array, and no headers —
 * instead of depending on a later request to carry the cleanup.
 *
 * @param res - the response being prepared.
 * @param lines - cookie serializations to add.
 */
function armCookies(res, lines) {
  if (lines.length === 0) return
  const state = res[COOKIES] ?? (res[COOKIES] = { lines: [], armed: false })
  state.lines.push(...lines)
  if (state.armed) return
  state.armed = true

  const writeHead = res.writeHead
  res.writeHead = function (statusCode, statusMessage, headers) {
    const pending = state.lines
    let message
    if (typeof statusMessage === 'string') message = statusMessage
    else headers = statusMessage

    if (Array.isArray(headers)) {
      headers = [...headers, ...pending.flatMap((line) => ['set-cookie', line])]
    } else if (headers !== undefined && headers !== null) {
      const copy = {}
      let replaced = false
      for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === 'set-cookie') {
          copy['set-cookie'] = [...cookieValues(headers[key]), ...pending]
          replaced = true
        } else {
          copy[key] = headers[key]
        }
      }
      if (!replaced) copy['set-cookie'] = [...pending]
      headers = copy
    } else {
      res.setHeader('set-cookie', [...cookieValues(res.getHeader('set-cookie')), ...pending])
    }

    return message === undefined
      ? writeHead.call(res, statusCode, headers)
      : writeHead.call(res, statusCode, message, headers)
  }
}

/**
 * Normalize one header value to the array form `setHeader` expects.
 *
 * @param value - current `Set-Cookie` value, if any.
 * @returns the value as an array.
 */
function cookieValues(value) {
  if (value === undefined) return []
  return Array.isArray(value) ? value : [value]
}

/**
 * Clamp a configuration number, falling back when it is not a number.
 *
 * @param value - configured value.
 * @param fallback - value used when configuration is absent or invalid.
 * @param range - inclusive `[min, max]` bounds.
 * @returns a usable integer.
 */
function bounded(value, fallback, range) {
  const number = Number(value)
  if (value === undefined || value === null || !Number.isFinite(number)) return fallback
  return Math.min(range[1], Math.max(range[0], Math.trunc(number)))
}
