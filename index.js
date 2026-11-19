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
 *    `dsh-auth-<43 base64url characters>`; browsers list their jar oldest
 *    first (RFC 6265 section 5.4) and every launch cookie uses `Path=/`, so
 *    the tail of the header is the newest set. Everything except the newest
 *    `keep` is deleted in the browser jar with `Max-Age=0`, so the jar shrinks
 *    at the first successful handshake instead of growing without bound.
 *
 * It never decodes a cookie value: only the name is needed to rank the jar,
 * and the value is the signed session payload (`authority`, `issuedAt`,
 * `expiresAt`). The guard therefore cannot read, log, or act on login state.
 *
 * Neither half is sufficient alone, which is why both are installed: raising the
 * budget only postpones the wall (~350 starts instead of ~72), and pruning alone
 * can never run, because a connection rejected with 431 never reaches the
 * listener.
 *
 * ## What it deliberately does not do
 *
 * It never decodes a cookie value, renames, re-signs, or rewrites a cookie it
 * keeps, and it never touches a cookie whose name is not the exact minted
 * shape — a future format change degrades to "budget raised, nothing retired"
 * rather than to a broken session. It also keeps the cookie belonging to the
 * current authority even when that cookie is not among the newest `keep`, so
 * the running instance cannot delete the very cookie it is authenticating with.
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

/** Length implied by `MINTED`; checked first so the regex only sees candidates. */
const MINTED_LENGTH = PREFIX.length + 43

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

/**
 * Cap per response so a huge jar cannot produce an unbounded reply.
 *
 * `dsh-auth-` plus 43 digest characters is the only name shape accepted, so
 * one deletion line is ~125 bytes on the wire; 96 of them stay near 12 KiB.
 * That clears the 16 KiB default response-header budget of Node HTTP clients
 * (a 128-line reply made `fetch` fail to decode the handshake) and is far
 * below what browsers accept. A jar larger than this drains across later
 * requests instead of risking one oversized response.
 */
const MAX_RETIRE_PER_RESPONSE = 96

/**
 * Symbol key holding a response's queued `Set-Cookie` deletions.
 *
 * @type {symbol}
 */
const COOKIES = Symbol('auth-cookie-guard.cookies')

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
  // Only raise: a Host that already allows a larger budget keeps it.
  const applied = Math.max(previous ?? 0, maxHeaderBytes)
  server.maxHeaderSize = applied

  // Read the listener's origin once: the protocol names request cookies and
  // the bound authority is the fallback when a request carries no Host.
  const { protocol, bound } = listenerIdentity(webServer)

  // Requests normally repeat one authority, so resolve its digest once per
  // change instead of once per request. The name is resolved per request
  // exactly as the Host resolves it, so a page opened on `localhost` instead of
  // `127.0.0.1` still protects the cookie it is using.
  let lastHost
  let lastName
  function currentCookie(host) {
    if (host !== lastHost) {
      lastHost = host
      lastName = cookieNameOf(protocol, host)
    }
    return lastName
  }

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

    // One pass over the header: `seen` holds each minted name once in browser
    // order, `newest` the raw tail, which is what "newest keep" means.
    const seen = new Set()
    const newest = []
    let start = 0
    do {
      let stop = header.indexOf(';', start)
      if (stop === -1) stop = header.length
      // Scan this segment only: searching from `start` to the end of the header
      // for every empty segment would make a `;`-heavy header quadratic.
      let at = -1
      for (let index = start; index < stop; index += 1) {
        if (header.charCodeAt(index) === 61) {
          at = index
          break
        }
      }
      if (at !== -1) {
        const name = header.slice(start, at).trim()
        if (name.length === MINTED_LENGTH && MINTED.test(name)) {
          seen.add(name)
          newest.push(name)
          if (newest.length > keep) newest.shift()
        }
      }
      start = stop + 1
    } while (start < header.length)
    if (seen.size === 0) return

    // Browsers emit the jar oldest first (RFC 6265 section 5.4), so the tail
    // holds the newest launches; the current authority is kept by name even
    // when it is not in that tail.
    const retained = new Set(newest)
    const current = currentCookie(req.headers.host) ?? bound
    if (current !== undefined) retained.add(current)

    const lines = []
    for (const name of seen) {
      if (retained.has(name)) continue
      lines.push(`${name}=; ${EXPIRATION}`)
      if (lines.length === MAX_RETIRE_PER_RESPONSE) break
    }
    if (lines.length === 0) return

    armCookies(res, lines)
    ctx.logger?.info?.(
      `auth-cookie-guard: retired ${String(lines.length)} launch cookie(s), kept ${String(retained.size)}`,
    )
  }

  ctx.effect(() => {
    server.prependListener('request', retire)
    return () => {
      server.removeListener('request', retire)
      if (server.maxHeaderSize === applied) server.maxHeaderSize = previous
    }
  })

  ctx.logger?.info?.(
    `auth-cookie-guard: listener header budget ${String(applied)} bytes, keeping ${String(keep)} launch cookie(s)`,
  )
}

/**
 * Read the listener's protocol and the cookie name of its bound authority.
 *
 * @param webServer - the live service.
 * @returns `{ protocol, bound }`; plain HTTP and no fallback name when the
 *   origin is unreadable.
 */
function listenerIdentity(webServer) {
  try {
    const url = new URL(webServer.getOrigin())
    if (url.host === '') return { protocol: url.protocol, bound: undefined }
    const authority = url.protocol === 'https:' ? url.origin : url.host
    return {
      protocol: url.protocol,
      bound: PREFIX + createHash('sha256').update(authority).digest('base64url'),
    }
  } catch {
    return { protocol: 'http:', bound: undefined }
  }
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
 * Queue `Set-Cookie` deletions until the response commits its headers.
 *
 * The welcome handshake answers with `res.writeHead(303, { 'set-cookie': … })`.
 * Node replaces every existing value of a header named in that object, so a
 * deletion appended beforehand is silently lost. Keeping the lines here and
 * merging them inside this response's own `writeHead` puts them on the same
 * response for all call shapes — object, flat array, and no headers — instead
 * of depending on a later request to carry the cleanup.
 *
 * @param res - the response being prepared.
 * @param lines - cookie serializations to add.
 */
function armCookies(res, lines) {
  const state = res[COOKIES] ?? (res[COOKIES] = { lines: [], armed: false })
  for (const line of lines) state.lines.push(line)
  if (state.armed) return
  state.armed = true

  const writeHead = res.writeHead
  res.writeHead = function (statusCode, statusMessage, headers) {
    let message
    if (typeof statusMessage === 'string') message = statusMessage
    else headers = statusMessage

    const pending = state.lines
    if (Array.isArray(headers)) {
      const merged = headers.slice()
      for (const line of pending) merged.push('set-cookie', line)
      headers = merged
    } else if (headers !== undefined && headers !== null) {
      const copy = {}
      const cookies = []
      for (const key of Object.keys(headers)) {
        const value = headers[key]
        if (key.toLowerCase() !== 'set-cookie') copy[key] = value
        else if (Array.isArray(value)) for (const item of value) cookies.push(item)
        else if (value !== undefined) cookies.push(value)
      }
      for (const line of pending) cookies.push(line)
      copy['set-cookie'] = cookies
      headers = copy
    } else {
      const existing = res.getHeader('set-cookie')
      const cookies = existing === undefined
        ? []
        : Array.isArray(existing)
          ? existing.slice()
          : [existing]
      for (const line of pending) cookies.push(line)
      res.setHeader('set-cookie', cookies)
    }

    return message === undefined
      ? writeHead.call(res, statusCode, headers)
      : writeHead.call(res, statusCode, message, headers)
  }
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
