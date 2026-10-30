import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { apply } from '../index.js'

/** Launch-cookie shape the Host mints: prefix plus a 43-character digest. */
function mintedCookie(index) {
  const name = 'dsh-auth-' + createHash('sha256').update(`cookie-${index}`).digest('base64url')
  const payload = Buffer.from(JSON.stringify({ issuedAt: 1_000_000 + index })).toString('base64url')
  return { name, value: `v1.${payload}.signature` }
}

/** A browser jar holding `count` launch cookies, as the handshake receives it. */
function jar(count) {
  return Array.from({ length: count }, (_, index) => {
    const { name, value } = mintedCookie(index)
    return `${name}=${value}`
  }).join('; ')
}

/**
 * Start a listener guarded by the plugin and return its origin.
 *
 * @param handler - route under test.
 * @returns `{ origin, close }` for the server.
 */
async function guarded(handler) {
  const server = createServer(handler)
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const origin = `http://127.0.0.1:${server.address().port}`

  apply({
    webServer: { server, getOrigin: () => origin },
    logger: { info() {}, warn() {} },
    effect: (fn) => {
      fn()
      return () => {}
    },
  })

  return {
    origin,
    close: () => new Promise((resolve) => server.close(resolve)),
  }
}

/** Send the 100-cookie jar and return the response's Set-Cookie lines. */
async function handshake(origin) {
  const response = await fetch(`${origin}/?token=launch-token`, {
    headers: { cookie: jar(100) },
    redirect: 'manual',
  })
  return response.headers.getSetCookie()
}

/** The four newest cookies are kept; every older one must be retired. */
function assertRetired(lines, extra = 0) {
  const deletions = lines.filter((line) => line.includes('Max-Age=0'))
  assert.equal(deletions.length, 96)
  assert.equal(lines.length, 96 + extra)
  for (const index of [96, 97, 98, 99]) {
    const { name } = mintedCookie(index)
    assert.ok(!deletions.some((line) => line.startsWith(`${name}=`)), `kept cookie ${name} was deleted`)
  }
}

test('object-form writeHead (the 303 handshake) keeps the deletions', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(303, {
      location: './',
      'set-cookie': 'dsh-auth-new=1; Path=/',
    })
    res.end()
  })
  try {
    const lines = await handshake(server.origin)
    assert.equal(lines.filter((line) => line.startsWith('dsh-auth-new=')).length, 1)
    assertRetired(lines, 1)
  } finally {
    await server.close()
  }
})

test('implicit writeHead (plain 200) keeps the deletions', async () => {
  const server = await guarded((req, res) => {
    res.end('ok')
  })
  try {
    assertRetired(await handshake(server.origin))
  } finally {
    await server.close()
  }
})

test('object-form writeHead without set-cookie keeps the deletions', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('ok')
  })
  try {
    assertRetired(await handshake(server.origin))
  } finally {
    await server.close()
  }
})

test('three-argument writeHead keeps the deletions', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(200, 'OK', { 'set-cookie': 'dsh-auth-new=1; Path=/' })
    res.end('ok')
  })
  try {
    assertRetired(await handshake(server.origin), 1)
  } finally {
    await server.close()
  }
})
