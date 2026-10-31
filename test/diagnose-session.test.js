import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { zstdCompressSync } from 'node:zlib'

const script = fileURLToPath(new URL('../scripts/diagnose-session.mjs', import.meta.url))

/** One zstd frame per line, exactly like a DSH session log. */
function writeSession(lines) {
  const directory = mkdtempSync(join(tmpdir(), 'dsh-session-doctor-'))
  const file = join(directory, 'session.v4.jsonl.zstd')
  writeFileSync(file, Buffer.concat(lines.map((line) => zstdCompressSync(Buffer.from(`${line}\n`)))))
  return file
}

const message = (role, source, text) => JSON.stringify({
  type: `${role}/message`,
  seq: 1,
  data: { message: { role, source, content: [{ type: 'text', text }] } },
})

test('a clean session log passes', () => {
  const file = writeSession([
    '{"type":"session","version":4}',
    message('user', { kind: 'user' }, 'hi'),
    message('assistant', { kind: 'model' }, 'hello'),
  ])
  const run = spawnSync(process.execPath, [script, file], { encoding: 'utf8' })
  assert.equal(run.status, 0, run.stderr)
  assert.match(run.stdout, /OK: 1 session log/)
})

test('the retired plugin wrapper is reported with its plugin name', () => {
  const file = writeSession([
    '{"type":"session","version":4}',
    message('assistant', { kind: 'plugin', plugin: 'some-old-plugin' }, 'hello'),
  ])
  let failed
  try {
    execFileSync(process.execPath, [script, file], { encoding: 'utf8' })
  } catch (error) {
    failed = error
  }
  assert.ok(failed, 'script must exit non-zero')
  assert.equal(failed.status, 1)
  assert.match(String(failed.stdout), /INVALID/)
  assert.match(String(failed.stdout), /some-old-plugin/)
  assert.match(String(failed.stderr), /found 1 message/)
})

test('a missing source kind is reported too', () => {
  const file = writeSession([message('user', { plugin: 'x' }, 'hi')])
  const run = spawnSync(process.execPath, [script, file], { encoding: 'utf8' })
  assert.equal(run.status, 1)
  assert.match(run.stdout, /source\.kind is missing or empty/)
})
