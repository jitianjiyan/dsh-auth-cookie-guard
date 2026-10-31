#!/usr/bin/env node
/**
 * Read-only diagnosis of a stored DSH session log.
 *
 * DSH session format V4 admits only producer-owned message sources: a message
 * whose `source.kind` is absent, empty, or the retired `"plugin"` wrapper makes
 * the whole log unreadable ("format v4 message requires a producer-owned source
 * kind"). A log gets such a message when it was written by an older DSH build
 * or by a plugin using the removed `agent.inject({ source: { kind: "plugin" } })`
 * form; this script names the file, the event, and the old plugin wrapper so the
 * culprit can be updated instead of guessing.
 *
 * This file is a diagnostic only. It never writes to the session directory.
 *
 * Usage:
 *   node scripts/diagnose-session.mjs "%USERPROFILE%\.dsh\sessions"
 *   node scripts/diagnose-session.mjs <session.v4.jsonl.zstd>
 *
 * Exit code 0 = no invalid source found, 1 = invalid sources found, 2 = bad usage.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { zstdDecompressSync } from 'node:zlib'

const ZSTD_MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd])
const target = process.argv[2]

if (target === undefined) {
  console.error('usage: node scripts/diagnose-session.mjs <session.v*.jsonl.zstd | sessions-dir>')
  process.exit(2)
}

const files = collect(target)
if (files.length === 0) {
  console.error(`no .jsonl.zstd session logs found under ${target}`)
  process.exit(2)
}

let invalid = 0
for (const file of files) {
  let lines
  try {
    lines = decode(readFileSync(file))
  } catch (error) {
    console.error(`[skip] ${file}: ${error.message}`)
    continue
  }
  for (const [index, line] of lines.entries()) {
    let event
    try {
      event = JSON.parse(line)
    } catch {
      continue
    }
    for (const message of messagesOf(event)) {
      const reason = reasonOf(message.source)
      if (reason === undefined) continue
      invalid += 1
      const plugin = message.source?.plugin
      console.log(`INVALID ${file}`)
      console.log(`  line ${index + 1}  type=${String(event.type)}  seq=${String(event.seq ?? '?')}  role=${String(message.role)}  id=${String(message.id ?? '?')}`)
      console.log(`  source: ${JSON.stringify(message.source)}`)
      console.log(`  reason: ${reason}${typeof plugin === 'string' ? ` (written as the retired plugin wrapper "${plugin}")` : ''}`)
      console.log(`  preview: ${preview(message)}`)
    }
  }
}

if (invalid === 0) {
  console.log(`OK: ${files.length} session log(s) contain no invalid message source`)
  process.exit(0)
}
console.error(`found ${invalid} message(s) with an invalid source across ${files.length} session log(s)`)
console.error('Repair: back up the affected session directory, then move it out of the sessions folder')
console.error('(or delete that session in the DSH UI). Updating the plugin/DSH build that wrote the')
console.error('old wrapper prevents the same message in new logs.')
process.exit(1)

/** @param {string} target @returns {string[]} */
function collect(target) {
  let info
  try {
    info = statSync(target)
  } catch {
    return []
  }
  if (info.isFile()) return target.endsWith('.jsonl.zstd') ? [target] : []
  const found = []
  for (const name of readdirSync(target)) {
    found.push(...collect(join(target, name)))
  }
  return found
}

/**
 * Decode a log whose zstd frames are concatenated one after another. Node's
 * zstd stream stops at the first frame, so frames are located by their magic
 * and decoded one at a time; a magic byte inside a frame is treated as a frame
 * boundary only when the truncated frame still decodes.
 *
 * @param {Buffer} buffer @returns {string[]}
 */
function decode(buffer) {
  const offsets = []
  let cursor = 0
  while ((cursor = buffer.indexOf(ZSTD_MAGIC, cursor)) !== -1) {
    offsets.push(cursor)
    cursor += ZSTD_MAGIC.length
  }
  const lines = []
  for (let index = 0; index < offsets.length; index += 1) {
    let decoded = false
    for (let next = index + 1; next <= offsets.length; next += 1) {
      const end = next < offsets.length ? offsets[next] : buffer.length
      try {
        lines.push(...zstdDecompressSync(buffer.subarray(offsets[index], end)).toString('utf8').split('\n'))
        index = next - 1
        decoded = true
        break
      } catch {
        // A zstd magic inside compressed data: extend to the next candidate.
      }
    }
    if (!decoded) throw new Error(`undecodable zstd frame at byte ${String(offsets[index])}`)
  }
  return lines.filter((line) => line.trim() !== '')
}

/** @param {unknown} value @returns {any} */
function messagesOf(value) {
  const found = []
  const visit = (node) => {
    if (node === null || typeof node !== 'object') return
    if (Array.isArray(node)) {
      for (const item of node) visit(item)
      return
    }
    if (typeof node.role === 'string' && node.source !== undefined) found.push(node)
    for (const key of Object.keys(node)) visit(node[key])
  }
  visit(value)
  return found
}

/** @param {unknown} source @returns {string | undefined} */
function reasonOf(source) {
  if (source === null || typeof source !== 'object') return 'message has no source object'
  const kind = source.kind
  if (typeof kind !== 'string' || kind.length === 0) return 'source.kind is missing or empty'
  if (kind === 'plugin') return 'source.kind is the retired "plugin" wrapper'
  return undefined
}

/** @param {any} message @returns {string} */
function preview(message) {
  const text = JSON.stringify(message.content ?? '')
  return text.length > 160 ? `${text.slice(0, 157)}...` : text
}
