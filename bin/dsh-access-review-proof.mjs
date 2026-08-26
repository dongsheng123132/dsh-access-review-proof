#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { evaluateAccessReviewManifest, inspectAccessReviewManifestJson } from '../lib/access-review-proof.mjs'
const [command, manifestPath] = process.argv.slice(2)
if (!['inspect', 'verify'].includes(command) || !manifestPath) { process.stderr.write('Usage: dsh-access-review-proof <inspect|verify> <manifest.json>\n'); process.exit(2) }
try { const manifestJson = await readFile(manifestPath, 'utf8'); const result = command === 'inspect' ? inspectAccessReviewManifestJson(manifestJson) : evaluateAccessReviewManifest(manifestJson); process.stdout.write(`${JSON.stringify(result)}\n`); process.exitCode = command === 'verify' && result.verdict !== 'access-review-closed' ? 1 : 0 } catch (error) { process.stdout.write(`${JSON.stringify({ ok: false, error: { code: error.code || 'ERROR' } })}\n`); process.exitCode = 2 }
