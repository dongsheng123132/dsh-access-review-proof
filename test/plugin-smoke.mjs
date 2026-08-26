import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createDefinitions } from '../index.js'
const manifestJson = await readFile(new URL('../examples/closed.json', import.meta.url), 'utf8'); const tools = createDefinitions(); assert.deepEqual(tools.map(tool => tool.name), ['dsh_access_review_inspect', 'dsh_access_review_verify']); const result = await tools[0].execute({ manifestJson }); assert.equal(result.entitlementCount, 2); process.stdout.write(`${JSON.stringify({ ok: true, tools: tools.map(tool => tool.name), entitlementCount: result.entitlementCount })}\n`)
