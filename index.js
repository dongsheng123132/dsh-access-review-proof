import { inspectAccessReviewManifestJson, verifyAccessReviewManifest } from './lib/access-review-proof.mjs'
export const name = 'dsh-access-review-proof'
export const inject = ['tools']
const renderJson = (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }]
const define = value => ({ ...value, output: { schema: {}, render: renderJson } })
export function createDefinitions(_ctx = {}, config = {}) {
  const workspaceRoot = config.workspaceRoot || process.cwd()
  return [
    define({ name: 'dsh_access_review_inspect', description: 'Inspect bounded hashes and counts from explicit entitlement-review evidence.', parameters: { type: 'object', required: ['manifestJson'], properties: { manifestJson: { type: 'string' } }, additionalProperties: false }, execute: async ({ manifestJson }) => inspectAccessReviewManifestJson(manifestJson) }),
    define({ name: 'dsh_access_review_verify', description: 'Verify supplied access-review closure and write a redacted content-addressed report.', parameters: { type: 'object', required: ['manifestPath', 'artifactDir'], properties: { manifestPath: { type: 'string' }, artifactDir: { type: 'string' } }, additionalProperties: false }, execute: async args => verifyAccessReviewManifest({ workspaceRoot, ...args }) })
  ]
}
export function apply(ctx, config = {}) { for (const definition of createDefinitions(ctx, config)) ctx.tools.register(definition) }
