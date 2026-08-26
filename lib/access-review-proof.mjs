import { createHash } from 'node:crypto'
import { lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises'
import { isAbsolute, relative, resolve } from 'node:path'

const MAX_FILE = 4 * 1024 * 1024
const HEX = /^[a-f0-9]{64}$/
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/
const RISKS = new Set(['low', 'medium', 'high', 'critical'])
const DECISIONS = new Set(['keep', 'revoke'])
const STATES = new Set(['active', 'revoked'])
const SECRET_VALUE = /(?:bearer\s+[a-z0-9._-]{12,}|(?:sk|ghp|github_pat)_[a-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i
const stable = value => JSON.stringify(value, (_, child) => child && typeof child === 'object' && !Array.isArray(child) ? Object.fromEntries(Object.entries(child).sort(([a], [b]) => a.localeCompare(b))) : child)
export const sha256 = value => createHash('sha256').update(value).digest('hex')
const fail = (code, message) => Object.assign(new Error(message), { code })
const hash = (value, label) => { if (typeof value !== 'string' || !HEX.test(value)) throw fail('INVALID_MANIFEST', `${label} must be lowercase SHA-256`) }
const boundedId = (value, label) => { if (typeof value !== 'string' || !ID.test(value)) throw fail('INVALID_MANIFEST', `${label} must be a bounded public id`) }
const timestamp = (value, label) => { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw fail('INVALID_TIME', `${label} must be an ISO timestamp`); return parsed }
const integer = (value, label, min, max) => { if (!Number.isSafeInteger(value) || value < min || value > max) throw fail('INVALID_MANIFEST', `${label} invalid`) }

function rejectSecrets(value, path = '$') {
  if (typeof value === 'string' && SECRET_VALUE.test(value)) throw fail('SECRET_MATERIAL', `secret-shaped value rejected at ${path}`)
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value)) {
    if (/(?:secret|password|credential|api[_-]?key|private[_-]?key|authorization|cookie|token|raw|body|content|log|prompt|chat|email|account|display[_-]?name)$/i.test(key) && (typeof child === 'string' || typeof child === 'number')) throw fail('SECRET_MATERIAL', `sensitive field rejected at ${path}.${key}`)
    rejectSecrets(child, `${path}.${key}`)
  }
}

function uniqueHashList(values, label, min = 0, max = 10000) {
  if (!Array.isArray(values) || values.length < min || values.length > max) throw fail('INVALID_MANIFEST', `${label} invalid`)
  const set = new Set()
  for (const [index, value] of values.entries()) { hash(value, `${label}[${index}]`); if (set.has(value)) throw fail('INVALID_MANIFEST', `duplicate ${label}`); set.add(value) }
  return set
}

function parseManifest(input) {
  let manifest
  try { manifest = typeof input === 'string' ? JSON.parse(input) : structuredClone(input) } catch { throw fail('INVALID_MANIFEST', 'manifest must be JSON') }
  if (!manifest || manifest.schemaVersion !== 1) throw fail('INVALID_MANIFEST', 'schemaVersion 1 required')
  rejectSecrets(manifest); boundedId(manifest.proofId, 'proofId')
  const evaluationMs = timestamp(manifest.evaluationTime, 'evaluationTime')
  const review = manifest.review || {}
  for (const key of ['reviewIdHash', 'inventorySha256', 'policySha256']) hash(review[key], `review.${key}`)
  const startsMs = timestamp(review.startsAt, 'review.startsAt'); const dueMs = timestamp(review.dueAt, 'review.dueAt'); const completedMs = timestamp(review.completedAt, 'review.completedAt')
  const policy = manifest.policy || {}
  integer(policy.maxEvidenceAgeMs, 'policy.maxEvidenceAgeMs', 1000, 365 * 86400000); integer(policy.minDistinctObservers, 'policy.minDistinctObservers', 1, 100)
  if (policy.defaultOnMissing !== 'revoke') throw fail('INVALID_MANIFEST', 'policy.defaultOnMissing must be revoke')
  const requiredStages = policy.requiredStages || {}
  for (const risk of RISKS) integer(requiredStages[risk], `policy.requiredStages.${risk}`, 1, 4)
  const independentRisks = new Set(policy.independentReviewerRisks || [])
  if ([...independentRisks].some(risk => !RISKS.has(risk))) throw fail('INVALID_MANIFEST', 'independentReviewerRisks invalid')
  if (!Array.isArray(manifest.entitlements) || !manifest.entitlements.length || manifest.entitlements.length > 10000) throw fail('INVALID_MANIFEST', 'entitlements invalid')
  const entitlementIds = new Set()
  const entitlements = manifest.entitlements.map((row, index) => {
    for (const key of ['entitlementIdHash', 'principalHash', 'resourceHash', 'permissionHash', 'inventoryReceiptSha256']) hash(row?.[key], `entitlements[${index}].${key}`)
    if (!RISKS.has(row.risk)) throw fail('INVALID_MANIFEST', 'entitlement risk invalid')
    if (entitlementIds.has(row.entitlementIdHash)) throw fail('INVALID_MANIFEST', 'duplicate entitlement'); entitlementIds.add(row.entitlementIdHash)
    return row
  })
  if (!Array.isArray(manifest.decisions) || manifest.decisions.length > 40000) throw fail('INVALID_MANIFEST', 'decisions invalid')
  const decisionKeys = new Set()
  const decisions = manifest.decisions.map((row, index) => {
    for (const key of ['reviewIdHash', 'entitlementIdHash', 'reviewerHash', 'observerHash', 'decisionReceiptSha256']) hash(row?.[key], `decisions[${index}].${key}`)
    integer(row.stage, `decisions[${index}].stage`, 1, 4); if (!DECISIONS.has(row.decision)) throw fail('INVALID_MANIFEST', 'decision invalid')
    const key = `${row.entitlementIdHash}:${row.stage}`; if (decisionKeys.has(key)) throw fail('INVALID_MANIFEST', 'duplicate entitlement stage decision'); decisionKeys.add(key)
    return { ...row, decidedMs: timestamp(row.decidedAt, `decisions[${index}].decidedAt`) }
  })
  if (!Array.isArray(manifest.closures) || manifest.closures.length > 10000) throw fail('INVALID_MANIFEST', 'closures invalid')
  const closureIds = new Set()
  const closures = manifest.closures.map((row, index) => {
    for (const key of ['reviewIdHash', 'entitlementIdHash', 'applicationReceiptSha256', 'observerHash']) hash(row?.[key], `closures[${index}].${key}`)
    if (!STATES.has(row.resultingState)) throw fail('INVALID_MANIFEST', 'closure state invalid')
    if (closureIds.has(row.entitlementIdHash)) throw fail('INVALID_MANIFEST', 'duplicate closure'); closureIds.add(row.entitlementIdHash)
    return { ...row, observedMs: timestamp(row.observedAt, `closures[${index}].observedAt`) }
  })
  const snapshot = manifest.snapshot || {}
  for (const key of ['reviewIdHash', 'postReviewInventorySha256', 'observerHash']) hash(snapshot[key], `snapshot.${key}`)
  const activeIds = uniqueHashList(snapshot.activeEntitlementIdHashes, 'snapshot.activeEntitlementIdHashes'); const revokedIds = uniqueHashList(snapshot.revokedEntitlementIdHashes, 'snapshot.revokedEntitlementIdHashes')
  const snapshotMs = timestamp(snapshot.observedAt, 'snapshot.observedAt')
  return { manifest, evaluationMs, review, startsMs, dueMs, completedMs, policy, requiredStages, independentRisks, entitlements, entitlementIds, decisions, closures, snapshot, activeIds, revokedIds, snapshotMs }
}

export function inspectAccessReviewManifestJson(manifestJson) {
  const { manifest, review, entitlements, decisions, closures } = parseManifest(manifestJson)
  return { schemaVersion: 1, proofIdHash: sha256(manifest.proofId), reviewIdHash: review.reviewIdHash, inventorySha256: review.inventorySha256, policySha256: review.policySha256, entitlementCount: entitlements.length, decisionCount: decisions.length, closureCount: closures.length, changesAccess: false, queriesLiveIdentity: false }
}

export function evaluateAccessReviewManifest(manifestJson) {
  const { manifest, evaluationMs, review, startsMs, dueMs, completedMs, policy, requiredStages, independentRisks, entitlements, entitlementIds, decisions, closures, snapshot, activeIds, revokedIds, snapshotMs } = parseManifest(manifestJson)
  const entitlementById = new Map(entitlements.map(row => [row.entitlementIdHash, row]))
  const decisionsById = new Map(entitlements.map(row => [row.entitlementIdHash, []]))
  for (const row of decisions) decisionsById.get(row.entitlementIdHash)?.push(row)
  for (const rows of decisionsById.values()) rows.sort((a, b) => a.stage - b.stage)
  const closureById = new Map(closures.map(row => [row.entitlementIdHash, row]))
  const reviewChronologyValid = startsMs < dueMs && startsMs <= completedMs && completedMs <= dueMs && dueMs <= evaluationMs && snapshotMs >= completedMs && snapshotMs <= evaluationMs
  const inventoryComplete = decisions.every(row => entitlementIds.has(row.entitlementIdHash)) && closures.every(row => entitlementIds.has(row.entitlementIdHash))
  const decisionsComplete = entitlements.every(row => (decisionsById.get(row.entitlementIdHash)?.length || 0) === requiredStages[row.risk])
  const decisionChronologyValid = decisions.every(row => row.decidedMs >= startsMs && row.decidedMs <= completedMs) && entitlements.every(row => { const rows = decisionsById.get(row.entitlementIdHash) || []; return rows.every((item, index) => item.stage === index + 1 && (index === 0 || item.decidedMs >= rows[index - 1].decidedMs)) })
  const stagePolicySatisfied = entitlements.every(row => (decisionsById.get(row.entitlementIdHash) || []).every(item => item.stage <= requiredStages[row.risk]))
  const reviewerIndependenceSatisfied = entitlements.every(row => { const decisionsForRow = decisionsById.get(row.entitlementIdHash) || []; if (!independentRisks.has(row.risk)) return true; const reviewers = decisionsForRow.map(item => item.reviewerHash); return reviewers.every(value => value !== row.principalHash) && new Set(reviewers).size === reviewers.length })
  const bindingsSatisfied = decisions.every(row => row.reviewIdHash === review.reviewIdHash) && closures.every(row => row.reviewIdHash === review.reviewIdHash) && snapshot.reviewIdHash === review.reviewIdHash
  const closureComplete = closures.length === entitlements.length && entitlements.every(row => closureById.has(row.entitlementIdHash))
  const closureChronologyValid = closures.every(row => row.observedMs >= completedMs && row.observedMs <= snapshotMs)
  const closureMatchesDecisions = entitlements.every(row => { const decisionRows = decisionsById.get(row.entitlementIdHash) || []; const finalDecision = decisionRows.at(-1)?.decision || policy.defaultOnMissing; const closure = closureById.get(row.entitlementIdHash); return closure && closure.resultingState === (finalDecision === 'keep' ? 'active' : 'revoked') && (finalDecision !== 'revoke' || closure.applicationReceiptSha256 !== '0'.repeat(64)) })
  const expectedActive = new Set(closures.filter(row => row.resultingState === 'active').map(row => row.entitlementIdHash)); const expectedRevoked = new Set(closures.filter(row => row.resultingState === 'revoked').map(row => row.entitlementIdHash))
  const snapshotMatchesClosure = activeIds.size + revokedIds.size === entitlementIds.size && [...activeIds].every(id => expectedActive.has(id)) && [...revokedIds].every(id => expectedRevoked.has(id)) && [...entitlementIds].every(id => activeIds.has(id) !== revokedIds.has(id))
  const distinctObserverCount = new Set([...decisions.map(row => row.observerHash), ...closures.map(row => row.observerHash), snapshot.observerHash]).size
  const observerThresholdSatisfied = distinctObserverCount >= policy.minDistinctObservers
  const evidenceFresh = evaluationMs - snapshotMs >= 0 && evaluationMs - snapshotMs <= policy.maxEvidenceAgeMs
  const checks = { reviewChronologyValid, inventoryComplete, decisionsComplete, decisionChronologyValid, stagePolicySatisfied, reviewerIndependenceSatisfied, bindingsSatisfied, closureComplete, closureChronologyValid, closureMatchesDecisions, snapshotMatchesClosure, observerThresholdSatisfied, evidenceFresh }
  const verified = Object.values(checks).every(Boolean)
  return { schemaVersion: 1, verdict: verified ? 'access-review-closed' : 'not-closed', proofIdHash: sha256(manifest.proofId), reviewIdHash: review.reviewIdHash, inventorySha256: review.inventorySha256, policySha256: review.policySha256, postReviewInventorySha256: snapshot.postReviewInventorySha256, checks, disclosures: { entitlementCount: entitlements.length, decisionCount: decisions.length, closureCount: closures.length, activeCount: activeIds.size, revokedCount: revokedIds.size, distinctObserverCount }, changesAccess: false, approvesAccess: false, revokesAccess: false, authenticatesReceipts: false, queriesLiveIdentity: false, provesInventoryExhaustive: false, provesAbsenceOfUndeclaredEntitlements: false, destructiveActions: false }
}

async function safeManifest(root, manifestPath) {
  if (typeof manifestPath !== 'string' || !manifestPath || manifestPath.length > 512 || isAbsolute(manifestPath)) throw fail('PATH_ESCAPE', 'manifestPath must be workspace-relative')
  const absolute = resolve(root, manifestPath); const rel = relative(root, absolute); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'manifestPath escapes workspaceRoot')
  let cursor = root; let stat; const parts = rel.split(/[\\/]/)
  for (const [index, part] of parts.entries()) { cursor = resolve(cursor, part); stat = await lstat(cursor).catch(() => { throw fail('MISSING_MANIFEST', 'manifest missing') }); if (stat.isSymbolicLink()) throw fail('UNSAFE_MANIFEST', 'manifest path contains symlink'); if (index < parts.length - 1 && !stat.isDirectory()) throw fail('UNSAFE_MANIFEST', 'manifest parent invalid') }
  if (!stat.isFile() || stat.size > MAX_FILE) throw fail('UNSAFE_MANIFEST', 'manifest must be a regular file no larger than 4 MiB')
  const realRel = relative(await realpath(root), await realpath(absolute)); if (realRel.startsWith('..') || isAbsolute(realRel)) throw fail('PATH_ESCAPE', 'real manifest escapes workspaceRoot')
  return readFile(absolute, 'utf8')
}

async function safeArtifactDir(root, artifactDir) {
  if (typeof artifactDir !== 'string' || !artifactDir || artifactDir.length > 512 || isAbsolute(artifactDir)) throw fail('PATH_ESCAPE', 'artifactDir must be workspace-relative')
  const dir = resolve(root, artifactDir); const rel = relative(root, dir); if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw fail('PATH_ESCAPE', 'artifactDir escapes workspaceRoot')
  let cursor = root
  for (const part of rel.split(/[\\/]/)) { cursor = resolve(cursor, part); try { const stat = await lstat(cursor); if (stat.isSymbolicLink() || !stat.isDirectory()) throw fail('UNSAFE_ARTIFACT_DIR', 'artifactDir components must be real directories') } catch (error) { if (error.code !== 'ENOENT') throw error; await mkdir(cursor) } }
  return dir
}

export async function verifyAccessReviewManifest({ workspaceRoot, manifestPath, artifactDir }) {
  const root = resolve(workspaceRoot); const report = evaluateAccessReviewManifest(await safeManifest(root, manifestPath)); const bytes = Buffer.from(`${stable(report)}\n`); const digest = sha256(bytes); const dir = await safeArtifactDir(root, artifactDir); const output = resolve(dir, `access-review-proof-${digest}.json`)
  try { await writeFile(output, bytes, { flag: 'wx' }) } catch (error) { if (error.code !== 'EEXIST') throw error; if (!(await readFile(output)).equals(bytes)) throw fail('ARTIFACT_DIVERGED', 'content-addressed artifact diverged') }
  const readBack = await readFile(output); if (sha256(readBack) !== digest) throw fail('READBACK_FAILED', 'artifact read-back failed')
  return { ...report, artifact: { path: relative(root, output).replaceAll('\\', '/'), sha256: digest, verifiedByReadBack: true } }
}
