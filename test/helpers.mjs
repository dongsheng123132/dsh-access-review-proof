import { readFile } from 'node:fs/promises'
export async function fixture() { return JSON.parse(await readFile(new URL('../examples/closed.json', import.meta.url), 'utf8')) }
