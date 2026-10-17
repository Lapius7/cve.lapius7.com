import type { Key } from '@/lib/i18n'

const STATUS: Record<string, Key> = {
  received: 'stNew', 'awaiting analysis': 'stAwait', 'undergoing analysis': 'stUnder', analyzed: 'stAnalyzed',
  modified: 'stMod', deferred: 'stDef', rejected: 'stRej',
}
const VERSION: Record<string, Key> = { affected: 'vsAffected', unaffected: 'vsUnaffected', unknown: 'vsUnknown' }
const REF: Record<string, Key> = {
  'third party advisory': 'refThird', 'vdb entry': 'refVdb', 'mailing list': 'refMail', exploit: 'refExploit', 'broken link': 'refBroken',
  'release notes': 'refRelease2', patch: 'refPatch2', 'us government resource': 'refGov2', mitigation: 'refMitig', 'vendor advisory': 'refVendor2',
  product: 'refProduct', 'issue tracking': 'refIssue', 'technical description': 'refTech', 'press/media coverage': 'refPress', 'permanent link': 'refPermLink',
  'not applicable': 'refNotApp', 'signature': 'refSigned', 'vulnerability report': 'refVuln', 'third party': 'refThirdparty',
}
type T = (k: Key) => string
export const statusLabel = (t: T, s: string) => (STATUS[s.toLowerCase()] ? t(STATUS[s.toLowerCase()]) : s)
export const versionLabel = (t: T, s: string) => (VERSION[s.toLowerCase()] ? t(VERSION[s.toLowerCase()]) : s)
export const refTagLabel = (t: T, s: string) => (REF[s.toLowerCase()] ? t(REF[s.toLowerCase()]) : s)
