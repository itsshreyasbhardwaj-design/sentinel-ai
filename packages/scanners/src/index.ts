export * from './types.js';
export * from './registry.js';
export * from './engine.js';
export * from './workspace.js';
export * from './zip.js';
export * from './exec.js';
export * from './ignore.js';

export { runRules, ruleAppliesTo, isTestPath } from './rules/engine.js';
export { SAST_RULES } from './rules/sast.js';
export { AI_SECURITY_RULES, AI_FRAMEWORK_MARKERS } from './rules/ai-security.js';
export { CONTAINER_RULES, IAC_RULES, CONFIG_RULES } from './rules/infrastructure.js';
export {
  SECRET_PATTERNS,
  shannonEntropy,
  assessGenericSecret,
  isLikelyPlaceholder,
  maskSecret,
} from './rules/secrets.js';

export * from './manifests/index.js';
export * from './advisories/semver.js';
export { BUNDLED_ADVISORIES, advisoriesFor, type Advisory } from './advisories/bundled.js';
export { queryOsv } from './advisories/osv.js';

export { generateSbom, toCycloneDxJson } from './native/sbom.js';
export { classifyLicense, normalizeLicenseId, type LicenseCategory } from './native/license.js';
export { detectAiApplication, type AiDetection } from './native/ai-security.js';
export { getDependencyInventory } from './native/inventory.js';
