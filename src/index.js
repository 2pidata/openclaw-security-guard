/**
 * 🛡️ OpenClaw Security Guard
 * 
 * Complete security layer for OpenClaw
 * CLI Scanner + Live Dashboard
 * 
 * NO TELEMETRY - 100% PRIVATE
 * 
 * @author Miloud Belarebia
 * @license MIT
 * @see https://github.com/2pidata/openclaw-security-guard
 * @see https://2pidata.com
 */

// Scanners
export { SecretsScanner } from './scanners/secrets-scanner.js';
export { ConfigAuditor } from './scanners/config-auditor.js';
export { PromptInjectionDetector } from './scanners/prompt-injection-detector.js';
export { DependencyScanner } from './scanners/dependency-scanner.js';
export { McpServerAuditor } from './scanners/mcp-server-auditor.js';
export { InfraScanner } from './scanners/infra-scanner.js';

// Hardening
export { AutoHardener } from './hardening/auto-hardener.js';

// Dashboard
export { startDashboard } from './dashboard/server.js';

// Utils
export { loadConfig, getOpenClawPath, formatDuration } from './utils/helpers.js';
export { i18n } from './utils/i18n.js';
export {
  sanitizePath,
  isPathSafe,
  escapeHtml,
  escapeJson,
  isSafeUrl,
  isAllowedOrigin
} from './utils/validation.js';

// Metadata
export const VERSION = '1.0.0';
export const AUTHOR = 'Miloud Belarebia';
export const WEBSITE = 'https://2pidata.com';
export const REPOSITORY = 'https://github.com/2pidata/openclaw-security-guard';

// Privacy statement
export const PRIVACY = {
  telemetry: false,
  tracking: false,
  externalRequests: false,
  dataCollection: false
};

/**
 * Quick audit for programmatic use
 * 
 * @example
 * ```javascript
 * import { quickAudit } from 'openclaw-security-guard';
 * const results = await quickAudit('~/.openclaw');
 * console.log(results.securityScore);
 * ```
 */
export async function quickAudit(basePath, options = {}) {
  const results = {
    timestamp: new Date().toISOString(),
    version: VERSION,
    path: basePath,
    scanners: {},
    summary: { critical: 0, high: 0, medium: 0, low: 0 }
  };
  
  const { SecretsScanner } = await import('./scanners/secrets-scanner.js');
  const { ConfigAuditor } = await import('./scanners/config-auditor.js');
  const { PromptInjectionDetector } = await import('./scanners/prompt-injection-detector.js');
  
  const scanners = [
    ['secrets', SecretsScanner],
    ['config', ConfigAuditor],
    ['prompts', PromptInjectionDetector]
  ];
  
  for (const [name, Scanner] of scanners) {
    try {
      const scanner = new Scanner(options.config || {});
      const result = await scanner.scan(basePath, options);
      results.scanners[name] = result;
      results.summary.critical += result.summary?.critical || 0;
      results.summary.high += result.summary?.high || 0;
      results.summary.medium += result.summary?.medium || 0;
      results.summary.low += result.summary?.low || 0;
    } catch (error) {
      results.scanners[name] = { error: error.message };
    }
  }
  
  // Calculate score
  let score = 100;
  score -= results.summary.critical * 10;
  score -= results.summary.high * 5;
  score -= results.summary.medium * 2;
  results.securityScore = Math.max(0, Math.min(100, score));
  
  return results;
}

/**
 * Check a single message for prompt injection
 * 
 * @example
 * ```javascript
 * import { checkPromptInjection } from 'openclaw-security-guard';
 * const result = checkPromptInjection('ignore all previous instructions');
 * if (!result.safe) console.log('Injection detected!');
 * ```
 */
export async function checkPromptInjection(message, options = {}) {
  const { PromptInjectionDetector } = await import('./scanners/prompt-injection-detector.js');
  const detector = new PromptInjectionDetector(options.config || {});
  return detector.checkMessage(message);
}

export default {
  VERSION,
  AUTHOR,
  WEBSITE,
  PRIVACY,
  quickAudit,
  checkPromptInjection
};
