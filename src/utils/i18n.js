/**
 * Internationalization (i18n)
 *
 * Support for English, French, and Arabic
 */

const translations = {
  en: {
    scanning: 'Scanning',
    secretsScan: 'Secrets Scan',
    configAudit: 'Configuration Audit',
    promptInjectionScan: 'Prompt Injection Scan',
    dependencyScan: 'Dependency Scan',
    mcpServerAudit: 'MCP Server Audit',
    summary: 'SUMMARY',
    duration: 'Duration',
    actionRequired: 'ACTION REQUIRED',
    reviewRecommended: 'REVIEW RECOMMENDED',
    allClear: 'ALL CLEAR',
    noIssuesFound: 'No security issues found. Great job!',
    runFix: 'Run fix command',
    reportSaved: 'Report saved',
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    infraScan: 'Infrastructure Scan',
    networkScan: 'Network Security',
    sshScan: 'SSH Access Control',
    systemScan: 'System Hardening',
    tlsScan: 'TLS / Certificates',
    resourceScan: 'Resource Security'
  },

  fr: {
    scanning: 'Analyse en cours',
    secretsScan: 'Scan des secrets',
    configAudit: 'Audit de configuration',
    promptInjectionScan: 'D\u00e9tection d\'injection de prompts',
    dependencyScan: 'Scan des d\u00e9pendances',
    mcpServerAudit: 'Audit des serveurs MCP',
    summary: 'R\u00c9SUM\u00c9',
    duration: 'Dur\u00e9e',
    actionRequired: 'ACTION REQUISE',
    reviewRecommended: 'R\u00c9VISION RECOMMAND\u00c9E',
    allClear: 'TOUT EST OK',
    noIssuesFound: 'Aucun probl\u00e8me de s\u00e9curit\u00e9 d\u00e9tect\u00e9. Bravo !',
    runFix: 'Ex\u00e9cuter la commande de correction',
    reportSaved: 'Rapport sauvegard\u00e9',
    critical: 'Critique',
    high: '\u00c9lev\u00e9',
    medium: 'Moyen',
    low: 'Faible',
    infraScan: 'Scan d\'infrastructure',
    networkScan: 'S\u00e9curit\u00e9 r\u00e9seau',
    sshScan: 'Contr\u00f4le d\'acc\u00e8s SSH',
    systemScan: 'Durcissement syst\u00e8me',
    tlsScan: 'TLS / Certificats',
    resourceScan: 'S\u00e9curit\u00e9 des ressources'
  },

  ar: {
    scanning: '\u062c\u0627\u0631\u064a \u0627\u0644\u0641\u062d\u0635',
    secretsScan: '\u0641\u062d\u0635 \u0627\u0644\u0623\u0633\u0631\u0627\u0631',
    configAudit: '\u062a\u062f\u0642\u064a\u0642 \u0627\u0644\u0625\u0639\u062f\u0627\u062f\u0627\u062a',
    promptInjectionScan: '\u0643\u0634\u0641 \u062d\u0642\u0646 \u0627\u0644\u0623\u0648\u0627\u0645\u0631',
    dependencyScan: '\u0641\u062d\u0635 \u0627\u0644\u062a\u0628\u0639\u064a\u0627\u062a',
    mcpServerAudit: '\u062a\u062f\u0642\u064a\u0642 \u062e\u0648\u0627\u062f\u0645 MCP',
    summary: '\u0627\u0644\u0645\u0644\u062e\u0635',
    duration: '\u0627\u0644\u0645\u062f\u0629',
    actionRequired: '\u0625\u062c\u0631\u0627\u0621 \u0645\u0637\u0644\u0648\u0628',
    reviewRecommended: '\u064a\u0646\u0635\u062d \u0628\u0627\u0644\u0645\u0631\u0627\u062c\u0639\u0629',
    allClear: '\u0643\u0644 \u0634\u064a\u0621 \u0639\u0644\u0649 \u0645\u0627 \u064a\u0631\u0627\u0645',
    noIssuesFound: '\u0644\u0645 \u064a\u062a\u0645 \u0627\u0644\u0639\u062b\u0648\u0631 \u0639\u0644\u0649 \u0623\u064a \u0645\u0634\u0643\u0644\u0629 \u0623\u0645\u0646\u064a\u0629. \u0639\u0645\u0644 \u0645\u0645\u062a\u0627\u0632!',
    runFix: '\u062a\u0634\u063a\u064a\u0644 \u0623\u0645\u0631 \u0627\u0644\u0625\u0635\u0644\u0627\u062d',
    reportSaved: '\u062a\u0645 \u062d\u0641\u0638 \u0627\u0644\u062a\u0642\u0631\u064a\u0631',
    critical: '\u062d\u0631\u062c',
    high: '\u0639\u0627\u0644\u064a',
    medium: '\u0645\u062a\u0648\u0633\u0637',
    low: '\u0645\u0646\u062e\u0641\u0636',
    infraScan: '\u0641\u062d\u0635 \u0627\u0644\u0628\u0646\u064a\u0629 \u0627\u0644\u062a\u062d\u062a\u064a\u0629',
    networkScan: '\u0623\u0645\u0646 \u0627\u0644\u0634\u0628\u0643\u0629',
    sshScan: '\u0627\u0644\u062a\u062d\u0643\u0645 \u0641\u064a \u0627\u0644\u0648\u0635\u0648\u0644 \u0639\u0628\u0631 SSH',
    systemScan: '\u062a\u0642\u0648\u064a\u0629 \u0627\u0644\u0646\u0638\u0627\u0645',
    tlsScan: 'TLS / \u0627\u0644\u0634\u0647\u0627\u062f\u0627\u062a',
    resourceScan: '\u0623\u0645\u0646 \u0627\u0644\u0645\u0648\u0627\u0631\u062f'
  }
};

/**
 * Get translation function for a language
 */
export function i18n(lang = 'en') {
  const t = translations[lang] || translations.en;

  return (key) => t[key] || translations.en[key] || key;
}

export default i18n;
