# 📖 OpenClaw Security Guard - Documentation

<div align="center">

**Complete Documentation for OpenClaw Security Guard**

[🏠 Home](./README.md) •
[🚀 Getting Started](./guides/getting-started.md) •
[📋 CLI Reference](./api/cli.md) •
[🔌 API Reference](./api/programmatic.md) •
[🌍 Translations](./fr/README.md)

</div>

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Features](#features)
5. [CLI Reference](#cli-reference)
6. [Dashboard](#dashboard)
7. [Scanners](#scanners)
8. [Configuration](#configuration)
9. [Security Score](#security-score)
10. [Programmatic Usage](#programmatic-usage)
11. [Best Practices](#best-practices)
12. [Troubleshooting](#troubleshooting)
13. [FAQ](#faq)

---

## Introduction

**OpenClaw Security Guard** is a comprehensive security layer for OpenClaw installations. It provides:

- 🔍 **5 Security Scanners** - Detect secrets, misconfigurations, and vulnerabilities
- 📊 **Live Dashboard** - Real-time monitoring with password protection
- 🔧 **Auto-Fix** - Automatically fix common security issues
- 🌍 **Multi-language** - English, French, Arabic

### Why You Need This

OpenClaw is powerful, but default configurations may expose your system to:

| Risk | Without Guard | With Guard |
|------|---------------|------------|
| Exposed API Keys | 😰 Unknown | ✅ Detected & Masked |
| Prompt Injection | 😰 Vulnerable | ✅ Real-time Blocking |
| Open DM Policy | 😰 Anyone can message | ✅ Audit & Alert |
| No Cost Limits | 😰 Unlimited spending | ✅ Cost Monitoring |
| Sandbox Disabled | 😰 Full system access | ✅ Auto-fix Available |

### Privacy

This tool is **100% private**:

- ❌ No telemetry
- ❌ No tracking
- ❌ No external requests
- ❌ No data collection
- ✅ Everything runs locally
- ✅ Open source - verify yourself

---

## Installation

### Requirements

- Node.js 22 or higher
- npm 10 or higher

### Global Installation (Recommended)

```bash
npm install -g openclaw-security-guard
```

### Verify Installation

```bash
openclaw-guard --version
# Output: 1.0.0
```

### Using npx (No Install)

```bash
npx openclaw-security-guard audit
```

---

## Quick Start

### 1. Run Your First Audit

```bash
openclaw-guard audit
```

This will scan your OpenClaw installation and show a security report:

```
🛡️ OpenClaw Security Guard v1.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 Secrets Scanner............ ✅ No issues
🔧 Config Auditor............. ❌ 2 critical
💉 Injection Detector......... ✅ No issues
📦 Dependency Scanner......... ⚠️ 1 warning
🔌 MCP Server Auditor......... ✅ No issues
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Security Score: 65/100
```

### 2. Fix Issues

```bash
# Interactive mode
openclaw-guard fix

# Automatic mode
openclaw-guard fix --auto
```

### 3. Start Dashboard

```bash
openclaw-guard dashboard
```

On first run, you'll create a password. Then access: `http://localhost:18790`

---

## Features

### Security Scanners

| Scanner | What it Does |
|---------|--------------|
| **Secrets** | Detects API keys, tokens, passwords in 15+ formats |
| **Config** | Audits OpenClaw config against 15+ security rules |
| **Prompts** | Detects 50+ prompt injection patterns |
| **Dependencies** | Checks for vulnerable npm packages |
| **MCP Servers** | Validates installed MCP servers |

### Live Dashboard

- Real-time security score
- Request monitoring
- Cost tracking
- Threat detection
- Alert feed
- Password protected

### Auto-Fix

- Backs up before changes
- Interactive or automatic mode
- Detailed change log

---

## CLI Reference

### Global Options

```bash
openclaw-guard [command] [options]

Options:
  -V, --version        Output version number
  -c, --config <path>  Path to config file
  -l, --lang <lang>    Language (en|fr|ar)
  -v, --verbose        Verbose output
  -q, --quiet          Quiet mode (no banner)
  -h, --help           Display help
```

### Commands

#### `audit` - Run Security Audit

```bash
openclaw-guard audit [options]

Options:
  --deep              Deep scan (slower but thorough)
  --quick             Quick scan (faster)
  -o, --output <path> Output file
  -f, --format <fmt>  Format: text|json|html|md (default: text)
  --ci                CI mode (exit 1 on critical issues)
```

**Examples:**

```bash
# Basic audit
openclaw-guard audit

# Deep audit with HTML report
openclaw-guard audit --deep -o report.html -f html

# CI/CD integration
openclaw-guard audit --ci
```

#### `dashboard` - Start Live Dashboard

```bash
openclaw-guard dashboard [options]

Options:
  -p, --port <port>    Dashboard port (default: 18790)
  -g, --gateway <url>  OpenClaw Gateway URL (default: ws://127.0.0.1:18789)
  --no-browser         Don't open browser automatically
```

**Examples:**

```bash
# Start dashboard
openclaw-guard dashboard

# Custom port
openclaw-guard dashboard --port 3000

# Don't open browser
openclaw-guard dashboard --no-browser
```

#### `fix` - Fix Security Issues

```bash
openclaw-guard fix [options]

Options:
  --auto        Auto-fix without prompts
  --interactive Interactive mode (default)
  --backup      Create backup before changes (default: true)
  --dry-run     Preview changes without applying
```

**Examples:**

```bash
# Interactive fix
openclaw-guard fix

# Automatic fix
openclaw-guard fix --auto

# Preview only
openclaw-guard fix --dry-run
```

#### `scan` - Run Individual Scanners

```bash
openclaw-guard scan <scanner> [options]

Scanners:
  secrets     Scan for exposed secrets
  config      Audit configuration
  prompts     Detect injection patterns

Options (secrets):
  --quick     Quick scan

Options (config):
  --strict    Strict mode

Options (prompts):
  -s, --sensitivity <level>  low|medium|high (default: medium)
```

**Examples:**

```bash
# Scan for secrets
openclaw-guard scan secrets

# Audit config in strict mode
openclaw-guard scan config --strict

# Detect injections with high sensitivity
openclaw-guard scan prompts --sensitivity high
```

#### `report` - Generate Report

```bash
openclaw-guard report [options]

Options:
  -f, --format <fmt>   Format: html|json|md (default: html)
  -o, --output <path>  Output path (default: ./security-report)
```

**Examples:**

```bash
# HTML report
openclaw-guard report

# JSON report
openclaw-guard report -f json -o audit.json

# Markdown report
openclaw-guard report -f md -o SECURITY_AUDIT.md
```

#### `hooks` - Manage Git Hooks

```bash
openclaw-guard hooks <action>

Actions:
  install     Install pre-commit hook
  uninstall   Remove pre-commit hook
  status      Check if hook is installed
```

**Examples:**

```bash
# Install pre-commit hook
openclaw-guard hooks install

# Check status
openclaw-guard hooks status
```

#### `about` - About This Tool

```bash
openclaw-guard about
```

---

## Dashboard

### First Run Setup

1. Run `openclaw-guard dashboard`
2. Browser opens to `http://localhost:18790`
3. You'll see the **Setup** page
4. Create a password (minimum 8 characters)
5. You're logged in!

### Subsequent Runs

1. Run `openclaw-guard dashboard`
2. Browser opens to **Login** page
3. Enter your password
4. Access the dashboard

### Dashboard Features

| Feature | Description |
|---------|-------------|
| **Security Score** | 0-100 score with color coding |
| **Requests/min** | Real-time request counter |
| **Cost Today** | API cost tracking |
| **Threats** | Injection attempts, rate limits, blocked |
| **Config Status** | Sandbox, DM policy, gateway, etc. |
| **Alerts** | Recent security alerts |

### Password Reset

If you forget your password, delete the config file:

```bash
rm ~/.openclaw-security-guard/auth.json
```

Then restart the dashboard to create a new password.

---

## Scanners

### Secrets Scanner

Detects exposed secrets in your OpenClaw directory.

**Detected Patterns:**

| Type | Pattern Example |
|------|-----------------|
| OpenAI | `sk-...` |
| Anthropic | `sk-ant-...` |
| AWS | `AKIA...` |
| GitHub | `ghp_...`, `gho_...` |
| Slack | `xoxb-...`, `xoxp-...` |
| Stripe | `sk_live_...` |
| Private Keys | `-----BEGIN RSA PRIVATE KEY-----` |
| Generic | High entropy strings |

**Configuration:**

```json
{
  "scanners": {
    "secrets": {
      "enabled": true,
      "exclude": ["*.test.js", "node_modules/**"]
    }
  }
}
```

### Config Auditor

Validates OpenClaw configuration against security best practices.

**Rules Checked:**

| Rule | Severity | Recommendation |
|------|----------|----------------|
| Sandbox mode | Critical | Set to `always` |
| DM policy | High | Set to `pairing` |
| Gateway bind | Critical | Set to `loopback` |
| Elevated mode | High | Disable |
| Rate limiting | Medium | Enable |
| Cost limits | Medium | Set limits |

### Prompt Injection Detector

Detects prompt injection patterns in logs and messages.

**Categories:**

1. **Instruction Override** - "ignore previous instructions"
2. **Role Manipulation** - "you are now DAN"
3. **System Prompt** - "system: ..."
4. **Jailbreak** - Known jailbreak phrases
5. **Code Execution** - Attempts to execute code
6. **Data Extraction** - Attempts to extract data

**Sensitivity Levels:**

| Level | Description |
|-------|-------------|
| `low` | Only obvious attacks |
| `medium` | Balanced detection (default) |
| `high` | Aggressive detection (may have false positives) |

---

## Configuration

### Config File Location

Create `.openclaw-guard.json` in:
- Project directory (highest priority)
- Home directory (`~/.openclaw-guard.json`)

### Full Configuration

```json
{
  "scanners": {
    "secrets": {
      "enabled": true,
      "exclude": ["*.test.js", "node_modules/**", "*.log"]
    },
    "config": {
      "enabled": true,
      "strict": false
    },
    "prompts": {
      "enabled": true,
      "sensitivity": "medium"
    },
    "deps": {
      "enabled": true,
      "severity": "medium"
    },
    "mcp": {
      "enabled": true,
      "allowlist": [],
      "blockUnknown": false
    }
  },
  "dashboard": {
    "port": 18790,
    "openBrowser": true
  },
  "reporting": {
    "format": "html",
    "outputDir": "./security-reports"
  },
  "fix": {
    "backup": true,
    "autoApprove": false
  }
}
```

---

## Security Score

### How It's Calculated

Your security score starts at 100 and decreases based on issues:

| Factor | Points Deducted |
|--------|-----------------|
| Sandbox not `always` | -20 |
| DM policy is `open` | -15 |
| Gateway on public IP | -15 |
| Elevated mode enabled | -10 |
| Rate limiting disabled | -5 |
| Each critical finding | -10 |
| Each high finding | -5 |
| Each medium finding | -2 |

### Score Ranges

| Score | Status | Icon |
|-------|--------|------|
| 80-100 | Healthy | 🟢 |
| 60-79 | Attention Needed | 🟡 |
| 0-59 | Critical Issues | 🔴 |

### Improving Your Score

1. Run `openclaw-guard fix --auto`
2. Follow the recommendations
3. Re-run `openclaw-guard audit`

---

## Programmatic Usage

### Installation

```bash
npm install openclaw-security-guard
```

### Quick Audit

```javascript
import { quickAudit } from 'openclaw-security-guard';

const results = await quickAudit('~/.openclaw');
console.log(`Security Score: ${results.securityScore}/100`);
console.log(`Critical: ${results.summary.critical}`);
console.log(`High: ${results.summary.high}`);
```

### Check Prompt Injection

```javascript
import { checkPromptInjection } from 'openclaw-security-guard';

const result = await checkPromptInjection('ignore all previous instructions');

if (!result.safe) {
  console.log('Injection detected!');
  console.log('Patterns:', result.matches);
}
```

### Use Individual Scanners

```javascript
import { SecretsScanner, ConfigAuditor } from 'openclaw-security-guard';

// Scan for secrets
const secretsScanner = new SecretsScanner({});
const secretsResult = await secretsScanner.scan('~/.openclaw', {});

// Audit config
const configAuditor = new ConfigAuditor({});
const configResult = await configAuditor.scan('~/.openclaw', { strict: true });
```

### Start Dashboard Programmatically

```javascript
import { startDashboard } from 'openclaw-security-guard';

const { server, monitor, auth } = await startDashboard({
  port: 18790,
  gatewayUrl: 'ws://127.0.0.1:18789',
  openBrowser: false
});
```

---

## Best Practices

### 1. Regular Audits

```bash
# Add to crontab for daily audits
0 9 * * * openclaw-guard audit --quiet -o /var/log/openclaw-audit.json -f json
```

### 2. CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - run: npm install -g openclaw-security-guard
      - run: openclaw-guard audit --ci
```

### 3. Pre-commit Hooks

```bash
openclaw-guard hooks install
```

This prevents committing secrets accidentally.

### 4. Secure Configuration

```json
// openclaw.json - Recommended settings
{
  "agents": {
    "defaults": {
      "sandbox": { "mode": "always" },
      "tools": { "elevated": { "enabled": false } }
    }
  },
  "channels": {
    "whatsapp": { "dmPolicy": "pairing" }
  },
  "gateway": {
    "bind": "loopback"
  },
  "security": {
    "rateLimiting": { "enabled": true }
  }
}
```

---

## Troubleshooting

### "Command not found"

```bash
# Check if npm bin is in PATH
echo $PATH | grep npm

# Or use npx
npx openclaw-security-guard audit
```

### "Permission denied"

```bash
# Fix npm permissions
npm config set prefix ~/.npm-global
export PATH=~/.npm-global/bin:$PATH
```

### Dashboard won't open

```bash
# Check if port is in use
lsof -i :18790

# Use different port
openclaw-guard dashboard --port 3001
```

### "Cannot find OpenClaw"

The tool looks for OpenClaw in:
1. Current directory
2. `~/.openclaw`
3. Environment variable `OPENCLAW_HOME`

```bash
# Set custom path
export OPENCLAW_HOME=/path/to/openclaw
```

---

## FAQ

### Is my data sent anywhere?

**No.** This tool makes zero external requests. Everything runs locally. No telemetry, no tracking, no analytics.

### Can I use this in production?

**Yes.** This tool is designed for production use. The dashboard is password-protected and binds to localhost only.

### How do I update?

```bash
npm update -g openclaw-security-guard
```

### Can I contribute?

**Yes!** See [CONTRIBUTING.md](../CONTRIBUTING.md)

### Where do I report bugs?

Open an issue on [GitHub](https://github.com/2pidata/openclaw-security-guard/issues)

### Who made this?

**Miloud Belarebia** - [2pidata.com](https://2pidata.com)

---

## Support

- 📖 [Documentation](https://github.com/2pidata/openclaw-security-guard/docs)
- 🐛 [Report Bug](https://github.com/2pidata/openclaw-security-guard/issues)
- 💡 [Request Feature](https://github.com/2pidata/openclaw-security-guard/issues)
- 🌐 [Website](https://2pidata.com)

---

<div align="center">

**Made with ❤️ by [Miloud Belarebia](https://github.com/2pidata)**

[2pidata.com](https://2pidata.com) • #miloudbelarebia 🇲🇦

</div>
