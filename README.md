<p align="center">
  <img src="https://img.shields.io/npm/v/openclaw-security-guard?style=for-the-badge&color=blue&label=version" alt="npm version" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License" />
  <img src="https://img.shields.io/badge/Node.js-22%2B-success?style=for-the-badge&logo=node.js" alt="Node.js 22+" />
  <img src="https://img.shields.io/badge/Tests-25%2F25%20Passing-success?style=for-the-badge" alt="Tests Passing" />
  <img src="https://img.shields.io/badge/Telemetry-ZERO-blueviolet?style=for-the-badge" alt="Zero Telemetry" />
</p>

<h1 align="center">OpenClaw Security Guard</h1>

<p align="center">
  <strong>The missing security layer for your OpenClaw installation.</strong><br/>
  Audit. Monitor. Protect. All from one tool.
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> &bull;
  <a href="#-why-security-guard">Why This Tool</a> &bull;
  <a href="#-what-you-get">Features</a> &bull;
  <a href="#-live-dashboard">Dashboard</a> &bull;
  <a href="#-cli-reference">CLI</a> &bull;
  <a href="#-contributing">Contributing</a>
</p>

<p align="center">
  Built by <a href="https://github.com/miloudbelarebia">Miloud Belarebia</a> at <a href="https://2pidata.com">2PiData</a> &mdash; for the <a href="https://github.com/openclaw/openclaw">OpenClaw</a> community.
</p>

---

## The Problem

You installed OpenClaw. It works great. But ask yourself:

- Are your **API keys exposed** in config files or skills?
- Is your **sandbox mode** properly configured?
- Do your **MCP servers** come from verified sources?
- Could a **prompt injection** be hiding in your workspace files?
- Are your **npm dependencies** free of known vulnerabilities?

If you're not sure, you need this tool.

---

## Quick Start

```bash
# Install globally
npm install -g openclaw-security-guard

# Run your first audit
openclaw-guard audit

# Fix issues automatically
openclaw-guard fix --auto

# Launch the live dashboard
openclaw-guard dashboard
```

**30 seconds.** That's all it takes to know your security posture.

---

## Why Security Guard?

There are other security tools in the OpenClaw ecosystem. Here's how they compare:

| | Built-in `security audit` | ClawSec | OpenClaw Shield | **Security Guard** |
|---|:---:|:---:|:---:|:---:|
| Secrets scanning (API keys, tokens) | Basic | Yes | Yes | **15+ formats + entropy** |
| Config hardening & auto-fix | No | Partial | Partial | **Full auto-fix, 3 modes** |
| Prompt injection detection | No | No | Basic | **50+ patterns** |
| MCP server verification | No | No | No | **Allowlist-based** |
| npm dependency scanning | No | No | No | **Yes** |
| Live web dashboard | No | No | No | **Real-time scoring** |
| API cost monitoring | No | No | No | **Daily/monthly** |
| Pre-commit hooks | No | No | No | **Yes** |
| Multi-language (EN/FR/AR) | No | No | No | **Yes** |
| Zero telemetry guaranteed | Unknown | Unknown | Unknown | **100% local** |

**Security Guard doesn't replace these tools. It fills the gaps they leave.**

---

## What You Get

### 5 Application Scanners + Infrastructure Module

| Scanner | What it catches |
|---|---|
| **Secrets Scanner** | API keys, tokens, passwords, private keys, webhook URLs. Uses pattern matching + Shannon entropy analysis. |
| **Config Auditor** | Weak sandbox mode, open DM policy, public gateway binding, disabled rate limiting, elevated mode risks. |
| **Prompt Injection Detector** | 50+ patterns: instruction overrides, role hijacking, data exfiltration, delimiter manipulation, jailbreak attempts. |
| **Dependency Scanner** | Known CVEs in your npm dependency tree. |
| **MCP Server Auditor** | Unverified MCP servers not in the community allowlist. |

### Infrastructure Security (opt-in)

For production deployments, add `--infra` to scan your server:

```bash
openclaw-guard audit --infra
```

| Scanner | What it checks |
|---|---|
| **Network Security** | Firewall status (UFW/firewalld/macOS), public port exposure, gateway bound to 0.0.0.0 vs 127.0.0.1 |
| **SSH Access Control** | Password authentication, root login, fail2ban status, failed login attempts (24h) |
| **System Hardening** | Security updates available, config file permissions (600 vs 777), unattended upgrades |
| **TLS / Certificates** | Reverse proxy (Caddy/Nginx), Tailscale/WireGuard VPN status |
| **Resource Security** | Disk usage (DoS risk at >90%), memory usage monitoring |

The infra module catches what application scanning misses:
- App score says 85/100, but gateway is on `0.0.0.0` with SSH password auth enabled = actually vulnerable
- With `--infra`, the combined score reflects the real picture

### Auto-Hardening

Three modes to fix issues your way:

```bash
openclaw-guard fix               # Interactive: review each fix
openclaw-guard fix --auto        # Automatic: fix everything, backup first
openclaw-guard fix --dry-run     # Preview: see what would change
```

Every fix creates a timestamped backup. Nothing is irreversible.

### Security Score (0-100)

One number that tells you where you stand:

| Score | Meaning |
|---|---|
| **80-100** | You're in good shape. |
| **60-79** | Some issues to review. |
| **Below 60** | Action required now. |

Deductions: critical finding = -10, high = -5, medium = -2. Sandbox off = -20. Open DM policy = -15.

---

## Live Dashboard

```bash
openclaw-guard dashboard
```

Opens a password-protected web dashboard at `http://localhost:18790` with:

- **Real-time security score** that updates as threats are detected
- **Request monitoring** with requests-per-minute tracking
- **Cost tracking** for API usage (daily/monthly limits)
- **Threat feed** showing prompt injection attempts, blocked requests, rate limit hits
- **Config overview** at a glance

The dashboard runs on `localhost` only, uses PBKDF2 password hashing (100k iterations, SHA-512), and connects to your OpenClaw gateway via WebSocket.

---

## CLI Reference

| Command | Description |
|---|---|
| `openclaw-guard audit` | Full security audit |
| `openclaw-guard audit --deep` | Deep scan with entropy analysis |
| `openclaw-guard audit --quick` | Fast scan, skip advanced checks |
| `openclaw-guard audit --infra` | Include infrastructure scanning (network, SSH, system) |
| `openclaw-guard audit --ci` | CI mode (exit code 1 on critical issues) |
| `openclaw-guard fix` | Interactive fix mode |
| `openclaw-guard fix --auto` | Automatic fix with backup |
| `openclaw-guard fix --dry-run` | Preview fixes without applying |
| `openclaw-guard dashboard` | Start live dashboard |
| `openclaw-guard dashboard -p 3000` | Custom port |
| `openclaw-guard scan secrets` | Scan for secrets only |
| `openclaw-guard scan config` | Audit config only |
| `openclaw-guard scan prompts` | Detect prompt injections only |
| `openclaw-guard report -f html` | Generate HTML report |
| `openclaw-guard report -f json` | Generate JSON report |
| `openclaw-guard hooks install` | Install pre-commit hook |
| `openclaw-guard hooks status` | Check hook status |

### Global Options

| Option | Description |
|---|---|
| `-c, --config <path>` | Custom config file path |
| `-l, --lang <lang>` | Language: `en`, `fr`, `ar` |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | No banner |

---

## Configuration

Create `.openclaw-guard.json` in your project root or home directory:

```json
{
  "scanners": {
    "secrets": {
      "enabled": true,
      "exclude": ["*.test.js", "node_modules/**"]
    },
    "config": {
      "enabled": true,
      "strict": true
    },
    "prompts": {
      "enabled": true,
      "sensitivity": "high"
    },
    "mcpServers": {
      "allowlist": [
        "mcp-server-filesystem",
        "mcp-server-fetch",
        "mcp-server-memory",
        "mcp-server-sqlite",
        "mcp-server-git",
        "mcp-server-github"
      ],
      "blockUnknown": false
    }
  },
  "monitors": {
    "cost": {
      "dailyLimit": 10,
      "monthlyLimit": 100
    }
  },
  "dashboard": {
    "port": 18790
  }
}
```

---

## Programmatic API

Use Security Guard as a library in your own projects:

```javascript
import { quickAudit, checkPromptInjection } from 'openclaw-security-guard';

// Full audit
const results = await quickAudit('~/.openclaw');
console.log(`Score: ${results.securityScore}/100`);
console.log(`Critical: ${results.summary.critical}`);

// Check a message for injection
const check = await checkPromptInjection('ignore all previous instructions');
console.log(check.safe); // false
```

```javascript
// Individual scanners
import { SecretsScanner, ConfigAuditor, McpServerAuditor } from 'openclaw-security-guard';

const scanner = new SecretsScanner({});
const result = await scanner.scan('/path/to/openclaw');
```

---

## Privacy & Security

This is a security tool. It should be secure itself. Here's the commitment:

| | |
|---|---|
| **Telemetry** | None. Zero. |
| **Network requests** | None (except local WebSocket to your gateway) |
| **Data collection** | None |
| **Cloud dependency** | None |
| **Dashboard access** | `localhost` only, password-protected |
| **Password storage** | PBKDF2, 100k iterations, SHA-512 |
| **Input validation** | Zod schemas everywhere |
| **Report generation** | XSS-safe, path-traversal-safe |

See [SECURITY.md](./SECURITY.md) for the full security policy.

---

## Documentation

| Language | Link |
|---|---|
| English | [docs/en/README.md](./docs/en/README.md) |
| French | [docs/fr/README.md](./docs/fr/README.md) |
| Arabic | [docs/ar/README.md](./docs/ar/README.md) |

---

## Contributing

PRs welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md).

```bash
git clone https://github.com/2pidata/openclaw-security-guard.git
cd openclaw-security-guard
npm install
npm test    # 25 tests, 0 warnings
```

---

## License

[MIT](./LICENSE)

---

<p align="center">
  <strong>Created by <a href="https://github.com/miloudbelarebia">Miloud Belarebia</a></strong> at <strong><a href="https://2pidata.com">2PiData</a></strong><br/>
  Inspired by <a href="https://github.com/Yelp/detect-secrets">detect-secrets</a>, <a href="https://github.com/aquasecurity/trivy">trivy</a>, and <a href="https://owasp.org/">OWASP</a>.
</p>

<p align="center">
  <strong>If this tool helps you, leave a star. It helps others find it too.</strong><br/>
  <a href="https://github.com/2pidata/openclaw-security-guard">github.com/2pidata/openclaw-security-guard</a>
</p>

<p align="center">
  <a href="https://github.com/2pidata/openclaw-security-guard/issues">Report a bug</a> &bull;
  <a href="https://github.com/2pidata/openclaw-security-guard/issues">Request a feature</a> &bull;
  <a href="https://2pidata.com">2pidata.com</a>
</p>
