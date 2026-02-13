/**
 * 🏗️ Infrastructure Security Scanner
 *
 * Audits infrastructure-level security for production OpenClaw deployments.
 * Covers network, SSH, system hardening, TLS, and resource usage.
 *
 * Opt-in module: activated with --infra flag.
 * Cross-platform: Linux and macOS supported, Windows skipped gracefully.
 *
 * @author Miloud Belarebia
 * @see https://github.com/2pidata/openclaw-security-guard
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';

const execFileAsync = promisify(execFile);

/**
 * Run a command safely and return stdout, or null on failure
 */
async function safeExec(cmd, args = [], _options = {}) {
  try {
    const { stdout } = await execFileAsync(cmd, args, { timeout: 3000 });
    return stdout.trim();
  } catch (_e) {
    return null;
  }
}

/**
 * Check if a file exists
 */
async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch (_e) {
    return false;
  }
}

/**
 * Read file content safely
 */
async function safeReadFile(filePath) {
  try {
    return await fs.readFile(filePath, 'utf-8');
  } catch (_e) {
    return null;
  }
}

export class InfraScanner {
  constructor(config = {}) {
    this.config = config;
    this.platform = os.platform();
    this.isLinux = this.platform === 'linux';
    this.isMac = this.platform === 'darwin';
    this.isSupported = this.isLinux || this.isMac;
  }

  async scan(basePath, _options = {}) {
    const findings = [];
    const summary = { critical: 0, high: 0, medium: 0, low: 0 };
    const infraReport = {
      platform: this.platform,
      network: null,
      ssh: null,
      system: null,
      tls: null,
      resources: null
    };

    if (!this.isSupported) {
      return {
        findings,
        summary,
        infraReport,
        skipped: true,
        reason: `Infrastructure scanning not supported on ${this.platform}. Supported: linux, darwin.`
      };
    }

    // Run all infrastructure checks
    infraReport.network = await this.scanNetwork(findings);
    infraReport.ssh = await this.scanSSH(findings);
    infraReport.system = await this.scanSystem(basePath, findings);
    infraReport.tls = await this.scanTLS(findings);
    infraReport.resources = await this.scanResources(findings);

    // Count findings by severity
    for (const f of findings) {
      if (summary[f.severity] !== undefined) {
        summary[f.severity]++;
      }
    }

    return { findings, summary, infraReport };
  }

  // ============================================================
  // 1. NETWORK SECURITY SCANNER
  // ============================================================

  async scanNetwork(findings) {
    const report = {
      firewallActive: null,
      firewallTool: null,
      publicPorts: [],
      gatewayExposed: false,
      publicExposure: 'unknown'
    };

    // Check firewall status
    if (this.isLinux) {
      // Check UFW
      const ufwStatus = await safeExec('ufw', ['status']);
      if (ufwStatus !== null) {
        report.firewallTool = 'ufw';
        report.firewallActive = ufwStatus.includes('Status: active');
      } else {
        // Check firewalld
        const fwStatus = await safeExec('systemctl', ['is-active', 'firewalld']);
        if (fwStatus !== null) {
          report.firewallTool = 'firewalld';
          report.firewallActive = fwStatus === 'active';
        }
      }
    } else if (this.isMac) {
      // Check macOS firewall
      const pfStatus = await safeExec('/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate']);
      if (pfStatus !== null) {
        report.firewallTool = 'macOS Firewall';
        report.firewallActive = pfStatus.includes('enabled');
      }
    }

    if (report.firewallActive === false) {
      findings.push({
        type: 'infra-network',
        name: 'Firewall Inactive',
        severity: 'critical',
        message: `${report.firewallTool || 'Firewall'} is not active. Your system is exposed to network attacks.`,
        location: 'system',
        fix: this.isLinux ? 'Run: sudo ufw enable' : 'Enable in System Settings > Network > Firewall'
      });
    } else if (report.firewallActive === null) {
      findings.push({
        type: 'infra-network',
        name: 'No Firewall Detected',
        severity: 'high',
        message: 'No firewall tool detected on this system.',
        location: 'system',
        fix: this.isLinux ? 'Install UFW: sudo apt install ufw && sudo ufw enable' : 'Enable macOS Firewall in System Settings'
      });
    }

    // Check for services listening on 0.0.0.0 (public)
    let listeningPorts = null;
    if (this.isLinux) {
      listeningPorts = await safeExec('ss', ['-tlnp']);
    } else if (this.isMac) {
      listeningPorts = await safeExec('lsof', ['-iTCP', '-sTCP:LISTEN', '-P', '-n']);
    }

    if (listeningPorts) {
      const lines = listeningPorts.split('\n');
      for (const line of lines) {
        // Check for 0.0.0.0 or * bindings (publicly accessible)
        if (line.includes('0.0.0.0:') || line.includes('*:') || line.includes(':::')) {
          // Check if it's the OpenClaw gateway port (18789 or 18790)
          if (line.includes(':18789') || line.includes(':18790')) {
            report.gatewayExposed = true;
            findings.push({
              type: 'infra-network',
              name: 'OpenClaw Gateway Publicly Exposed',
              severity: 'critical',
              message: 'OpenClaw gateway or dashboard is bound to 0.0.0.0 (accessible from any network interface).',
              location: 'network',
              fix: 'Configure gateway to bind to 127.0.0.1 (loopback) only'
            });
          }
          // Track public ports
          const portMatch = line.match(/:(\d+)\s/);
          if (portMatch) {
            report.publicPorts.push(parseInt(portMatch[1]));
          }
        }
      }
    }

    // Determine exposure level
    if (!report.firewallActive && report.publicPorts.length > 5) {
      report.publicExposure = 'high';
    } else if (!report.firewallActive || report.gatewayExposed) {
      report.publicExposure = 'warning';
    } else if (report.publicPorts.length === 0) {
      report.publicExposure = 'excellent';
    } else {
      report.publicExposure = 'minimal';
    }

    return report;
  }

  // ============================================================
  // 2. SSH ACCESS CONTROL SCANNER
  // ============================================================

  async scanSSH(findings) {
    const report = {
      sshInstalled: false,
      passwordAuth: null,
      rootLogin: null,
      fail2banActive: null,
      failedLogins24h: null,
      bannedIPs: null
    };

    // Check sshd_config
    const sshdConfigPaths = [
      '/etc/ssh/sshd_config',
      '/etc/ssh/sshd_config.d/',
      '/private/etc/ssh/sshd_config'  // macOS
    ];

    let sshdConfig = null;
    for (const configPath of sshdConfigPaths) {
      sshdConfig = await safeReadFile(configPath);
      if (sshdConfig) break;
    }

    if (sshdConfig) {
      report.sshInstalled = true;

      // Check password authentication
      const passwordLine = sshdConfig.match(/^\s*PasswordAuthentication\s+(yes|no)/mi);
      if (passwordLine) {
        report.passwordAuth = passwordLine[1].toLowerCase() === 'yes';
      } else {
        // Default is yes on most systems
        report.passwordAuth = true;
      }

      if (report.passwordAuth) {
        findings.push({
          type: 'infra-ssh',
          name: 'SSH Password Authentication Enabled',
          severity: 'high',
          message: 'SSH password authentication is enabled. This is vulnerable to brute force attacks.',
          location: '/etc/ssh/sshd_config',
          fix: 'Set PasswordAuthentication no in sshd_config and use key-based auth'
        });
      }

      // Check root login
      const rootLine = sshdConfig.match(/^\s*PermitRootLogin\s+(yes|no|prohibit-password|without-password)/mi);
      if (rootLine) {
        report.rootLogin = rootLine[1].toLowerCase();
      } else {
        report.rootLogin = 'yes'; // Default on most systems
      }

      if (report.rootLogin === 'yes') {
        findings.push({
          type: 'infra-ssh',
          name: 'SSH Root Login Permitted',
          severity: 'high',
          message: 'Direct root login via SSH is permitted.',
          location: '/etc/ssh/sshd_config',
          fix: 'Set PermitRootLogin no or PermitRootLogin prohibit-password'
        });
      }
    }

    // Check fail2ban
    if (this.isLinux) {
      const fail2banStatus = await safeExec('systemctl', ['is-active', 'fail2ban']);
      if (fail2banStatus !== null) {
        report.fail2banActive = fail2banStatus === 'active';
      }

      if (report.sshInstalled && report.fail2banActive === false) {
        findings.push({
          type: 'infra-ssh',
          name: 'fail2ban Not Active',
          severity: 'medium',
          message: 'fail2ban is installed but not running. SSH brute force protection is disabled.',
          location: 'system',
          fix: 'Run: sudo systemctl enable --now fail2ban'
        });
      } else if (report.sshInstalled && report.fail2banActive === null) {
        findings.push({
          type: 'infra-ssh',
          name: 'fail2ban Not Installed',
          severity: 'medium',
          message: 'fail2ban is not installed. No SSH brute force protection.',
          location: 'system',
          fix: 'Install: sudo apt install fail2ban && sudo systemctl enable --now fail2ban'
        });
      }

      // Count failed login attempts (last 24h)
      const failedLogins = await safeExec('journalctl', [
        '-u', 'sshd',
        '--since', '24 hours ago',
        '--no-pager',
        '-q'
      ]);
      if (failedLogins) {
        const failedCount = (failedLogins.match(/Failed password/gi) || []).length;
        report.failedLogins24h = failedCount;

        if (failedCount > 50) {
          findings.push({
            type: 'infra-ssh',
            name: 'High Failed SSH Login Attempts',
            severity: 'high',
            message: `${failedCount} failed SSH login attempts in the last 24 hours. Possible brute force attack.`,
            location: 'system logs',
            fix: 'Enable fail2ban and consider changing SSH port or using VPN'
          });
        } else if (failedCount > 10) {
          findings.push({
            type: 'infra-ssh',
            name: 'Failed SSH Login Attempts Detected',
            severity: 'medium',
            message: `${failedCount} failed SSH login attempts in the last 24 hours.`,
            location: 'system logs',
            fix: 'Monitor and ensure fail2ban is active'
          });
        }
      }

      // Count banned IPs
      const bannedOutput = await safeExec('fail2ban-client', ['status', 'sshd']);
      if (bannedOutput) {
        const bannedMatch = bannedOutput.match(/Currently banned:\s+(\d+)/);
        if (bannedMatch) {
          report.bannedIPs = parseInt(bannedMatch[1]);
        }
      }
    }

    return report;
  }

  // ============================================================
  // 3. SYSTEM HARDENING SCANNER
  // ============================================================

  async scanSystem(basePath, findings) {
    const report = {
      securityUpdates: null,
      configPermissions: null,
      unattendedUpgrades: null
    };

    // Check security updates available
    if (this.isLinux) {
      const updates = await safeExec('apt', ['list', '--upgradable']);
      if (updates) {
        const securityUpdates = (updates.match(/security/gi) || []).length;
        report.securityUpdates = securityUpdates;

        if (securityUpdates > 0) {
          findings.push({
            type: 'infra-system',
            name: 'Security Updates Available',
            severity: securityUpdates > 5 ? 'high' : 'medium',
            message: `${securityUpdates} security update(s) available.`,
            location: 'system',
            fix: 'Run: sudo apt update && sudo apt upgrade'
          });
        }
      }

      // Check unattended upgrades
      const unattendedStatus = await safeExec('systemctl', ['is-active', 'unattended-upgrades']);
      if (unattendedStatus !== null) {
        report.unattendedUpgrades = unattendedStatus === 'active';
      }
    } else if (this.isMac) {
      const updates = await safeExec('softwareupdate', ['-l']);
      if (updates && !updates.includes('No new software available')) {
        report.securityUpdates = 1; // At least one
        findings.push({
          type: 'infra-system',
          name: 'macOS Updates Available',
          severity: 'medium',
          message: 'macOS software updates are available.',
          location: 'system',
          fix: 'Run: softwareupdate -ia or update via System Settings'
        });
      }
    }

    // Check config file permissions
    const openclawConfigPath = path.join(basePath, 'openclaw.json');
    if (await fileExists(openclawConfigPath)) {
      try {
        const stats = await fs.stat(openclawConfigPath);
        const mode = (stats.mode & 0o777).toString(8);
        report.configPermissions = mode;

        // Config should be 600 or 644, not 777 or world-writable
        if (stats.mode & 0o002) { // world-writable
          findings.push({
            type: 'infra-system',
            name: 'Config File World-Writable',
            severity: 'critical',
            message: `openclaw.json has permissions ${mode} (world-writable). Any user can modify your config.`,
            location: openclawConfigPath,
            fix: `Run: chmod 600 ${openclawConfigPath}`
          });
        } else if (stats.mode & 0o020) { // group-writable
          findings.push({
            type: 'infra-system',
            name: 'Config File Group-Writable',
            severity: 'medium',
            message: `openclaw.json has permissions ${mode} (group-writable).`,
            location: openclawConfigPath,
            fix: `Run: chmod 600 ${openclawConfigPath}`
          });
        }
      } catch (_e) {
        // Can't check permissions
      }
    }

    return report;
  }

  // ============================================================
  // 4. TLS / CERTIFICATE SCANNER
  // ============================================================

  async scanTLS(findings) {
    const report = {
      reverseProxy: null,
      tlsEnabled: null,
      tailscaleActive: null,
      wireguardEncryption: null
    };

    // Check for Caddy (common reverse proxy for OpenClaw)
    const caddyStatus = await safeExec('systemctl', ['is-active', 'caddy']);
    if (caddyStatus !== null) {
      report.reverseProxy = 'caddy';
      report.tlsEnabled = caddyStatus === 'active';
    }

    // Check for Nginx
    if (!report.reverseProxy) {
      const nginxStatus = await safeExec('systemctl', ['is-active', 'nginx']);
      if (nginxStatus !== null) {
        report.reverseProxy = 'nginx';
        report.tlsEnabled = nginxStatus === 'active';
      }
    }

    // Check Tailscale status
    const tailscaleStatus = await safeExec('tailscale', ['status', '--json']);
    if (tailscaleStatus) {
      try {
        const tsData = JSON.parse(tailscaleStatus);
        report.tailscaleActive = tsData.BackendState === 'Running';
        report.wireguardEncryption = report.tailscaleActive;
      } catch (_e) {
        report.tailscaleActive = tailscaleStatus.includes('Running') || !tailscaleStatus.includes('stopped');
      }
    }

    // No reverse proxy and no VPN = potential risk for production
    if (!report.reverseProxy && !report.tailscaleActive) {
      findings.push({
        type: 'infra-tls',
        name: 'No Reverse Proxy or VPN Detected',
        severity: 'low',
        message: 'No reverse proxy (Caddy/Nginx) or VPN (Tailscale) detected. If this is a production server, traffic may not be encrypted.',
        location: 'system',
        fix: 'For production: set up Caddy as reverse proxy (automatic TLS) or use Tailscale VPN'
      });
    }

    return report;
  }

  // ============================================================
  // 5. RESOURCE SECURITY SCANNER
  // ============================================================

  async scanResources(findings) {
    const report = {
      diskUsagePercent: null,
      memoryUsagePercent: null,
      cpuCount: os.cpus().length,
      uptime: os.uptime()
    };

    // Check disk usage
    const diskOutput = await safeExec('df', ['-h', '/']);
    if (diskOutput) {
      const lines = diskOutput.split('\n');
      if (lines.length > 1) {
        const match = lines[1].match(/(\d+)%/);
        if (match) {
          report.diskUsagePercent = parseInt(match[1]);

          if (report.diskUsagePercent > 95) {
            findings.push({
              type: 'infra-resource',
              name: 'Disk Almost Full',
              severity: 'critical',
              message: `Disk usage is at ${report.diskUsagePercent}%. System may become unresponsive (DoS risk).`,
              location: 'system',
              fix: 'Free disk space immediately. Check logs and tmp directories.'
            });
          } else if (report.diskUsagePercent > 90) {
            findings.push({
              type: 'infra-resource',
              name: 'Disk Usage High',
              severity: 'high',
              message: `Disk usage is at ${report.diskUsagePercent}%.`,
              location: 'system',
              fix: 'Monitor disk usage and plan cleanup.'
            });
          }
        }
      }
    }

    // Check memory usage
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedPercent = Math.round(((totalMem - freeMem) / totalMem) * 100);
    report.memoryUsagePercent = usedPercent;

    if (usedPercent > 95) {
      findings.push({
        type: 'infra-resource',
        name: 'Memory Almost Exhausted',
        severity: 'high',
        message: `Memory usage is at ${usedPercent}%. System may start killing processes.`,
        location: 'system',
        fix: 'Investigate memory usage with: top or htop'
      });
    }

    return report;
  }
}
