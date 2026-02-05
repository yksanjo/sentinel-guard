# 🔒 Sentinel Guard

> AI Security Auditor for Dependency Trees

Sentinel Guard is a production-ready CLI tool that scans your Node.js dependencies for security vulnerabilities using the [OSV (Open Source Vulnerabilities)](https://osv.dev/) database. It provides intelligent risk analysis, AI-powered explanations, and actionable recommendations to keep your projects secure.

![Node Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)
![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Features

- 🔍 **Comprehensive Scanning** - Scans all dependencies in your `package.json`
- 🧠 **AI-Powered Analysis** - Smart explanations of vulnerability impact
- 📊 **Risk Scoring** - 0-100 risk score with color-coded severity levels
- 💡 **Smart Recommendations** - Suggests safer alternatives to vulnerable packages
- 🔗 **OSV Integration** - Real-time queries to the Open Source Vulnerabilities database
- 🖥️ **Beautiful CLI UI** - Built with Ink (React for CLI) for an immersive experience
- 📄 **JSON Mode** - CI/CD friendly output for automation
- 🪝 **npm Hook** - Optional automatic scanning on `npm install`

## 🚀 Installation

### Via npx (Recommended)

```bash
npx sentinel-guard
```

### Global Installation

```bash
npm install -g sentinel-guard
sentinel-guard
```

### Local Installation

```bash
npm install --save-dev sentinel-guard
npx sentinel-guard
```

## 📖 Usage

### Quick Start

Scan your current project:

```bash
sentinel-guard
```

### Scan Specific Packages

```bash
sentinel-guard scan lodash@4.17.20 axios@0.21.0
```

### Check a Single Package

```bash
sentinel-guard check express@4.18.0
```

### JSON Output (CI/CD)

```bash
sentinel-guard --json
sentinel-guard scan --json
```

### Filter by Severity

```bash
sentinel-guard scan --severity high --json
```

### Get Vulnerability Details

```bash
sentinel-guard explain GHSA-xxxx-xxxx-xxxx
```

### Install npm Hook

Automatically scan new dependencies before installing:

```bash
sentinel-guard hook install
```

Then add this to your `.bashrc` or `.zshrc`:

```bash
alias npm="$(pwd)/.sentinel/npm-hook.sh"
```

To remove the hook:

```bash
sentinel-guard hook remove
```

## 📊 Risk Score

Sentinel Guard calculates a risk score from 0-100 based on:

| Score | Level | Description |
|-------|-------|-------------|
| 80-100 | 🔴 Critical | Immediate action required |
| 60-79 | 🟠 High | Address within 7 days |
| 40-59 | 🟡 Medium | Schedule for next sprint |
| 20-39 | 🟢 Low | Standard update cycle |
| 0-19 | ✅ Safe | No action needed |

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Run Sentinel Guard
        run: npx sentinel-guard --json --severity high > security-report.json
        continue-on-error: true
      
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
```

### GitLab CI

```yaml
security_audit:
  stage: test
  image: node:20
  script:
    - npx sentinel-guard --json --severity high > security-report.json
  artifacts:
    reports:
      junit: security-report.json
  allow_failure: true
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

npx sentinel-guard --json --severity high
if [ $? -ne 0 ]; then
  echo "❌ Security vulnerabilities found. Please fix before committing."
  exit 1
fi
```

## 📋 JSON Output Format

```json
{
  "summary": {
    "riskScore": 75,
    "riskLevel": "high",
    "totalPackages": 42,
    "vulnerablePackages": 5,
    "totalVulnerabilities": 12,
    "cvssAverage": 7.2,
    "scanTime": "2024-01-15T10:30:00.000Z"
  },
  "vulnerabilities": [
    {
      "package": "lodash",
      "version": "4.17.20",
      "vulnerabilityId": "GHSA-29mw-wpgm-hmr9",
      "severity": "HIGH",
      "summary": "Prototype Pollution in lodash",
      "aiExplanation": "High severity issue allowing prototype pollution. Recommend patching within 7 days.",
      "fixedIn": "4.17.21",
      "references": ["https://github.com/advisories/GHSA-29mw-wpgm-hmr9"]
    }
  ],
  "recommendations": [
    {
      "package": "lodash",
      "currentVersion": "^4.17.20",
      "recommendedVersion": "4.17.21",
      "saferAlternative": "radash",
      "reason": "Modern, tree-shakeable utility library with TypeScript support"
    }
  ]
}
```

## 🔐 Security Data Sources

Sentinel Guard queries the [OSV (Open Source Vulnerabilities)](https://osv.dev/) database, which aggregates data from:

- GitHub Security Advisories
- PyPA Advisory Database
- Go Vulnerability Database
- RustSec Advisory Database
- Global Security Database
- OSS-Fuzz
- And more...

## 🎯 Smart Alternatives

Sentinel Guard suggests safer alternatives for commonly vulnerable packages:

| Package | Safer Alternatives |
|---------|-------------------|
| `lodash` | `radash`, `remeda` |
| `moment` | `date-fns`, `dayjs`, `luxon` |
| `request` | `axios`, `node-fetch`, `undici` |
| `uuid` | `crypto.randomUUID` (native) |

## 🛠️ Development

### Setup

```bash
git clone https://github.com/yourusername/sentinel-guard.git
cd sentinel-guard
npm install
```

### Build

```bash
npm run build
```

### Development Mode

```bash
npm run dev
```

### Run Locally

```bash
npm start
```

## 📝 API Reference

### Commands

| Command | Description | Options |
|---------|-------------|---------|
| `scan [packages...]` | Scan dependencies | `--json`, `--fix`, `--severity`, `--directory` |
| `check <package>` | Check single package | `--json` |
| `explain <vulnId>` | Explain vulnerability | - |
| `hook <install/remove>` | Manage npm hook | `--directory` |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--json` | Output JSON format | `false` |
| `--severity <level>` | Minimum severity to report | `low` |
| `--directory <path>` | Project directory | `cwd` |
| `--fix` | Auto-apply safe updates | `false` |

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [OSV](https://osv.dev/) for the vulnerability database
- [Ink](https://github.com/vadimdemedes/ink) for the React CLI framework
- [Commander.js](https://github.com/tj/commander.js/) for CLI argument parsing

---

<p align="center">
  <sub>Built with ❤️ by the Sentinel Guard Team</sub>
</p>
