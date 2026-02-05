import { RiskScore } from './risk-calculator.js';
import { OSVVulnerability } from './osv-client.js';

export interface JSONReport {
  summary: {
    riskScore: number;
    riskLevel: string;
    totalPackages: number;
    vulnerablePackages: number;
    totalVulnerabilities: number;
    cvssAverage: number;
    scanTime: string;
  };
  vulnerabilities: Array<{
    package: string;
    version: string;
    vulnerabilityId: string;
    severity: string;
    summary: string;
    aiExplanation: string;
    fixedIn?: string;
    references: string[];
  }>;
  recommendations: Array<{
    package: string;
    currentVersion: string;
    recommendedVersion: string;
    saferAlternative?: string;
    reason: string;
  }>;
}

export interface SafeAlternative {
  original: string;
  alternative: string;
  reason: string;
  popularity?: string;
  maintenance?: string;
}

export class Formatter {
  /**
   * Format output for CI/CD (JSON)
   */
  formatJSON(
    riskScore: RiskScore,
    vulnerabilities: Map<string, OSVVulnerability[]>,
    getAIExplanation: (vuln: OSVVulnerability) => string
  ): JSONReport {
    const report: JSONReport = {
      summary: {
        riskScore: riskScore.total,
        riskLevel: this.getRiskLevel(riskScore.total),
        totalPackages: riskScore.totalPackages,
        vulnerablePackages: riskScore.vulnerablePackages,
        totalVulnerabilities: this.countTotalVulnerabilities(vulnerabilities),
        cvssAverage: riskScore.cvssAverage,
        scanTime: new Date().toISOString(),
      },
      vulnerabilities: [],
      recommendations: [],
    };

    for (const [pkgName, vulns] of vulnerabilities.entries()) {
      for (const vuln of vulns) {
        const fixedIn = this.extractFixedVersion(vuln);
        
        report.vulnerabilities.push({
          package: pkgName.split('@')[0],
          version: pkgName.split('@')[1] || 'unknown',
          vulnerabilityId: vuln.id,
          severity: this.getSeverityLabel(vuln),
          summary: vuln.summary || 'No summary available',
          aiExplanation: getAIExplanation(vuln),
          fixedIn,
          references: vuln.references?.map(r => r.url) || [],
        });
      }
    }

    // Sort by severity
    report.vulnerabilities.sort((a, b) => {
      const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0 };
      return severityOrder[b.severity as keyof typeof severityOrder] - 
             severityOrder[a.severity as keyof typeof severityOrder];
    });

    // Generate recommendations
    report.recommendations = this.generateRecommendations(vulnerabilities);

    return report;
  }

  /**
   * Format output for terminal (text)
   */
  formatText(
    riskScore: RiskScore,
    vulnerabilities: Map<string, OSVVulnerability[]>
  ): string {
    const lines: string[] = [];
    
    lines.push('╔════════════════════════════════════════════════════════════╗');
    lines.push('║              SENTINEL GUARD SECURITY REPORT                ║');
    lines.push('╚════════════════════════════════════════════════════════════╝');
    lines.push('');
    
    // Summary section
    const riskEmoji = riskScore.total >= 80 ? '🔴' : 
                      riskScore.total >= 60 ? '🟠' : 
                      riskScore.total >= 40 ? '🟡' : 
                      riskScore.total >= 20 ? '🟢' : '✅';
    
    lines.push(`Risk Score: ${riskEmoji} ${riskScore.total}/100 (${this.getRiskLevel(riskScore.total).toUpperCase()})`);
    lines.push(`Packages Scanned: ${riskScore.totalPackages}`);
    lines.push(`Vulnerable Packages: ${riskScore.vulnerablePackages}`);
    lines.push(`Total Vulnerabilities: ${this.countTotalVulnerabilities(vulnerabilities)}`);
    if (riskScore.cvssAverage > 0) {
      lines.push(`Average CVSS Score: ${riskScore.cvssAverage}`);
    }
    lines.push('');

    // Breakdown
    if (riskScore.breakdown.critical > 0) {
      lines.push(`  🔴 Critical: ${riskScore.breakdown.critical}`);
    }
    if (riskScore.breakdown.high > 0) {
      lines.push(`  🟠 High: ${riskScore.breakdown.high}`);
    }
    if (riskScore.breakdown.medium > 0) {
      lines.push(`  🟡 Medium: ${riskScore.breakdown.medium}`);
    }
    if (riskScore.breakdown.low > 0) {
      lines.push(`  🟢 Low: ${riskScore.breakdown.low}`);
    }
    lines.push('');

    // Vulnerabilities
    if (this.countTotalVulnerabilities(vulnerabilities) > 0) {
      lines.push('VULNERABILITIES:');
      lines.push('─'.repeat(60));
      
      for (const [pkgName, vulns] of vulnerabilities.entries()) {
        if (vulns.length > 0) {
          lines.push(`\n📦 ${pkgName}`);
          for (const vuln of vulns) {
            const severity = this.getSeverityLabel(vuln);
            const icon = severity === 'CRITICAL' ? '🔴' :
                        severity === 'HIGH' ? '🟠' :
                        severity === 'MEDIUM' ? '🟡' : '🟢';
            lines.push(`  ${icon} ${vuln.id} (${severity})`);
            if (vuln.summary) {
              lines.push(`     ${vuln.summary.substring(0, 80)}...`);
            }
          }
        }
      }
    } else {
      lines.push('✅ No vulnerabilities found!');
    }

    lines.push('');
    lines.push('Scan completed at: ' + new Date().toLocaleString());

    return lines.join('\n');
  }

  /**
   * Generate safe alternatives for vulnerable packages
   */
  getSafeAlternatives(packageName: string): SafeAlternative[] {
    const alternatives: Record<string, SafeAlternative[]> = {
      'lodash': [{
        original: 'lodash',
        alternative: 'radash',
        reason: 'Modern, tree-shakeable utility library with TypeScript support',
        popularity: 'Growing rapidly',
        maintenance: 'Very active',
      }, {
        original: 'lodash',
        alternative: 'remeda',
        reason: 'Functional utility library with excellent tree-shaking',
        popularity: 'Moderate',
        maintenance: 'Active',
      }],
      'moment': [{
        original: 'moment',
        alternative: 'date-fns',
        reason: 'Modern date utility library, tree-shakeable, immutable',
        popularity: 'Very high',
        maintenance: 'Very active',
      }, {
        original: 'moment',
        alternative: 'dayjs',
        reason: '2KB alternative to Moment.js with compatible API',
        popularity: 'Very high',
        maintenance: 'Active',
      }, {
        original: 'moment',
        alternative: 'luxon',
        reason: 'Powerful date/time library from Moment.js team',
        popularity: 'High',
        maintenance: 'Active',
      }],
      'request': [{
        original: 'request',
        alternative: 'axios',
        reason: 'Promise-based HTTP client with wide browser support',
        popularity: 'Very high',
        maintenance: 'Very active',
      }, {
        original: 'request',
        alternative: 'node-fetch',
        reason: 'Lightweight fetch implementation for Node.js',
        popularity: 'Very high',
        maintenance: 'Active',
      }, {
        original: 'request',
        alternative: 'undici',
        reason: 'Modern HTTP client, becoming Node.js standard',
        popularity: 'Growing',
        maintenance: 'Very active (Node.js core team)',
      }],
      'uuid': [{
        original: 'uuid',
        alternative: 'crypto.randomUUID',
        reason: 'Native Node.js 14.17+ and modern browsers, no dependency needed',
        popularity: 'Native',
        maintenance: 'Node.js core',
      }],
      'mkdirp': [{
        original: 'mkdirp',
        alternative: 'fs.mkdir with recursive option',
        reason: 'Native Node.js 10.12+, no dependency needed',
        popularity: 'Native',
        maintenance: 'Node.js core',
      }],
      'rimraf': [{
        original: 'rimraf',
        alternative: 'fs.rm with recursive option',
        reason: 'Native Node.js 14.14+, no dependency needed',
        popularity: 'Native',
        maintenance: 'Node.js core',
      }],
      'minimatch': [{
        original: 'minimatch',
        alternative: 'picomatch',
        reason: 'Faster glob matching with better performance',
        popularity: 'High',
        maintenance: 'Active',
      }],
      'qs': [{
        original: 'qs',
        alternative: 'URLSearchParams',
        reason: 'Native JavaScript API, no dependency needed',
        popularity: 'Native',
        maintenance: 'JavaScript standard',
      }],
    };

    // Check for partial matches
    for (const [key, alts] of Object.entries(alternatives)) {
      if (packageName.includes(key) || key.includes(packageName)) {
        return alts;
      }
    }

    // Default recommendation
    return [{
      original: packageName,
      alternative: 'Check npm trends for actively maintained alternatives',
      reason: 'Consider packages with recent updates and smaller dependency trees',
      popularity: 'N/A',
      maintenance: 'N/A',
    }];
  }

  /**
   * Get upgrade recommendation for a specific vulnerability
   */
  getUpgradeRecommendation(vuln: OSVVulnerability): string {
    const fixedIn = this.extractFixedVersion(vuln);
    if (fixedIn) {
      return `Upgrade to version ${fixedIn} or later`;
    }
    
    if (vuln.affected && vuln.affected[0]?.ranges) {
      for (const range of vuln.affected[0].ranges) {
        for (const event of range.events) {
          if (event.fixed) {
            return `Upgrade to version ${event.fixed} or later`;
          }
        }
      }
    }

    return 'Check vulnerability details for fix version';
  }

  private countTotalVulnerabilities(vulnerabilities: Map<string, OSVVulnerability[]>): number {
    let count = 0;
    for (const vulns of vulnerabilities.values()) {
      count += vulns.length;
    }
    return count;
  }

  private getRiskLevel(score: number): string {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'safe';
  }

  private getSeverityLabel(vuln: OSVVulnerability): string {
    const text = `${vuln.summary || ''} ${vuln.details || ''}`.toLowerCase();
    
    if (text.includes('critical') || vuln.id.includes('CRITICAL')) return 'CRITICAL';
    if (text.includes('high') || vuln.id.includes('HIGH')) return 'HIGH';
    if (text.includes('medium') || vuln.id.includes('MEDIUM')) return 'MEDIUM';
    if (text.includes('low') || vuln.id.includes('LOW')) return 'LOW';
    
    // Check CVSS
    if (vuln.severity) {
      for (const sev of vuln.severity) {
        const score = parseFloat(sev.score);
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        if (score > 0) return 'LOW';
      }
    }

    return 'UNKNOWN';
  }

  private extractFixedVersion(vuln: OSVVulnerability): string | undefined {
    if (vuln.affected) {
      for (const affected of vuln.affected) {
        if (affected.ranges) {
          for (const range of affected.ranges) {
            for (const event of range.events) {
              if (event.fixed) {
                return event.fixed;
              }
            }
          }
        }
      }
    }
    return undefined;
  }

  private generateRecommendations(
    vulnerabilities: Map<string, OSVVulnerability[]>
  ): JSONReport['recommendations'] {
    const recommendations: JSONReport['recommendations'] = [];
    const seen = new Set<string>();

    for (const [pkgName, vulns] of vulnerabilities.entries()) {
      if (vulns.length > 0 && !seen.has(pkgName)) {
        seen.add(pkgName);
        const [name, version] = pkgName.split('@');
        const alternatives = this.getSafeAlternatives(name);
        
        if (alternatives.length > 0 && alternatives[0].alternative !== name) {
          const fixedVersion = this.extractFixedVersion(vulns[0]);
          recommendations.push({
            package: name,
            currentVersion: version || 'unknown',
            recommendedVersion: fixedVersion || 'latest',
            saferAlternative: alternatives[0].alternative,
            reason: alternatives[0].reason,
          });
        }
      }
    }

    return recommendations;
  }
}

export const formatter = new Formatter();
