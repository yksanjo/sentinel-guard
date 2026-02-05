import { OSVVulnerability } from './osv-client.js';

export interface RiskScore {
  total: number;
  breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  vulnerablePackages: number;
  totalPackages: number;
  cvssAverage: number;
}

export interface RiskCategory {
  level: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  score: number;
  color: string;
  emoji: string;
}

export class RiskCalculator {
  /**
   * Calculate overall risk score based on vulnerabilities found
   * Returns a score from 0-100 where 100 is highest risk
   */
  calculateRiskScore(vulnerabilities: Map<string, OSVVulnerability[]>): RiskScore {
    let totalScore = 0;
    const breakdown = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };
    let totalCvss = 0;
    let cvssCount = 0;
    let vulnerablePackages = 0;
    const totalPackages = vulnerabilities.size;

    for (const [pkgName, vulns] of vulnerabilities.entries()) {
      if (vulns.length > 0) {
        vulnerablePackages++;
        
        for (const vuln of vulns) {
          const severity = this.getSeverity(vuln);
          const cvssScore = this.extractCvssScore(vuln);
          
          if (cvssScore > 0) {
            totalCvss += cvssScore;
            cvssCount++;
          }

          switch (severity) {
            case 'CRITICAL':
              breakdown.critical++;
              totalScore += 25;
              break;
            case 'HIGH':
              breakdown.high++;
              totalScore += 15;
              break;
            case 'MEDIUM':
              breakdown.medium++;
              totalScore += 8;
              break;
            case 'LOW':
              breakdown.low++;
              totalScore += 3;
              break;
          }
        }
      }
    }

    // Cap at 100
    totalScore = Math.min(100, totalScore);

    // Factor in percentage of vulnerable packages
    const vulnerabilityRatio = vulnerablePackages / Math.max(totalPackages, 1);
    const adjustedScore = Math.round(totalScore * (0.7 + vulnerabilityRatio * 0.3));

    return {
      total: Math.min(100, adjustedScore),
      breakdown,
      vulnerablePackages,
      totalPackages,
      cvssAverage: cvssCount > 0 ? Math.round((totalCvss / cvssCount) * 10) / 10 : 0,
    };
  }

  /**
   * Get severity level from vulnerability data
   */
  getSeverity(vuln: OSVVulnerability): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' {
    // Check CVSS scores first
    const cvssScore = this.extractCvssScore(vuln);
    if (cvssScore >= 9.0) return 'CRITICAL';
    if (cvssScore >= 7.0) return 'HIGH';
    if (cvssScore >= 4.0) return 'MEDIUM';
    if (cvssScore > 0) return 'LOW';

    // Check severity field
    if (vuln.severity) {
      for (const sev of vuln.severity) {
        const score = parseFloat(sev.score);
        if (!isNaN(score)) {
          if (score >= 9.0) return 'CRITICAL';
          if (score >= 7.0) return 'HIGH';
          if (score >= 4.0) return 'MEDIUM';
          return 'LOW';
        }
      }
    }

    // Infer from summary/description
    const text = `${vuln.summary || ''} ${vuln.details || ''}`.toLowerCase();
    if (text.includes('critical') || text.includes('rce') || text.includes('remote code')) {
      return 'CRITICAL';
    }
    if (text.includes('high') || text.includes('ssrf') || text.includes('sql injection')) {
      return 'HIGH';
    }
    if (text.includes('medium') || text.includes('moderate') || text.includes('xss')) {
      return 'MEDIUM';
    }
    if (text.includes('low') || text.includes('minor')) {
      return 'LOW';
    }

    return 'UNKNOWN';
  }

  /**
   * Extract CVSS score from vulnerability data
   */
  extractCvssScore(vuln: OSVVulnerability): number {
    if (!vuln.severity) return 0;

    for (const sev of vuln.severity) {
      const score = parseFloat(sev.score);
      if (!isNaN(score) && score > 0) {
        // Normalize to 0-10 scale
        if (score <= 1) return score * 10; // Assume 0-1 scale
        return Math.min(10, score);
      }
    }

    return 0;
  }

  /**
   * Get risk category from score
   */
  getRiskCategory(score: number): RiskCategory {
    if (score >= 80) {
      return { level: 'critical', score, color: '#FF4444', emoji: '🔴' };
    }
    if (score >= 60) {
      return { level: 'high', score, color: '#FF8800', emoji: '🟠' };
    }
    if (score >= 40) {
      return { level: 'medium', score, color: '#FFCC00', emoji: '🟡' };
    }
    if (score >= 20) {
      return { level: 'low', score, color: '#88CC00', emoji: '🟢' };
    }
    return { level: 'safe', score, color: '#00AA00', emoji: '✅' };
  }

  /**
   * Get AI-powered explanation for a vulnerability
   * This simulates GPT-4o analysis
   */
  getAIExplanation(vuln: OSVVulnerability): string {
    const severity = this.getSeverity(vuln);
    const patterns = this.getAttackPatterns(vuln);
    
    const explanations: Record<string, string[]> = {
      CRITICAL: [
        `This ${vuln.id} vulnerability enables ${patterns}. Immediate action required.`,
        `Critical exposure: ${patterns}. Could lead to complete system compromise.`,
        `Severe risk detected. ${patterns} possible without authentication.`,
      ],
      HIGH: [
        `High severity issue allowing ${patterns}. Recommend patching within 7 days.`,
        `Significant security risk: ${patterns}. Consider workaround if patch unavailable.`,
        `Exploitation could result in ${patterns}. Prioritize for next sprint.`,
      ],
      MEDIUM: [
        `Moderate risk through ${patterns}. Patch during regular maintenance.`,
        `Potential for ${patterns} under specific conditions. Monitor for exploits.`,
        `Security enhancement needed: ${patterns}. Schedule update soon.`,
      ],
      LOW: [
        `Minor security consideration: ${patterns}. Low exploit probability.`,
        `Informational risk regarding ${patterns}. Standard update cycle acceptable.`,
        `Edge case vulnerability enabling ${patterns}. Risk is minimal.`,
      ],
      UNKNOWN: [
        `Risk level unclear. Review ${vuln.id} details manually.`,
        `Insufficient data for automatic assessment. Check references for context.`,
      ],
    };

    const options = explanations[severity] || explanations.UNKNOWN;
    return options[Math.floor(Math.random() * options.length)];
  }

  /**
   * Get attack patterns based on vulnerability data
   */
  private getAttackPatterns(vuln: OSVVulnerability): string {
    const text = `${vuln.summary || ''} ${vuln.details || ''}`.toLowerCase();
    
    const patterns: Record<string, string> = {
      'rce': 'remote code execution',
      'remote code': 'remote code execution',
      'arbitrary code': 'arbitrary code execution',
      'command injection': 'command injection',
      'sql injection': 'SQL injection',
      'ssrf': 'server-side request forgery',
      'xss': 'cross-site scripting',
      'csrf': 'cross-site request forgery',
      'path traversal': 'directory traversal',
      'prototype pollution': 'prototype pollution',
      'regex dos': 'ReDoS attacks',
      'denial of service': 'denial of service',
      'information disclosure': 'information leakage',
      'authentication bypass': 'authentication bypass',
      'privilege escalation': 'privilege escalation',
    };

    for (const [keyword, description] of Object.entries(patterns)) {
      if (text.includes(keyword)) {
        return description;
      }
    }

    return 'malicious activity';
  }
}

export const riskCalculator = new RiskCalculator();
