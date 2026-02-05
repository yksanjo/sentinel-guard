import React from 'react';
import { Box, Text } from 'ink';
import { OSVVulnerability } from '../utils/osv-client.js';
import { Formatter, SafeAlternative } from '../utils/formatter.js';
import { RiskCalculator } from '../utils/risk-calculator.js';

interface RecommendationPanelProps {
  vulnerabilities: Map<string, OSVVulnerability[]>;
  maxRecommendations?: number;
}

const formatter = new Formatter();
const riskCalculator = new RiskCalculator();

interface Recommendation {
  packageName: string;
  currentVersion?: string;
  fixedVersion?: string;
  alternatives: SafeAlternative[];
  severity: string;
}

export const RecommendationPanel: React.FC<RecommendationPanelProps> = ({
  vulnerabilities,
  maxRecommendations = 5,
}) => {
  // Generate recommendations based on vulnerabilities
  const recommendations: Recommendation[] = [];
  const seenPackages = new Set<string>();

  // Sort packages by severity
  const sortedEntries = Array.from(vulnerabilities.entries())
    .filter(([_, vulns]) => vulns.length > 0)
    .sort((a, b) => {
      const maxSeverityA = Math.max(...a[1].map(v => {
        const sev = riskCalculator.getSeverity(v);
        return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 }[sev] || 0;
      }));
      const maxSeverityB = Math.max(...b[1].map(v => {
        const sev = riskCalculator.getSeverity(v);
        return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 }[sev] || 0;
      }));
      return maxSeverityB - maxSeverityA;
    });

  for (const [packageName, vulns] of sortedEntries.slice(0, maxRecommendations)) {
    if (seenPackages.has(packageName)) continue;
    seenPackages.add(packageName);

    const pkgBaseName = packageName.split('@')[0];
    const alternatives = formatter.getSafeAlternatives(pkgBaseName);
    const fixedVersion = formatter.getUpgradeRecommendation(vulns[0]);
    
    const maxSeverity = vulns.reduce((max, vuln) => {
      const sev = riskCalculator.getSeverity(vuln);
      const score = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 }[sev] || 0;
      return Math.max(max, score);
    }, 0);

    const severityLabel = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][maxSeverity];

    recommendations.push({
      packageName: pkgBaseName,
      currentVersion: packageName.split('@')[1],
      fixedVersion: fixedVersion.replace('Upgrade to version ', '').replace(' or later', ''),
      alternatives,
      severity: severityLabel,
    });
  }

  if (recommendations.length === 0) {
    return (
      <Box marginY={1}>
        <Text color="greenBright">
          ✅ No recommendations needed - your dependencies look good!
        </Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column" marginTop={2}>
      <Box marginBottom={1}>
        <Text bold underline color="cyan">
          💡 RECOMMENDATIONS
        </Text>
      </Box>

      {recommendations.map((rec, index) => (
        <Box key={index} flexDirection="column" marginBottom={2}>
          <Box>
            <Text bold color="white">
              {index + 1}. {rec.packageName}
            </Text>
            <Text color="gray">
              {rec.currentVersion && ` (current: ${rec.currentVersion})`}
            </Text>
          </Box>

          <Box marginLeft={3} marginTop={1}>
            <Text color="yellow">
              ⬆️  Fix: Upgrade to {rec.fixedVersion}
            </Text>
          </Box>

          {rec.alternatives.length > 0 && rec.alternatives[0].alternative !== rec.packageName && (
            <Box marginLeft={3} marginTop={1} flexDirection="column">
              <Text color="green">🔄 Alternatives:</Text>
              {rec.alternatives.slice(0, 2).map((alt, altIndex) => (
                <Box key={altIndex} marginLeft={2} marginTop={1}>
                  <Text color="cyan">• {alt.alternative}</Text>
                  {alt.popularity && (
                    <Text color="gray"> ({alt.popularity})</Text>
                  )}
                </Box>
              ))}
            </Box>
          )}
        </Box>
      ))}

      <Box marginTop={1} padding={1} borderStyle="round" borderColor="gray">
        <Text color="gray" dimColor>
          💡 Tip: Run `sentinel-guard scan --fix` to auto-apply safe updates
        </Text>
      </Box>
    </Box>
  );
};

export default RecommendationPanel;
