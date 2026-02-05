import React, { useState, useEffect, useCallback } from 'react';
import { Box, Text, Spacer, useStdout } from 'ink';
import { Spinner } from 'ink-spinner';
import { OSVClient, OSVVulnerability, OSVPackage } from '../utils/osv-client.js';
import { RiskCalculator, RiskScore } from '../utils/risk-calculator.js';
import { RiskBadge } from './RiskBadge.js';
import { VulnerabilityList } from './VulnerabilityList.js';
import { RecommendationPanel } from './RecommendationPanel.js';
import { NPMInterceptor } from '../utils/npm-interceptor.js';
import { Formatter } from '../utils/formatter.js';

const osvClient = new OSVClient();
const riskCalculator = new RiskCalculator();
const npmInterceptor = new NPMInterceptor();
const formatter = new Formatter();

interface ScannerProps {
  cwd?: string;
  jsonMode?: boolean;
  fixMode?: boolean;
  specificPackages?: string[];
  onComplete?: (result: {
    riskScore: RiskScore;
    vulnerabilities: Map<string, OSVVulnerability[]>;
  }) => void;
}

interface ScanProgress {
  current: number;
  total: number;
  currentPackage: string;
}

export const Scanner: React.FC<ScannerProps> = ({
  cwd = process.cwd(),
  jsonMode = false,
  fixMode = false,
  specificPackages,
  onComplete,
}) => {
  const { stdout } = useStdout();
  const [progress, setProgress] = useState<ScanProgress>({
    current: 0,
    total: 0,
    currentPackage: '',
  });
  const [vulnerabilities, setVulnerabilities] = useState<Map<string, OSVVulnerability[]>>(new Map());
  const [riskScore, setRiskScore] = useState<RiskScore | null>(null);
  const [aiExplanations, setAiExplanations] = useState<Map<string, string>>(new Map());
  const [isScanning, setIsScanning] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [packages, setPackages] = useState<OSVPackage[]>([]);

  useEffect(() => {
    const runScan = async () => {
      try {
        // Get dependencies
        let deps: Map<string, { version: string; isDev: boolean }>;
        
        if (specificPackages && specificPackages.length > 0) {
          // Parse specific packages provided via command line
          deps = new Map();
          for (const pkg of specificPackages) {
            const match = pkg.match(/^(@?[^@]+)(?:@(.+))?$/);
            if (match) {
              deps.set(match[1], { version: match[2] || 'latest', isDev: false });
            }
          }
        } else {
          // Read from package.json
          deps = await npmInterceptor.getDependencies(cwd);
        }

        const pkgList: OSVPackage[] = Array.from(deps.entries()).map(([name, info]) => ({
          ecosystem: 'npm',
          name,
          version: info.version.replace(/^[\^~]/, ''), // Remove semver prefixes
        }));

        setPackages(pkgList);
        setProgress({ current: 0, total: pkgList.length, currentPackage: '' });

        // Scan each package
        const results = new Map<string, OSVVulnerability[]>();
        const explanations = new Map<string, string>();

        for (let i = 0; i < pkgList.length; i++) {
          const pkg = pkgList[i];
          const pkgKey = `${pkg.name}@${pkg.version}`;
          
          setProgress({
            current: i + 1,
            total: pkgList.length,
            currentPackage: pkgKey,
          });

          try {
            const vulns = await osvClient.queryPackage(pkg);
            results.set(pkgKey, vulns);

            // Generate AI explanations
            for (const vuln of vulns) {
              const explanation = riskCalculator.getAIExplanation(vuln);
              explanations.set(`${pkgKey}-${vuln.id}`, explanation);
            }
          } catch (err) {
            console.warn(`Failed to scan ${pkgKey}:`, err);
            results.set(pkgKey, []);
          }

          // Small delay to prevent rate limiting and show progress
          await new Promise(resolve => setTimeout(resolve, 50));
        }

        setVulnerabilities(results);
        setAiExplanations(explanations);

        // Calculate risk score
        const score = riskCalculator.calculateRiskScore(results);
        setRiskScore(score);

        setIsScanning(false);

        // Call completion callback
        onComplete?.({ riskScore: score, vulnerabilities: results });

        // Output JSON if requested
        if (jsonMode) {
          const report = formatter.formatJSON(score, results, (vuln) => 
            riskCalculator.getAIExplanation(vuln)
          );
          stdout.write(JSON.stringify(report, null, 2) + '\n');
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error occurred');
        setIsScanning(false);
      }
    };

    runScan();
  }, [cwd, jsonMode, specificPackages]);

  if (error) {
    return (
      <Box flexDirection="column">
        <Text color="red" bold>
          ❌ Error: {error}
        </Text>
      </Box>
    );
  }

  if (jsonMode) {
    // In JSON mode, only show minimal output during scan
    if (isScanning) {
      return (
        <Box>
          <Text color="gray">
            Scanning {progress.current}/{progress.total}: {progress.currentPackage}
          </Text>
        </Box>
      );
    }
    // Results are already output to stdout
    return null;
  }

  return (
    <Box flexDirection="column" padding={1}>
      {/* Header */}
      <Box marginBottom={1}>
        <Text bold color="cyan">
          🔒 SENTINEL GUARD - AI Security Auditor
        </Text>
      </Box>

      {/* Progress */}
      {isScanning && (
        <Box flexDirection="column" marginBottom={2}>
          <Box>
            <Text color="yellow">
              <Spinner type="dots" />
            </Text>
            <Text> </Text>
            <Text>Scanning dependencies...</Text>
          </Box>
          <Box marginTop={1}>
            <Text color="gray">
              {progress.current}/{progress.total} packages
            </Text>
          </Box>
          {progress.currentPackage && (
            <Box marginTop={1}>
              <Text color="blue">📦 {progress.currentPackage}</Text>
            </Box>
          )}
          
          {/* Progress bar */}
          <Box marginTop={1}>
            <Text color="green">
              {'█'.repeat(Math.floor((progress.current / progress.total) * 30))}
            </Text>
            <Text color="gray">
              {'░'.repeat(30 - Math.floor((progress.current / progress.total) * 30))}
            </Text>
            <Text> </Text>
            <Text color="gray">
              {Math.round((progress.current / progress.total) * 100)}%
            </Text>
          </Box>
        </Box>
      )}

      {/* Results */}
      {!isScanning && riskScore && (
        <Box flexDirection="column">
          {/* Risk Score */}
          <Box 
            borderStyle="round" 
            borderColor={
              riskScore.total >= 80 ? 'red' :
              riskScore.total >= 60 ? 'redBright' :
              riskScore.total >= 40 ? 'yellow' :
              riskScore.total >= 20 ? 'green' : 'greenBright'
            }
            paddingX={2}
            paddingY={1}
            marginBottom={1}
          >
            <RiskBadge score={riskScore.total} size="large" />
          </Box>

          {/* Summary */}
          <Box flexDirection="column" marginY={1}>
            <Text>
              <Text color="gray">Total Packages: </Text>
              <Text bold>{riskScore.totalPackages}</Text>
            </Text>
            <Text>
              <Text color="gray">Vulnerable: </Text>
              <Text 
                color={riskScore.vulnerablePackages > 0 ? 'red' : 'green'}
                bold
              >
                {riskScore.vulnerablePackages}
              </Text>
            </Text>
            {riskScore.cvssAverage > 0 && (
              <Text>
                <Text color="gray">Avg CVSS: </Text>
                <Text bold>{riskScore.cvssAverage}</Text>
              </Text>
            )}
          </Box>

          {/* Breakdown */}
          <Box flexDirection="column" marginY={1}>
            <Text bold underline>Breakdown</Text>
            {riskScore.breakdown.critical > 0 && (
              <Text color="red">
                🔴 Critical: {riskScore.breakdown.critical}
              </Text>
            )}
            {riskScore.breakdown.high > 0 && (
              <Text color="redBright">
                🟠 High: {riskScore.breakdown.high}
              </Text>
            )}
            {riskScore.breakdown.medium > 0 && (
              <Text color="yellow">
                🟡 Medium: {riskScore.breakdown.medium}
              </Text>
            )}
            {riskScore.breakdown.low > 0 && (
              <Text color="green">
                🟢 Low: {riskScore.breakdown.low}
              </Text>
            )}
            {riskScore.total === 0 && (
              <Text color="greenBright">
                ✅ No vulnerabilities found!
              </Text>
            )}
          </Box>

          {/* Vulnerability List */}
          <Box marginTop={2}>
            <VulnerabilityList 
              vulnerabilities={vulnerabilities}
              aiExplanations={aiExplanations}
              maxDisplay={10}
              showDetails={true}
            />
          </Box>

          {/* Recommendations */}
          <Box marginTop={2}>
            <RecommendationPanel vulnerabilities={vulnerabilities} />
          </Box>

          {/* Footer */}
          <Box marginTop={2} paddingTop={1} borderStyle="singleTop" borderColor="gray">
            <Text color="gray" dimColor>
              Scanned at: {new Date().toLocaleString()}
            </Text>
          </Box>
        </Box>
      )}
    </Box>
  );
};

export default Scanner;
