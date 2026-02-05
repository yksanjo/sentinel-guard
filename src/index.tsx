#!/usr/bin/env node
import React from 'react';
import { render } from 'ink';
import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

import { Scanner } from './components/Scanner.js';
import { OSVClient } from './utils/osv-client.js';
import { RiskCalculator } from './utils/risk-calculator.js';
import { NPMInterceptor } from './utils/npm-interceptor.js';
import { Formatter } from './utils/formatter.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const osvClient = new OSVClient();
const riskCalculator = new RiskCalculator();
const npmInterceptor = new NPMInterceptor();
const formatter = new Formatter();

const program = new Command();

program
  .name('sentinel-guard')
  .description('AI Security Auditor for Dependency Trees')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan dependencies for vulnerabilities')
  .argument('[packages...]', 'Specific packages to scan (optional)')
  .option('-j, --json', 'Output results as JSON for CI/CD integration')
  .option('-f, --fix', 'Auto-suggest and apply safe updates')
  .option('-d, --directory <path>', 'Directory containing package.json', process.cwd())
  .option('--severity <level>', 'Minimum severity level to report (critical, high, medium, low)', 'low')
  .action(async (packages: string[], options) => {
    try {
      // Check if package.json exists
      try {
        await fs.access(path.join(options.directory, 'package.json'));
      } catch {
        if (!packages || packages.length === 0) {
          console.error(chalk.red('❌ Error: package.json not found in the specified directory.'));
          console.error(chalk.gray('   Run this command in a Node.js project directory or specify packages to scan.'));
          process.exit(1);
        }
      }

      if (options.json) {
        // JSON mode - minimal output
        const deps = packages.length > 0 
          ? new Map(packages.map(p => {
              const match = p.match(/^(@?[^@]+)(?:@(.+))?$/);
              return [match?.[1] || p, { version: match?.[2] || 'latest', isDev: false }];
            }))
          : await npmInterceptor.getDependencies(options.directory);

        const pkgList = Array.from(deps.entries()).map(([name, info]) => ({
          ecosystem: 'npm' as const,
          name,
          version: info.version.replace(/^[\^~]/, ''),
        }));

        const results = new Map();
        for (const pkg of pkgList) {
          const pkgKey = `${pkg.name}@${pkg.version}`;
          process.stderr.write(`Scanning ${pkgKey}...\n`);
          try {
            const vulns = await osvClient.queryPackage(pkg);
            results.set(pkgKey, vulns);
          } catch (err) {
            results.set(pkgKey, []);
          }
        }

        const riskScore = riskCalculator.calculateRiskScore(results);
        const report = formatter.formatJSON(
          riskScore, 
          results, 
          (vuln) => riskCalculator.getAIExplanation(vuln)
        );

        // Filter by severity if specified
        if (options.severity && options.severity !== 'low') {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
          const minLevel = severityOrder[options.severity as keyof typeof severityOrder] || 0;
          report.vulnerabilities = report.vulnerabilities.filter(v => 
            severityOrder[v.severity.toLowerCase() as keyof typeof severityOrder] >= minLevel
          );
        }

        console.log(JSON.stringify(report, null, 2));
        
        // Exit with error code if critical vulnerabilities found
        if (riskScore.breakdown.critical > 0) {
          process.exit(1);
        }
      } else {
        // Interactive mode with Ink
        const { waitUntilExit } = render(
          <Scanner 
            cwd={options.directory}
            jsonMode={false}
            fixMode={options.fix}
            specificPackages={packages.length > 0 ? packages : undefined}
          />,
          { exitOnCtrlC: true }
        );

        await waitUntilExit();
      }
    } catch (error) {
      console.error(chalk.red('❌ Error:'), error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

program
  .command('check')
  .description('Quick check a specific package for vulnerabilities')
  .argument('<package>', 'Package name (e.g., lodash@4.17.20)')
  .option('-j, --json', 'Output results as JSON')
  .action(async (pkgStr: string, options) => {
    try {
      const match = pkgStr.match(/^(@?[^@]+)(?:@(.+))?$/);
      if (!match) {
        console.error(chalk.red('❌ Invalid package format. Use: name@version'));
        process.exit(1);
      }

      const pkg = {
        ecosystem: 'npm' as const,
        name: match[1],
        version: match[2] || 'latest',
      };

      if (!options.json) {
        console.log(chalk.blue(`🔍 Checking ${pkg.name}@${pkg.version}...\n`));
      }

      const vulns = await osvClient.queryPackage(pkg);

      if (options.json) {
        const pkgKey = `${pkg.name}@${pkg.version}`;
        const results = new Map([[pkgKey, vulns]]);
        const riskScore = riskCalculator.calculateRiskScore(results);
        const report = formatter.formatJSON(
          riskScore,
          results,
          (v) => riskCalculator.getAIExplanation(v)
        );
        console.log(JSON.stringify(report, null, 2));
      } else {
        if (vulns.length === 0) {
          console.log(chalk.green('✅ No vulnerabilities found!'));
        } else {
          console.log(chalk.red(`❌ Found ${vulns.length} vulnerability/vulnerabilities:\n`));
          
          for (const vuln of vulns) {
            const severity = riskCalculator.getSeverity(vuln);
            const color = severity === 'CRITICAL' ? 'red' :
                         severity === 'HIGH' ? 'redBright' :
                         severity === 'MEDIUM' ? 'yellow' : 'green';
            
            console.log(chalk[color](`${severity}: ${vuln.id}`));
            if (vuln.summary) {
              console.log(`  ${vuln.summary}`);
            }
            
            const aiExplanation = riskCalculator.getAIExplanation(vuln);
            console.log(chalk.magenta(`  🤖 AI: ${aiExplanation}`));
            
            const recommendation = formatter.getUpgradeRecommendation(vuln);
            console.log(chalk.yellow(`  💡 ${recommendation}`));
            console.log();
          }

          // Show alternatives
          const alternatives = formatter.getSafeAlternatives(pkg.name);
          if (alternatives.length > 0 && alternatives[0].alternative !== pkg.name) {
            console.log(chalk.cyan('🔄 Safer Alternatives:'));
            for (const alt of alternatives.slice(0, 3)) {
              console.log(`  • ${chalk.bold(alt.alternative)}: ${alt.reason}`);
            }
          }
        }
      }

      // Exit with error if vulnerabilities found
      if (vulns.length > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red('❌ Error:'), error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

program
  .command('hook')
  .description('Install or remove npm hook for automatic scanning')
  .argument('<action>', 'Action: install or remove')
  .option('-d, --directory <path>', 'Project directory', process.cwd())
  .action(async (action: string, options) => {
    try {
      if (action === 'install') {
        await npmInterceptor.installHook(options.directory);
        console.log(chalk.green('\n✅ Hook installed successfully!'));
        console.log(chalk.gray('\nTo complete setup, add this to your shell profile:'));
        console.log(chalk.cyan(`  alias npm="${path.join(options.directory, '.sentinel', 'npm-hook.sh')}"`));
      } else if (action === 'remove') {
        await npmInterceptor.removeHook(options.directory);
        console.log(chalk.green('✅ Hook removed successfully'));
        console.log(chalk.gray('Remove the alias from your shell profile if you added it.'));
      } else {
        console.error(chalk.red('❌ Invalid action. Use: install or remove'));
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red('❌ Error:'), error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

program
  .command('explain')
  .description('Get AI explanation for a vulnerability ID')
  .argument('<vulnId>', 'Vulnerability ID (e.g., GHSA-xxxx-xxxx-xxxx)')
  .action(async (vulnId: string) => {
    try {
      console.log(chalk.blue(`🔍 Fetching details for ${vulnId}...\n`));
      
      const vuln = await osvClient.getVulnerability(vulnId);
      
      if (!vuln) {
        console.error(chalk.red('❌ Vulnerability not found'));
        process.exit(1);
      }

      console.log(chalk.bold(vuln.id));
      if (vuln.summary) {
        console.log(chalk.white(vuln.summary));
      }
      if (vuln.details) {
        console.log(chalk.gray(vuln.details.substring(0, 500)));
        if (vuln.details.length > 500) {
          console.log(chalk.gray('...'));
        }
      }

      console.log(chalk.magenta(`\n🤖 AI Analysis:`));
      console.log(riskCalculator.getAIExplanation(vuln));

      if (vuln.references && vuln.references.length > 0) {
        console.log(chalk.cyan('\n📎 References:'));
        for (const ref of vuln.references.slice(0, 5)) {
          console.log(`  • ${ref.url}`);
        }
      }
    } catch (error) {
      console.error(chalk.red('❌ Error:'), error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

// Default action when no command is provided
program
  .argument('[path]', 'Path to project directory', process.cwd())
  .option('-j, --json', 'Output results as JSON')
  .action(async (projectPath: string, options) => {
    try {
      // Check if package.json exists
      try {
        await fs.access(path.join(projectPath, 'package.json'));
      } catch {
        program.help();
        return;
      }

      if (options.json) {
        const deps = await npmInterceptor.getDependencies(projectPath);
        const pkgList = Array.from(deps.entries()).map(([name, info]) => ({
          ecosystem: 'npm' as const,
          name,
          version: info.version.replace(/^[\^~]/, ''),
        }));

        const results = new Map();
        for (const pkg of pkgList) {
          const pkgKey = `${pkg.name}@${pkg.version}`;
          try {
            const vulns = await osvClient.queryPackage(pkg);
            results.set(pkgKey, vulns);
          } catch (err) {
            results.set(pkgKey, []);
          }
        }

        const riskScore = riskCalculator.calculateRiskScore(results);
        const report = formatter.formatJSON(
          riskScore, 
          results, 
          (vuln) => riskCalculator.getAIExplanation(vuln)
        );
        console.log(JSON.stringify(report, null, 2));
      } else {
        const { waitUntilExit } = render(
          <Scanner cwd={projectPath} />,
          { exitOnCtrlC: true }
        );
        await waitUntilExit();
      }
    } catch (error) {
      console.error(chalk.red('❌ Error:'), error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

program.parse();
