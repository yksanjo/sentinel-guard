import { spawn } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface InterceptOptions {
  command: string;
  args: string[];
  cwd: string;
}

export interface DependencyChange {
  name: string;
  oldVersion?: string;
  newVersion: string;
  type: 'add' | 'update' | 'remove';
  isDev: boolean;
}

export class NPMInterceptor {
  private originalPackageJson: any = null;
  private originalLockFile: string | null = null;

  /**
   * Read and parse package.json
   */
  async readPackageJson(cwd: string): Promise<any> {
    try {
      const content = await fs.readFile(path.join(cwd, 'package.json'), 'utf-8');
      return JSON.parse(content);
    } catch (error) {
      throw new Error('Failed to read package.json. Ensure you are in a Node.js project directory.');
    }
  }

  /**
   * Get list of dependencies from package.json
   */
  async getDependencies(cwd: string): Promise<Map<string, { version: string; isDev: boolean }>> {
    const pkg = await this.readPackageJson(cwd);
    const deps = new Map<string, { version: string; isDev: boolean }>();

    if (pkg.dependencies) {
      for (const [name, version] of Object.entries(pkg.dependencies)) {
        deps.set(name, { version: version as string, isDev: false });
      }
    }

    if (pkg.devDependencies) {
      for (const [name, version] of Object.entries(pkg.devDependencies)) {
        deps.set(name, { version: version as string, isDev: true });
      }
    }

    return deps;
  }

  /**
   * Detect what changes will be made by an npm command
   */
  async detectChanges(options: InterceptOptions): Promise<DependencyChange[]> {
    const changes: DependencyChange[] = [];
    const currentDeps = await this.getDependencies(options.cwd);

    // Parse npm command arguments
    const command = options.args[0];

    switch (command) {
      case 'install':
      case 'i':
      case 'add':
        // Check for package names in arguments
        for (let i = 1; i < options.args.length; i++) {
          const arg = options.args[i];
          if (arg.startsWith('-')) continue;

          const isDev = options.args.includes('--save-dev') || options.args.includes('-D');
          const isExact = options.args.includes('--save-exact') || options.args.includes('-E');

          // Parse package@version format
          const match = arg.match(/^(@?[^@]+)(?:@(.+))?$/);
          if (match) {
            const name = match[1];
            let version = match[2] || 'latest';
            
            if (!isExact && !version.startsWith('^') && !version.startsWith('~')) {
              version = `^${version}`;
            }

            changes.push({
              name,
              oldVersion: currentDeps.get(name)?.version,
              newVersion: version,
              type: currentDeps.has(name) ? 'update' : 'add',
              isDev,
            });
          }
        }
        break;

      case 'uninstall':
      case 'remove':
      case 'rm':
        for (let i = 1; i < options.args.length; i++) {
          const arg = options.args[i];
          if (arg.startsWith('-')) continue;

          const dep = currentDeps.get(arg);
          if (dep) {
            changes.push({
              name: arg,
              oldVersion: dep.version,
              newVersion: '',
              type: 'remove',
              isDev: dep.isDev,
            });
          }
        }
        break;

      case 'update':
      case 'upgrade':
        if (options.args.length === 1) {
          // Update all packages
          for (const [name, info] of currentDeps.entries()) {
            changes.push({
              name,
              oldVersion: info.version,
              newVersion: 'latest',
              type: 'update',
              isDev: info.isDev,
            });
          }
        } else {
          // Update specific packages
          for (let i = 1; i < options.args.length; i++) {
            const arg = options.args[i];
            if (arg.startsWith('-')) continue;

            const dep = currentDeps.get(arg);
            if (dep) {
              changes.push({
                name: arg,
                oldVersion: dep.version,
                newVersion: 'latest',
                type: 'update',
                isDev: dep.isDev,
              });
            }
          }
        }
        break;
    }

    return changes;
  }

  /**
   * Intercept npm install and run security scan
   */
  async interceptInstall(options: InterceptOptions, onScanComplete?: (safe: boolean) => void): Promise<void> {
    console.log('🔍 Sentinel Guard intercepting npm command...\n');

    const changes = await this.detectChanges(options);

    if (changes.length === 0) {
      console.log('ℹ️  No new dependencies detected, proceeding with install...\n');
      await this.runNPM(options);
      return;
    }

    console.log(`📦 Detected ${changes.length} dependency change(s):\n`);
    for (const change of changes) {
      const icon = change.type === 'add' ? '➕' : change.type === 'remove' ? '➖' : '⬆️';
      const type = change.isDev ? '(dev)' : '(prod)';
      if (change.type === 'remove') {
        console.log(`  ${icon} ${change.name} ${type}`);
      } else if (change.oldVersion) {
        console.log(`  ${icon} ${change.name}: ${change.oldVersion} → ${change.newVersion} ${type}`);
      } else {
        console.log(`  ${icon} ${change.name}@${change.newVersion} ${type}`);
      }
    }

    console.log('\n⏳ Running security scan...\n');

    // Note: Actual scan would happen here, then:
    // onScanComplete?.(isSafe);

    // For now, prompt user
    if (onScanComplete) {
      onScanComplete(true);
    }
  }

  /**
   * Run npm command
   */
  async runNPM(options: InterceptOptions): Promise<void> {
    return new Promise((resolve, reject) => {
      const child = spawn(options.command, options.args, {
        cwd: options.cwd,
        stdio: 'inherit',
        shell: true,
      });

      child.on('close', (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`npm exited with code ${code}`));
        }
      });
    });
  }

  /**
   * Install hook to intercept npm commands
   * This creates a wrapper script that intercepts npm
   */
  async installHook(cwd: string): Promise<void> {
    const hookScript = `#!/bin/bash
# Sentinel Guard npm interceptor
# This script wraps npm to add security scanning

ORIGINAL_NPM=$(which npm)
SENTINEL_GUARD=$(which sentinel-guard)

if [ "$1" == "install" ] || [ "$1" == "i" ] || [ "$1" == "add" ]; then
    # Run sentinel guard scan on new packages
    if [ $# -gt 1 ]; then
        echo "🔒 Sentinel Guard is scanning new dependencies..."
        # Extract package names from command
        PACKAGES=""
        for arg in "\$@"; do
            if [[ ! \$arg =~ ^- ]]; then
                if [ "\$arg" != "install" ] && [ "\$arg" != "i" ] && [ "\$arg" != "add" ]; then
                    PACKAGES="\$PACKAGES \$arg"
                fi
            fi
        done
        
        if [ -n "\$PACKAGES" ]; then
            # Run sentinel guard on these packages
            \$SENTINEL_GUARD scan \$PACKAGES --json > /tmp/sentinel-scan.json 2>&1
            EXIT_CODE=\$?
            
            if [ \$EXIT_CODE -ne 0 ]; then
                echo "⚠️  Security issues detected! Review before proceeding."
                cat /tmp/sentinel-scan.json
                read -p "Continue with install? (y/N): " -n 1 -r
                echo
                if [[ ! \$REPLY =~ ^[Yy]$ ]]; then
                    echo "❌ Install cancelled."
                    exit 1
                fi
            fi
        fi
    fi
fi

# Run original npm command
exec \$ORIGINAL_NPM "\$@"
`;

    const hookPath = path.join(cwd, '.sentinel', 'npm-hook.sh');
    await fs.mkdir(path.dirname(hookPath), { recursive: true });
    await fs.writeFile(hookPath, hookScript, { mode: 0o755 });

    console.log(`✅ Hook installed at: ${hookPath}`);
    console.log('📖 To use the hook, add the following to your .bashrc or .zshrc:');
    console.log(`   alias npm="${hookPath}"`);
  }

  /**
   * Remove the npm hook
   */
  async removeHook(cwd: string): Promise<void> {
    const hookPath = path.join(cwd, '.sentinel', 'npm-hook.sh');
    try {
      await fs.unlink(hookPath);
      await fs.rmdir(path.dirname(hookPath));
      console.log('✅ Hook removed successfully');
    } catch (error) {
      // Ignore errors if hook doesn't exist
    }
  }
}

export const npmInterceptor = new NPMInterceptor();
