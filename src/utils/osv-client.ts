import axios, { AxiosInstance } from 'axios';

export interface OSVPackage {
  ecosystem: string;
  name: string;
  version?: string;
}

export interface OSVVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{
    type: string;
    score: string;
  }>;
  aliases?: string[];
  modified?: string;
  published?: string;
  references?: Array<{
    type: string;
    url: string;
  }>;
  affected?: Array<{
    package: {
      ecosystem: string;
      name: string;
    };
    ranges?: Array<{
      type: string;
      events: Array<{
        introduced?: string;
        fixed?: string;
      }>;
    }>;
    versions?: string[];
  }>;
}

export interface OSVQueryResponse {
  vulns?: OSVVulnerability[];
}

export class OSVClient {
  private client: AxiosInstance;
  private baseURL = 'https://api.osv.dev/v1';

  constructor() {
    this.client = axios.create({
      baseURL: this.baseURL,
      headers: {
        'Content-Type': 'application/json',
      },
      timeout: 30000,
    });
  }

  /**
   * Query OSV database for vulnerabilities affecting a specific package version
   */
  async queryPackage(pkg: OSVPackage): Promise<OSVVulnerability[]> {
    try {
      const response = await this.client.post<OSVQueryResponse>('/query', {
        package: {
          ecosystem: pkg.ecosystem,
          name: pkg.name,
        },
        version: pkg.version,
      });

      return response.data.vulns || [];
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 404) {
          return []; // No vulnerabilities found
        }
        throw new Error(`OSV API error: ${error.message}`);
      }
      throw error;
    }
  }

  /**
   * Batch query multiple packages
   */
  async queryPackages(packages: OSVPackage[]): Promise<Map<string, OSVVulnerability[]>> {
    const results = new Map<string, OSVVulnerability[]>();
    
    // Process in batches of 10 to avoid rate limiting
    const batchSize = 10;
    for (let i = 0; i < packages.length; i += batchSize) {
      const batch = packages.slice(i, i + batchSize);
      const batchPromises = batch.map(async (pkg) => {
        const key = `${pkg.name}@${pkg.version || 'latest'}`;
        try {
          const vulns = await this.queryPackage(pkg);
          return { key, vulns };
        } catch (error) {
          console.warn(`Failed to query ${key}:`, error);
          return { key, vulns: [] };
        }
      });

      const batchResults = await Promise.all(batchPromises);
      batchResults.forEach(({ key, vulns }) => {
        results.set(key, vulns);
      });

      // Small delay between batches
      if (i + batchSize < packages.length) {
        await this.delay(100);
      }
    }

    return results;
  }

  /**
   * Get vulnerability details by ID
   */
  async getVulnerability(id: string): Promise<OSVVulnerability | null> {
    try {
      const response = await this.client.get<OSVVulnerability>(`/vulns/${id}`);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Determine if a vulnerability affects a specific version
   */
  affectsVersion(vuln: OSVVulnerability, version: string): boolean {
    if (!vuln.affected) return false;

    for (const affected of vuln.affected) {
      if (affected.versions?.includes(version)) {
        return true;
      }

      if (affected.ranges) {
        for (const range of affected.ranges) {
          if (range.type === 'SEMVER' || range.type === 'ECOSYSTEM') {
            let introduced: string | undefined;
            let fixed: string | undefined;

            for (const event of range.events) {
              if (event.introduced) introduced = event.introduced;
              if (event.fixed) fixed = event.fixed;
            }

            if (this.versionInRange(version, introduced, fixed)) {
              return true;
            }
          }
        }
      }
    }

    return false;
  }

  private versionInRange(version: string, introduced?: string, fixed?: string): boolean {
    // Simple semver comparison
    const compareVersions = (a: string, b: string): number => {
      const partsA = a.split('.').map(Number);
      const partsB = b.split('.').map(Number);
      
      for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
        const numA = partsA[i] || 0;
        const numB = partsB[i] || 0;
        if (numA < numB) return -1;
        if (numA > numB) return 1;
      }
      return 0;
    };

    if (introduced && compareVersions(version, introduced) < 0) {
      return false;
    }

    if (fixed && compareVersions(version, fixed) >= 0) {
      return false;
    }

    return true;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

export const osvClient = new OSVClient();
