/**
 * SolGuard Configuration
 * 
 * Loads config from solguard.config.json, .solguardrc, or package.json
 */

import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

export interface SolGuardConfig {
  // Patterns to disable
  disable?: string[];
  
  // Minimum severity to report
  minSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  
  // Files/directories to ignore
  ignore?: string[];
  
  // Custom rules (future)
  rules?: Record<string, 'error' | 'warn' | 'off'>;
  
  // Output preferences
  output?: {
    format?: 'terminal' | 'json' | 'markdown';
    colors?: boolean;
  };
  
  // CI settings
  ci?: {
    failOn?: 'critical' | 'high' | 'medium' | 'low' | 'any';
    generateSarif?: boolean;
  };
}

const CONFIG_FILES = [
  'solguard.config.json',
  '.solguardrc',
  '.solguardrc.json',
];

/**
 * Load configuration from the project root
 */
export function loadConfig(projectPath: string): SolGuardConfig {
  // Try dedicated config files
  for (const filename of CONFIG_FILES) {
    const configPath = join(projectPath, filename);
    if (existsSync(configPath)) {
      try {
        const content = readFileSync(configPath, 'utf-8');
        return JSON.parse(content);
      } catch (e) {
        console.warn(`Failed to parse ${filename}: ${e}`);
      }
    }
  }
  
  // Try package.json
  const packagePath = join(projectPath, 'package.json');
  if (existsSync(packagePath)) {
    try {
      const pkg = JSON.parse(readFileSync(packagePath, 'utf-8'));
      if (pkg.solguard) {
        return pkg.solguard;
      }
    } catch {
      // Ignore
    }
  }
  
  // Try Cargo.toml metadata (Rust projects)
  const cargoPath = join(projectPath, 'Cargo.toml');
  if (existsSync(cargoPath)) {
    try {
      const cargo = readFileSync(cargoPath, 'utf-8');
      // Basic TOML parsing for [package.metadata.solguard]
      const match = cargo.match(/\[package\.metadata\.solguard\]\s*([\s\S]*?)(?:\n\[|$)/);
      if (match) {
        // Very basic TOML -> JSON conversion
        const tomlSection = match[1];
        const config: any = {};
        
        for (const line of tomlSection.split('\n')) {
          const kvMatch = line.match(/^(\w+)\s*=\s*(.+)$/);
          if (kvMatch) {
            const [, key, value] = kvMatch;
            if (value.startsWith('[')) {
              config[key] = JSON.parse(value.replace(/'/g, '"'));
            } else if (value.startsWith('"') || value.startsWith("'")) {
              config[key] = value.slice(1, -1);
            } else if (value === 'true' || value === 'false') {
              config[key] = value === 'true';
            } else {
              config[key] = value;
            }
          }
        }
        
        return config;
      }
    } catch {
      // Ignore
    }
  }
  
  // Default config
  return {};
}

/**
 * Merge configs (cli args override config file)
 */
export function mergeConfig(
  fileConfig: SolGuardConfig,
  cliOptions: Partial<SolGuardConfig>
): SolGuardConfig {
  return {
    ...fileConfig,
    ...cliOptions,
    output: {
      ...fileConfig.output,
      ...cliOptions.output,
    },
    ci: {
      ...fileConfig.ci,
      ...cliOptions.ci,
    },
  };
}

/**
 * Check if a pattern is disabled
 */
export function isPatternDisabled(config: SolGuardConfig, patternId: string): boolean {
  return config.disable?.includes(patternId) || false;
}

/**
 * Check if a path should be ignored
 */
export function shouldIgnore(config: SolGuardConfig, filePath: string): boolean {
  if (!config.ignore) return false;
  
  return config.ignore.some(pattern => {
    // Simple glob matching
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      return regex.test(filePath);
    }
    return filePath.includes(pattern);
  });
}

/**
 * Generate example config file
 */
export function generateExampleConfig(): string {
  return JSON.stringify({
    // Disable specific patterns
    disable: [],
    
    // Minimum severity to report
    minSeverity: 'low',
    
    // Files/directories to ignore
    ignore: [
      'tests/**',
      '**/*.test.rs',
    ],
    
    // Configure individual rules
    rules: {
      SOL001: 'error',
      SOL002: 'error',
      SOL003: 'warn',
    },
    
    // Output preferences
    output: {
      format: 'terminal',
      colors: true,
    },
    
    // CI settings
    ci: {
      failOn: 'high',
      generateSarif: true,
    },
  }, null, 2);
}
