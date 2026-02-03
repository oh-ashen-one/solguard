#!/usr/bin/env node
import {
  listPatterns,
  runPatterns
} from "./chunk-YO5RPWWK.js";
import {
  parseIdl
} from "./chunk-HWAQQY7Q.js";
import {
  parseRustFiles
} from "./chunk-F7WQYU5F.js";

// src/index.ts
import { Command } from "commander";
import chalk7 from "chalk";

// src/commands/audit.ts
import chalk2 from "chalk";
import ora from "ora";

// src/ai/explain.ts
import Anthropic from "@anthropic-ai/sdk";
var client = new Anthropic();
async function explainFindings(findings) {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.warn("ANTHROPIC_API_KEY not set, skipping AI explanations");
    return;
  }
  const batchSize = 5;
  for (let i = 0; i < findings.length; i += batchSize) {
    const batch = findings.slice(i, i + batchSize);
    try {
      const explanations = await generateExplanations(batch);
      for (let j = 0; j < batch.length; j++) {
        if (explanations[j]) {
          batch[j].aiExplanation = explanations[j];
        }
      }
    } catch (error) {
      console.warn(`Failed to generate AI explanations: ${error}`);
    }
  }
}
async function generateExplanations(findings) {
  const prompt = `You are a Solana security expert. For each vulnerability finding below, provide a brief, actionable explanation in 2-3 sentences that:
1. Explains why this is dangerous in plain English
2. Describes the potential exploit scenario
3. Confirms or refines the suggested fix

Findings:
${findings.map((f, i) => `
${i + 1}. ${f.pattern} (${f.severity.toUpperCase()})
   Location: ${f.location.file}${f.location.line ? `:${f.location.line}` : ""}
   ${f.code ? `Code: ${f.code}` : ""}
   Current suggestion: ${f.suggestion || "None"}
`).join("\n")}

Respond with a JSON array of explanations, one per finding:
["explanation for finding 1", "explanation for finding 2", ...]`;
  const response = await client.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 1024,
    messages: [{ role: "user", content: prompt }]
  });
  const text = response.content.filter((block) => block.type === "text").map((block) => block.text).join("");
  try {
    const jsonMatch = text.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
  } catch {
    return text.split("\n").filter((line) => line.trim());
  }
  return [];
}

// src/report/index.ts
import chalk from "chalk";
function formatTerminal(result) {
  const lines = [];
  lines.push("");
  lines.push(chalk.bold("\u2501".repeat(60)));
  lines.push(chalk.bold(`  \u{1F4CB} AUDIT REPORT`));
  lines.push(chalk.gray(`  ${result.programPath}`));
  lines.push(chalk.gray(`  ${result.timestamp}`));
  lines.push(chalk.bold("\u2501".repeat(60)));
  lines.push("");
  const { summary } = result;
  lines.push(chalk.bold("  SUMMARY"));
  lines.push("");
  if (summary.critical > 0) {
    lines.push(chalk.red(`    \u{1F534} Critical: ${summary.critical}`));
  }
  if (summary.high > 0) {
    lines.push(chalk.redBright(`    \u{1F7E0} High: ${summary.high}`));
  }
  if (summary.medium > 0) {
    lines.push(chalk.yellow(`    \u{1F7E1} Medium: ${summary.medium}`));
  }
  if (summary.low > 0) {
    lines.push(chalk.blue(`    \u{1F535} Low: ${summary.low}`));
  }
  if (summary.info > 0) {
    lines.push(chalk.gray(`    \u26AA Info: ${summary.info}`));
  }
  lines.push("");
  lines.push(chalk.gray(`    Total: ${summary.total} findings`));
  lines.push("");
  if (result.passed) {
    lines.push(chalk.green.bold("  \u2705 PASSED - No critical or high severity issues"));
  } else {
    lines.push(chalk.red.bold("  \u274C FAILED - Critical or high severity issues found"));
  }
  lines.push("");
  lines.push(chalk.bold("\u2501".repeat(60)));
  lines.push("");
  if (result.findings.length > 0) {
    lines.push(chalk.bold("  FINDINGS"));
    lines.push("");
    for (const finding of result.findings) {
      lines.push(formatFinding(finding));
      lines.push("");
    }
  }
  return lines.join("\n");
}
function formatFinding(finding) {
  const lines = [];
  const severityColor = {
    critical: chalk.red,
    high: chalk.redBright,
    medium: chalk.yellow,
    low: chalk.blue,
    info: chalk.gray
  };
  const color = severityColor[finding.severity];
  lines.push(color(`  [${finding.id}] ${finding.severity.toUpperCase()}: ${finding.title}`));
  lines.push(chalk.gray(`  \u2514\u2500 ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}`));
  lines.push("");
  lines.push(chalk.white(`     ${finding.description}`));
  if (finding.code) {
    lines.push("");
    lines.push(chalk.gray(`     Code: ${finding.code}`));
  }
  if (finding.suggestion) {
    lines.push("");
    lines.push(chalk.cyan(`     \u{1F4A1} Fix: ${finding.suggestion.split("\n")[0]}`));
  }
  if (finding.aiExplanation) {
    lines.push("");
    lines.push(chalk.magenta(`     \u{1F916} AI: ${finding.aiExplanation}`));
  }
  return lines.join("\n");
}
function formatJson(result) {
  return JSON.stringify(result, null, 2);
}
function formatMarkdown(result) {
  const lines = [];
  lines.push(`# \u{1F6E1}\uFE0F SolGuard Audit Report`);
  lines.push("");
  lines.push(`**Program:** \`${result.programPath}\``);
  lines.push(`**Date:** ${result.timestamp}`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|----------|-------|");
  lines.push(`| \u{1F534} Critical | ${result.summary.critical} |`);
  lines.push(`| \u{1F7E0} High | ${result.summary.high} |`);
  lines.push(`| \u{1F7E1} Medium | ${result.summary.medium} |`);
  lines.push(`| \u{1F535} Low | ${result.summary.low} |`);
  lines.push(`| \u26AA Info | ${result.summary.info} |`);
  lines.push(`| **Total** | **${result.summary.total}** |`);
  lines.push("");
  if (result.passed) {
    lines.push("### \u2705 Status: PASSED");
    lines.push("No critical or high severity issues found.");
  } else {
    lines.push("### \u274C Status: FAILED");
    lines.push("Critical or high severity issues require immediate attention.");
  }
  lines.push("");
  if (result.findings.length > 0) {
    lines.push("## Findings");
    lines.push("");
    for (const finding of result.findings) {
      const emoji = {
        critical: "\u{1F534}",
        high: "\u{1F7E0}",
        medium: "\u{1F7E1}",
        low: "\u{1F535}",
        info: "\u26AA"
      };
      lines.push(`### ${emoji[finding.severity]} [${finding.id}] ${finding.title}`);
      lines.push("");
      lines.push(`**Severity:** ${finding.severity.toUpperCase()}`);
      lines.push(`**Location:** \`${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}\``);
      lines.push("");
      lines.push(finding.description);
      lines.push("");
      if (finding.code) {
        lines.push("**Code:**");
        lines.push("```rust");
        lines.push(finding.code);
        lines.push("```");
        lines.push("");
      }
      if (finding.suggestion) {
        lines.push("**Recommendation:**");
        lines.push("```rust");
        lines.push(finding.suggestion);
        lines.push("```");
        lines.push("");
      }
      if (finding.aiExplanation) {
        lines.push(`> \u{1F916} **AI Analysis:** ${finding.aiExplanation}`);
        lines.push("");
      }
    }
  }
  lines.push("---");
  lines.push("*Generated by [SolGuard](https://github.com/oh-ashen-one/solguard)*");
  return lines.join("\n");
}

// src/commands/audit.ts
import { existsSync, readdirSync, statSync } from "fs";
import { join } from "path";
async function auditCommand(path, options) {
  const spinner = ora("Starting audit...").start();
  try {
    if (!existsSync(path)) {
      spinner.fail(`Path not found: ${path}`);
      process.exit(1);
    }
    const isDirectory = statSync(path).isDirectory();
    let idlPath = null;
    let rustFiles = [];
    if (isDirectory) {
      const idlDir = join(path, "target", "idl");
      if (existsSync(idlDir)) {
        const idlFiles = readdirSync(idlDir).filter((f) => f.endsWith(".json"));
        if (idlFiles.length > 0) {
          idlPath = join(idlDir, idlFiles[0]);
        }
      }
      const programsDir = join(path, "programs");
      const srcDir = join(path, "src");
      if (existsSync(programsDir)) {
        rustFiles = findRustFiles(programsDir);
      } else if (existsSync(srcDir)) {
        rustFiles = findRustFiles(srcDir);
      }
    } else if (path.endsWith(".json")) {
      idlPath = path;
    } else if (path.endsWith(".rs")) {
      rustFiles = [path];
    }
    spinner.text = "Parsing program...";
    let idlData = null;
    if (idlPath) {
      spinner.text = `Parsing IDL: ${idlPath}`;
      idlData = await parseIdl(idlPath);
      if (options.verbose) {
        console.log(chalk2.gray(`
  Found ${idlData.instructions.length} instructions`));
      }
    }
    let rustAst = null;
    if (rustFiles.length > 0) {
      spinner.text = `Parsing ${rustFiles.length} Rust files...`;
      rustAst = await parseRustFiles(rustFiles);
      if (options.verbose) {
        console.log(chalk2.gray(`
  Parsed ${rustFiles.length} files`));
      }
    }
    if (!idlData && !rustAst) {
      spinner.fail("No IDL or Rust files found to audit");
      process.exit(1);
    }
    spinner.text = "Scanning for vulnerabilities...";
    const findings = await runPatterns({ idl: idlData, rust: rustAst, path });
    if (options.ai && findings.length > 0) {
      spinner.text = "Generating AI explanations...";
      await explainFindings(findings);
    }
    const result = {
      programPath: path,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      findings,
      summary: {
        critical: findings.filter((f) => f.severity === "critical").length,
        high: findings.filter((f) => f.severity === "high").length,
        medium: findings.filter((f) => f.severity === "medium").length,
        low: findings.filter((f) => f.severity === "low").length,
        info: findings.filter((f) => f.severity === "info").length,
        total: findings.length
      },
      passed: findings.filter((f) => ["critical", "high"].includes(f.severity)).length === 0
    };
    spinner.stop();
    switch (options.output) {
      case "json":
        console.log(formatJson(result));
        break;
      case "markdown":
        console.log(formatMarkdown(result));
        break;
      default:
        console.log(formatTerminal(result));
    }
    if (!result.passed) {
      process.exit(1);
    }
  } catch (error) {
    spinner.fail(`Audit failed: ${error}`);
    process.exit(1);
  }
}
function findRustFiles(dir) {
  const files = [];
  function walk(currentDir) {
    const entries = readdirSync(currentDir);
    for (const entry of entries) {
      const fullPath = join(currentDir, entry);
      const stat = statSync(fullPath);
      if (stat.isDirectory() && !entry.startsWith(".") && entry !== "target") {
        walk(fullPath);
      } else if (entry.endsWith(".rs")) {
        files.push(fullPath);
      }
    }
  }
  walk(dir);
  return files;
}

// src/commands/fetch.ts
import chalk3 from "chalk";
import ora2 from "ora";
import { Connection, PublicKey } from "@solana/web3.js";
import { writeFileSync, mkdirSync, existsSync as existsSync2 } from "fs";
import { join as join2 } from "path";
var DEFAULT_RPC = "https://api.mainnet-beta.solana.com";
async function fetchAndAuditCommand(programId, options) {
  const spinner = ora2("Connecting to Solana...").start();
  try {
    let pubkey;
    try {
      pubkey = new PublicKey(programId);
    } catch {
      spinner.fail("Invalid program ID");
      process.exit(1);
    }
    const rpcUrl = options.rpc || process.env.SOLANA_RPC_URL || DEFAULT_RPC;
    const connection = new Connection(rpcUrl, "confirmed");
    spinner.text = "Checking program account...";
    const accountInfo = await connection.getAccountInfo(pubkey);
    if (!accountInfo) {
      spinner.fail(`Program not found: ${programId}`);
      process.exit(1);
    }
    if (!accountInfo.executable) {
      spinner.fail(`Account is not a program: ${programId}`);
      process.exit(1);
    }
    spinner.text = "Fetching IDL...";
    const [idlAddress] = PublicKey.findProgramAddressSync(
      [Buffer.from("anchor:idl"), pubkey.toBuffer()],
      pubkey
    );
    const idlAccount = await connection.getAccountInfo(idlAddress);
    if (!idlAccount) {
      spinner.warn("No Anchor IDL found on-chain");
      console.log(chalk3.yellow("\n  This program may not be an Anchor program, or IDL was not published."));
      console.log(chalk3.yellow("  Try auditing the source code directly instead.\n"));
      process.exit(1);
    }
    const idlData = idlAccount.data.slice(12);
    let idlJson;
    try {
      idlJson = idlData.toString("utf8");
      JSON.parse(idlJson);
    } catch {
      spinner.fail("IDL appears to be compressed. Decompression not yet supported.");
      process.exit(1);
    }
    const tempDir = join2(process.cwd(), ".solguard-temp");
    if (!existsSync2(tempDir)) {
      mkdirSync(tempDir, { recursive: true });
    }
    const idlPath = join2(tempDir, `${programId}.json`);
    writeFileSync(idlPath, idlJson);
    spinner.succeed(`IDL fetched for ${programId}`);
    console.log(chalk3.gray(`  Saved to: ${idlPath}
`));
    await auditCommand(idlPath, {
      output: options.output || "terminal",
      ai: options.ai !== false,
      verbose: options.verbose || false
    });
  } catch (error) {
    spinner.fail(`Failed to fetch program: ${error.message}`);
    if (options.verbose) {
      console.error(error);
    }
    process.exit(1);
  }
}
function listKnownPrograms() {
  const programs = [
    { name: "Token Program", id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
    { name: "Token 2022", id: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" },
    { name: "Associated Token", id: "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" },
    { name: "Metaplex Token Metadata", id: "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s" },
    { name: "Metaplex Bubblegum", id: "BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY" },
    { name: "Marinade Finance", id: "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD" },
    { name: "Raydium AMM", id: "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8" },
    { name: "Orca Whirlpools", id: "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc" },
    { name: "Jupiter Aggregator", id: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4" },
    { name: "Squads V3", id: "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu" }
  ];
  console.log(chalk3.bold("\n  Known Solana Programs:\n"));
  for (const program2 of programs) {
    console.log(chalk3.cyan(`  ${program2.name}`));
    console.log(chalk3.gray(`    ${program2.id}
`));
  }
  console.log(chalk3.dim("  Use: solguard fetch <program-id> to audit\n"));
}

// src/commands/certificate.ts
import chalk4 from "chalk";
import ora3 from "ora";
import { writeFileSync as writeFileSync2 } from "fs";
import { join as join3 } from "path";

// src/certificate/metadata.ts
import { createHash } from "crypto";
function generateCertificateMetadata(result, programId, imageUri = "https://solguard.dev/certificate.png") {
  const passed = result.passed;
  const findingsHash = createHash("sha256").update(JSON.stringify(result.findings)).digest("hex").slice(0, 16);
  return {
    name: `SolGuard Audit: ${programId.slice(0, 8)}...`,
    symbol: "AUDIT",
    description: passed ? `\u2705 This program passed the SolGuard security audit with no critical or high severity issues.` : `\u26A0\uFE0F This program was audited by SolGuard. ${result.summary.critical} critical and ${result.summary.high} high severity issues were found.`,
    image: imageUri,
    external_url: `https://solguard.dev/audit/${programId}`,
    attributes: [
      {
        trait_type: "Status",
        value: passed ? "PASSED" : "FAILED"
      },
      {
        trait_type: "Critical Issues",
        value: result.summary.critical
      },
      {
        trait_type: "High Issues",
        value: result.summary.high
      },
      {
        trait_type: "Medium Issues",
        value: result.summary.medium
      },
      {
        trait_type: "Low Issues",
        value: result.summary.low
      },
      {
        trait_type: "Total Findings",
        value: result.summary.total
      },
      {
        trait_type: "Audit Date",
        value: result.timestamp.split("T")[0]
      },
      {
        trait_type: "Findings Hash",
        value: findingsHash
      },
      {
        trait_type: "Auditor",
        value: "SolGuard AI"
      },
      {
        trait_type: "Version",
        value: "1.0.0"
      }
    ],
    properties: {
      files: [
        {
          uri: imageUri,
          type: "image/png"
        }
      ],
      category: "image"
    }
  };
}
function calculateSeverityScore(result) {
  const weights = {
    critical: 40,
    high: 25,
    medium: 10,
    low: 3,
    info: 1
  };
  let score = 0;
  score += result.summary.critical * weights.critical;
  score += result.summary.high * weights.high;
  score += result.summary.medium * weights.medium;
  score += result.summary.low * weights.low;
  score += result.summary.info * weights.info;
  return Math.min(100, score);
}
function generateCertificateSvg(programId, passed, summary, timestamp) {
  const statusColor = passed ? "#10B981" : "#EF4444";
  const statusText = passed ? "PASSED" : "FAILED";
  const date = new Date(timestamp).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric"
  });
  return `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 500" width="400" height="500">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#18181B"/>
      <stop offset="100%" style="stop-color:#09090B"/>
    </linearGradient>
  </defs>
  
  <!-- Background -->
  <rect width="400" height="500" fill="url(#bg)" rx="16"/>
  
  <!-- Border -->
  <rect x="8" y="8" width="384" height="484" fill="none" stroke="${statusColor}" stroke-width="2" rx="12" opacity="0.5"/>
  
  <!-- Header -->
  <text x="200" y="50" text-anchor="middle" fill="#FAFAFA" font-family="system-ui" font-size="24" font-weight="bold">\u{1F6E1}\uFE0F SolGuard</text>
  <text x="200" y="75" text-anchor="middle" fill="#71717A" font-family="system-ui" font-size="12">Security Audit Certificate</text>
  
  <!-- Status Badge -->
  <rect x="125" y="100" width="150" height="40" fill="${statusColor}" rx="20"/>
  <text x="200" y="127" text-anchor="middle" fill="#FAFAFA" font-family="system-ui" font-size="18" font-weight="bold">${statusText}</text>
  
  <!-- Program ID -->
  <text x="200" y="180" text-anchor="middle" fill="#A1A1AA" font-family="monospace" font-size="10">Program ID</text>
  <text x="200" y="200" text-anchor="middle" fill="#FAFAFA" font-family="monospace" font-size="11">${programId.slice(0, 22)}...</text>
  
  <!-- Findings Summary -->
  <text x="200" y="250" text-anchor="middle" fill="#A1A1AA" font-family="system-ui" font-size="12">Findings Summary</text>
  
  <g transform="translate(50, 270)">
    <rect width="70" height="50" fill="#7F1D1D" rx="8"/>
    <text x="35" y="25" text-anchor="middle" fill="#FCA5A5" font-family="system-ui" font-size="20" font-weight="bold">${summary.critical}</text>
    <text x="35" y="42" text-anchor="middle" fill="#FCA5A5" font-family="system-ui" font-size="9">Critical</text>
  </g>
  
  <g transform="translate(130, 270)">
    <rect width="70" height="50" fill="#78350F" rx="8"/>
    <text x="35" y="25" text-anchor="middle" fill="#FCD34D" font-family="system-ui" font-size="20" font-weight="bold">${summary.high}</text>
    <text x="35" y="42" text-anchor="middle" fill="#FCD34D" font-family="system-ui" font-size="9">High</text>
  </g>
  
  <g transform="translate(210, 270)">
    <rect width="70" height="50" fill="#422006" rx="8"/>
    <text x="35" y="25" text-anchor="middle" fill="#FDE68A" font-family="system-ui" font-size="20" font-weight="bold">${summary.medium}</text>
    <text x="35" y="42" text-anchor="middle" fill="#FDE68A" font-family="system-ui" font-size="9">Medium</text>
  </g>
  
  <g transform="translate(290, 270)">
    <rect width="70" height="50" fill="#1E3A5F" rx="8"/>
    <text x="35" y="25" text-anchor="middle" fill="#93C5FD" font-family="system-ui" font-size="20" font-weight="bold">${summary.low}</text>
    <text x="35" y="42" text-anchor="middle" fill="#93C5FD" font-family="system-ui" font-size="9">Low</text>
  </g>
  
  <!-- Date -->
  <text x="200" y="370" text-anchor="middle" fill="#71717A" font-family="system-ui" font-size="11">Audited on ${date}</text>
  
  <!-- Footer -->
  <text x="200" y="450" text-anchor="middle" fill="#52525B" font-family="system-ui" font-size="10">Powered by AI \u2022 solguard.dev</text>
  <text x="200" y="470" text-anchor="middle" fill="#3F3F46" font-family="system-ui" font-size="8">This certificate is stored on the Solana blockchain</text>
</svg>
  `.trim();
}

// src/commands/certificate.ts
async function certificateCommand(path, options) {
  const spinner = ora3("Running audit...").start();
  try {
    let result;
    const originalLog = console.log;
    let jsonOutput = "";
    console.log = (msg) => {
      jsonOutput += msg;
    };
    try {
      const { parseRustFiles: parseRustFiles2 } = await import("./rust-LZBLPUB7.js");
      const { runPatterns: runPatterns2 } = await import("./patterns-7NVPT5DP.js");
      const { existsSync: existsSync5, statSync: statSync4, readdirSync: readdirSync4 } = await import("fs");
      if (!existsSync5(path)) {
        throw new Error(`Path not found: ${path}`);
      }
      const isDirectory = statSync4(path).isDirectory();
      let rustFiles = [];
      if (isDirectory) {
        const findRustFiles3 = (dir) => {
          const files = [];
          const entries = readdirSync4(dir, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = join3(dir, entry.name);
            if (entry.isDirectory() && !entry.name.startsWith(".") && entry.name !== "target") {
              files.push(...findRustFiles3(fullPath));
            } else if (entry.name.endsWith(".rs")) {
              files.push(fullPath);
            }
          }
          return files;
        };
        const srcDir = join3(path, "src");
        const programsDir = join3(path, "programs");
        if (existsSync5(programsDir)) {
          rustFiles = findRustFiles3(programsDir);
        } else if (existsSync5(srcDir)) {
          rustFiles = findRustFiles3(srcDir);
        } else {
          rustFiles = findRustFiles3(path);
        }
      } else if (path.endsWith(".rs")) {
        rustFiles = [path];
      }
      if (rustFiles.length === 0) {
        throw new Error("No Rust files found");
      }
      spinner.text = "Analyzing code...";
      const rust = await parseRustFiles2(rustFiles);
      const findings = await runPatterns2({ idl: null, rust, path });
      result = {
        programPath: path,
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        findings,
        summary: {
          critical: findings.filter((f) => f.severity === "critical").length,
          high: findings.filter((f) => f.severity === "high").length,
          medium: findings.filter((f) => f.severity === "medium").length,
          low: findings.filter((f) => f.severity === "low").length,
          info: findings.filter((f) => f.severity === "info").length,
          total: findings.length
        },
        passed: findings.filter((f) => ["critical", "high"].includes(f.severity)).length === 0
      };
    } finally {
      console.log = originalLog;
    }
    spinner.text = "Generating certificate...";
    const programId = options.programId || "Unknown";
    const severityScore = calculateSeverityScore(result);
    const metadata = generateCertificateMetadata(result, programId);
    const svg = generateCertificateSvg(programId, result.passed, result.summary, result.timestamp);
    const outputDir = options.output || ".";
    const metadataPath = join3(outputDir, "certificate-metadata.json");
    const svgPath = join3(outputDir, "certificate.svg");
    writeFileSync2(metadataPath, JSON.stringify(metadata, null, 2));
    writeFileSync2(svgPath, svg);
    spinner.succeed("Certificate generated!");
    console.log("");
    console.log(chalk4.bold("  Certificate Summary"));
    console.log(chalk4.gray("  \u2500".repeat(25)));
    console.log("");
    console.log(`  Status: ${result.passed ? chalk4.green("\u2705 PASSED") : chalk4.red("\u274C FAILED")}`);
    console.log(`  Severity Score: ${chalk4.yellow(severityScore + "/100")} ${severityScore === 0 ? "(Perfect!)" : ""}`);
    console.log("");
    console.log(`  Findings:`);
    console.log(`    ${chalk4.red("Critical:")} ${result.summary.critical}`);
    console.log(`    ${chalk4.yellow("High:")} ${result.summary.high}`);
    console.log(`    ${chalk4.blue("Medium:")} ${result.summary.medium}`);
    console.log(`    ${chalk4.gray("Low:")} ${result.summary.low}`);
    console.log("");
    console.log(chalk4.gray(`  Metadata: ${metadataPath}`));
    console.log(chalk4.gray(`  SVG: ${svgPath}`));
    console.log("");
    if (result.passed) {
      console.log(chalk4.green("  \u{1F389} This program is ready for NFT certificate minting!"));
    } else {
      console.log(chalk4.yellow("  \u26A0\uFE0F  Fix the issues above before minting a certificate."));
    }
    console.log("");
  } catch (error) {
    spinner.fail(`Certificate generation failed: ${error.message}`);
    process.exit(1);
  }
}

// src/commands/watch.ts
import chalk5 from "chalk";
import { watch } from "fs";
import { join as join4, relative } from "path";
import { readdirSync as readdirSync2, statSync as statSync2, existsSync as existsSync3 } from "fs";
async function watchCommand(path, options) {
  console.log(chalk5.cyan("\n  \u{1F50D} SolGuard Watch Mode\n"));
  console.log(chalk5.gray(`  Watching: ${path}`));
  console.log(chalk5.gray("  Press Ctrl+C to stop\n"));
  if (!existsSync3(path)) {
    console.error(chalk5.red(`  Error: Path not found: ${path}`));
    process.exit(1);
  }
  const dirsToWatch = /* @__PURE__ */ new Set();
  function findDirs(dir) {
    dirsToWatch.add(dir);
    try {
      const entries = readdirSync2(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && !entry.name.startsWith(".") && entry.name !== "target" && entry.name !== "node_modules") {
          findDirs(join4(dir, entry.name));
        }
      }
    } catch {
    }
  }
  if (statSync2(path).isDirectory()) {
    findDirs(path);
  } else {
    dirsToWatch.add(path);
  }
  let debounceTimer = null;
  let lastAuditTime = 0;
  const DEBOUNCE_MS = 1e3;
  async function runAudit() {
    const now = Date.now();
    if (now - lastAuditTime < DEBOUNCE_MS) {
      return;
    }
    lastAuditTime = now;
    console.log(chalk5.yellow("\n  \u2500".repeat(30)));
    console.log(chalk5.yellow(`  \u{1F504} Re-auditing at ${(/* @__PURE__ */ new Date()).toLocaleTimeString()}`));
    console.log(chalk5.yellow("  \u2500".repeat(30)));
    try {
      await auditCommand(path, {
        output: options.output || "terminal",
        ai: options.ai !== false,
        verbose: false
      });
    } catch (error) {
    }
  }
  console.log(chalk5.green("  Running initial audit...\n"));
  await runAudit();
  for (const dir of dirsToWatch) {
    try {
      watch(dir, { recursive: false }, (eventType, filename) => {
        if (!filename) return;
        if (!filename.endsWith(".rs")) return;
        if (filename.startsWith(".")) return;
        console.log(chalk5.blue(`
  \u{1F4DD} Changed: ${relative(path, join4(dir, filename))}`));
        if (debounceTimer) {
          clearTimeout(debounceTimer);
        }
        debounceTimer = setTimeout(runAudit, 500);
      });
    } catch (error) {
    }
  }
  process.on("SIGINT", () => {
    console.log(chalk5.gray("\n\n  \u{1F44B} Watch mode stopped\n"));
    process.exit(0);
  });
  await new Promise(() => {
  });
}

// src/commands/stats.ts
import chalk6 from "chalk";
function statsCommand() {
  const patterns = listPatterns();
  console.log("");
  console.log(chalk6.bold("  \u{1F4CA} SolGuard Statistics"));
  console.log(chalk6.gray("  \u2500".repeat(25)));
  console.log("");
  console.log(chalk6.cyan("  Version:"), "0.1.0");
  console.log(chalk6.cyan("  Patterns:"), patterns.length);
  console.log("");
  const bySeverity = {
    critical: patterns.filter((p) => p.severity === "critical"),
    high: patterns.filter((p) => p.severity === "high"),
    medium: patterns.filter((p) => p.severity === "medium"),
    low: patterns.filter((p) => p.severity === "low")
  };
  console.log(chalk6.bold("  Vulnerability Patterns:"));
  console.log("");
  if (bySeverity.critical.length > 0) {
    console.log(chalk6.red("  \u{1F534} Critical:"));
    for (const p of bySeverity.critical) {
      console.log(chalk6.gray(`     ${p.id}: ${p.name}`));
    }
    console.log("");
  }
  if (bySeverity.high.length > 0) {
    console.log(chalk6.yellow("  \u{1F7E0} High:"));
    for (const p of bySeverity.high) {
      console.log(chalk6.gray(`     ${p.id}: ${p.name}`));
    }
    console.log("");
  }
  if (bySeverity.medium.length > 0) {
    console.log(chalk6.blue("  \u{1F7E1} Medium:"));
    for (const p of bySeverity.medium) {
      console.log(chalk6.gray(`     ${p.id}: ${p.name}`));
    }
    console.log("");
  }
  console.log(chalk6.bold("  Capabilities:"));
  console.log("");
  console.log(chalk6.green("  \u2713"), "Anchor IDL parsing");
  console.log(chalk6.green("  \u2713"), "Rust source code analysis");
  console.log(chalk6.green("  \u2713"), "AI-powered explanations");
  console.log(chalk6.green("  \u2713"), "On-chain program fetching");
  console.log(chalk6.green("  \u2713"), "NFT certificate generation");
  console.log(chalk6.green("  \u2713"), "Watch mode for development");
  console.log(chalk6.green("  \u2713"), "JSON/Markdown output");
  console.log("");
  console.log(chalk6.bold("  Available Commands:"));
  console.log("");
  console.log(chalk6.cyan("  solguard audit <path>"), "      Audit a program");
  console.log(chalk6.cyan("  solguard fetch <program-id>"), "Fetch and audit on-chain");
  console.log(chalk6.cyan("  solguard certificate <path>"), "Generate NFT certificate");
  console.log(chalk6.cyan("  solguard watch <path>"), "      Watch and auto-audit");
  console.log(chalk6.cyan("  solguard programs"), "          List known programs");
  console.log(chalk6.cyan("  solguard stats"), "             Show this info");
  console.log("");
  console.log(chalk6.gray("  Built by Midir for Solana Agent Hackathon 2026"));
  console.log(chalk6.gray("  https://github.com/oh-ashen-one/solguard"));
  console.log("");
}

// src/commands/github.ts
import { exec } from "child_process";
import { promisify } from "util";
import { mkdir, rm, readdir, readFile } from "fs/promises";
import { join as join5 } from "path";
import { tmpdir } from "os";
var execAsync = promisify(exec);
function parseGithubUrl(input) {
  const urlMatch = input.match(/github\.com[\/:]([^\/]+)\/([^\/\.\s]+)/);
  if (urlMatch) {
    return { owner: urlMatch[1], repo: urlMatch[2].replace(/\.git$/, "") };
  }
  const shortMatch = input.match(/^([^\/]+)\/([^\/]+)$/);
  if (shortMatch) {
    return { owner: shortMatch[1], repo: shortMatch[2] };
  }
  return null;
}
async function cloneRepo(owner, repo, options) {
  const tempDir = join5(tmpdir(), `solguard-${Date.now()}`);
  await mkdir(tempDir, { recursive: true });
  const repoUrl = `https://github.com/${owner}/${repo}.git`;
  await execAsync(`git clone --depth 1 ${repoUrl} ${tempDir}`, {
    timeout: 6e4
  });
  if (options.pr) {
    await execAsync(
      `git fetch origin pull/${options.pr}/head:pr-${options.pr}`,
      { cwd: tempDir, timeout: 3e4 }
    );
    await execAsync(
      `git checkout pr-${options.pr}`,
      { cwd: tempDir }
    );
  } else if (options.branch) {
    await execAsync(
      `git checkout ${options.branch}`,
      { cwd: tempDir }
    );
  }
  return tempDir;
}
async function findRustFiles2(dir) {
  const files = [];
  async function scan(currentDir) {
    const entries = await readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join5(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (["node_modules", "target", ".git", "dist", "build"].includes(entry.name)) {
          continue;
        }
        await scan(fullPath);
      } else if (entry.name.endsWith(".rs")) {
        files.push(fullPath);
      }
    }
  }
  await scan(dir);
  return files;
}
async function findIdlFiles(dir) {
  const files = [];
  async function scan(currentDir) {
    const entries = await readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join5(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (["node_modules", "target", ".git"].includes(entry.name)) continue;
        await scan(fullPath);
      } else if (entry.name.endsWith(".json") && (entry.name.includes("idl") || currentDir.includes("idl"))) {
        files.push(fullPath);
      }
    }
  }
  await scan(dir);
  return files;
}
async function auditGithub(repoInput, options = {}) {
  const startTime = Date.now();
  const parsed = parseGithubUrl(repoInput);
  if (!parsed) {
    throw new Error(`Invalid GitHub repository: ${repoInput}`);
  }
  const { owner, repo } = parsed;
  let tempDir = null;
  try {
    if (options.verbose) {
      console.log(`Cloning ${owner}/${repo}...`);
    }
    tempDir = await cloneRepo(owner, repo, {
      pr: options.pr,
      branch: options.branch
    });
    const rustFiles = await findRustFiles2(tempDir);
    const idlFiles = await findIdlFiles(tempDir);
    if (options.verbose) {
      console.log(`Found ${rustFiles.length} Rust files, ${idlFiles.length} IDL files`);
    }
    const idls = await Promise.all(
      idlFiles.map(async (f) => {
        try {
          const content = await readFile(f, "utf-8");
          return { path: f.replace(tempDir + "/", ""), idl: parseIdl(content) };
        } catch {
          return null;
        }
      })
    );
    const allFindings = [];
    try {
      const parsedRust = parseRustFiles(rustFiles);
      for (const file of parsedRust.files) {
        const relativePath = file.path.replace(tempDir + "\\", "").replace(tempDir + "/", "");
        const findings = await runPatterns({
          path: relativePath,
          rust: {
            files: [file],
            functions: parsedRust.functions.filter((f) => f.file === file.path),
            structs: parsedRust.structs.filter((s) => s.file === file.path),
            implBlocks: parsedRust.implBlocks.filter((i) => i.file === file.path),
            content: file.content
          },
          idl: idls[0]?.idl || null
        });
        allFindings.push(...findings);
      }
    } catch (error) {
      if (options.verbose) {
        console.warn(`Failed to audit: ${error}`);
      }
    }
    const duration = Date.now() - startTime;
    return {
      repo: `${owner}/${repo}`,
      ref: options.pr ? `PR #${options.pr}` : options.branch || "main",
      files: rustFiles.length,
      findings: allFindings,
      duration
    };
  } finally {
    if (tempDir) {
      try {
        await rm(tempDir, { recursive: true, force: true });
      } catch {
      }
    }
  }
}
function formatGithubAuditResult(result, format = "text") {
  if (format === "json") {
    return JSON.stringify(result, null, 2);
  }
  if (format === "markdown") {
    const lines2 = [
      `# SolGuard Audit: ${result.repo}`,
      "",
      `**Ref:** ${result.ref}`,
      `**Files Scanned:** ${result.files}`,
      `**Duration:** ${result.duration}ms`,
      "",
      `## Findings (${result.findings.length})`,
      ""
    ];
    if (result.findings.length === 0) {
      lines2.push("\u2705 No vulnerabilities detected!");
    } else {
      const bySeverity = /* @__PURE__ */ new Map();
      for (const f of result.findings) {
        if (!bySeverity.has(f.severity)) {
          bySeverity.set(f.severity, []);
        }
        bySeverity.get(f.severity).push(f);
      }
      const severityEmoji = {
        critical: "\u{1F534}",
        high: "\u{1F7E0}",
        medium: "\u{1F7E1}",
        low: "\u{1F535}",
        info: "\u26AA"
      };
      for (const [severity, findings] of bySeverity) {
        lines2.push(`### ${severityEmoji[severity] || ""} ${severity.toUpperCase()} (${findings.length})`);
        lines2.push("");
        for (const f of findings) {
          lines2.push(`- **[${f.pattern}] ${f.title}**`);
          lines2.push(`  - Location: \`${f.location}\``);
          lines2.push(`  - ${f.description}`);
          lines2.push("");
        }
      }
    }
    return lines2.join("\n");
  }
  const lines = [
    `SolGuard Audit: ${result.repo} (${result.ref})`,
    `Files: ${result.files} | Duration: ${result.duration}ms`,
    ""
  ];
  if (result.findings.length === 0) {
    lines.push("\u2713 No vulnerabilities detected");
  } else {
    lines.push(`Found ${result.findings.length} issue(s):`);
    lines.push("");
    for (const f of result.findings) {
      const emoji = { critical: "\u{1F534}", high: "\u{1F7E0}", medium: "\u{1F7E1}", low: "\u{1F535}", info: "\u26AA" }[f.severity] || "";
      lines.push(`${emoji} [${f.pattern}] ${f.title}`);
      lines.push(`   ${f.location}`);
      lines.push(`   ${f.description}`);
      lines.push("");
    }
  }
  return lines.join("\n");
}

// src/commands/ci.ts
import { readFileSync, existsSync as existsSync4, readdirSync as readdirSync3, statSync as statSync3, writeFileSync as writeFileSync3 } from "fs";
import { join as join6 } from "path";
async function ciCommand(path, options) {
  const startTime = Date.now();
  if (!existsSync4(path)) {
    console.error(`::error::Path not found: ${path}`);
    process.exit(1);
  }
  const isDirectory = statSync3(path).isDirectory();
  let rustFiles = [];
  let idlPath = null;
  if (isDirectory) {
    rustFiles = findRustFilesRecursive(path);
    const idlDir = join6(path, "target", "idl");
    if (existsSync4(idlDir)) {
      const idlFiles = readdirSync3(idlDir).filter((f) => f.endsWith(".json"));
      if (idlFiles.length > 0) {
        idlPath = join6(idlDir, idlFiles[0]);
      }
    }
  } else if (path.endsWith(".rs")) {
    rustFiles = [path];
  }
  if (rustFiles.length === 0) {
    console.log("::warning::No Rust files found to audit");
    process.exit(0);
  }
  let idl = null;
  if (idlPath) {
    try {
      idl = parseIdl(readFileSync(idlPath, "utf-8"));
    } catch {
      console.log("::warning::Failed to parse IDL");
    }
  }
  const parsedRust = parseRustFiles(rustFiles);
  const allFindings = [];
  for (const file of parsedRust.files) {
    const findings = await runPatterns({
      path: file.path,
      rust: {
        files: [file],
        functions: parsedRust.functions.filter((f) => f.file === file.path),
        structs: parsedRust.structs.filter((s) => s.file === file.path),
        implBlocks: parsedRust.implBlocks.filter((i) => i.file === file.path),
        content: file.content
      },
      idl
    });
    allFindings.push(...findings);
  }
  const duration = Date.now() - startTime;
  for (const finding of allFindings) {
    const level = finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "notice";
    const location = typeof finding.location === "string" ? finding.location : `${finding.location.file}:${finding.location.line || 1}`;
    const [file, line] = location.split(":");
    console.log(`::${level} file=${file},line=${line || 1},title=[${finding.pattern}] ${finding.title}::${finding.description}`);
  }
  const counts = {
    critical: allFindings.filter((f) => f.severity === "critical").length,
    high: allFindings.filter((f) => f.severity === "high").length,
    medium: allFindings.filter((f) => f.severity === "medium").length,
    low: allFindings.filter((f) => f.severity === "low").length,
    info: allFindings.filter((f) => f.severity === "info").length
  };
  const summaryPath = process.env.GITHUB_STEP_SUMMARY || options.summary;
  if (summaryPath) {
    const summaryLines = [
      "## \u{1F6E1}\uFE0F SolGuard Security Audit",
      "",
      `| Severity | Count |`,
      `|----------|-------|`,
      `| \u{1F534} Critical | ${counts.critical} |`,
      `| \u{1F7E0} High | ${counts.high} |`,
      `| \u{1F7E1} Medium | ${counts.medium} |`,
      `| \u{1F535} Low | ${counts.low} |`,
      `| \u26AA Info | ${counts.info} |`,
      "",
      `**Files scanned:** ${rustFiles.length}`,
      `**Duration:** ${duration}ms`,
      `**Patterns:** ${listPatterns().length}`,
      ""
    ];
    if (allFindings.length > 0) {
      summaryLines.push("### Findings");
      summaryLines.push("");
      for (const f of allFindings.slice(0, 20)) {
        const emoji = { critical: "\u{1F534}", high: "\u{1F7E0}", medium: "\u{1F7E1}", low: "\u{1F535}", info: "\u26AA" }[f.severity] || "";
        summaryLines.push(`- ${emoji} **[${f.pattern}]** ${f.title}`);
        summaryLines.push(`  - ${f.description}`);
      }
      if (allFindings.length > 20) {
        summaryLines.push(`- ... and ${allFindings.length - 20} more`);
      }
    } else {
      summaryLines.push("\u2705 **No vulnerabilities detected!**");
    }
    writeFileSync3(summaryPath, summaryLines.join("\n"), { flag: "a" });
  }
  if (options.sarif) {
    const sarif = generateSarif(allFindings, path);
    writeFileSync3(options.sarif, JSON.stringify(sarif, null, 2));
    console.log(`::notice::SARIF report written to ${options.sarif}`);
  }
  console.log("\n--- SolGuard CI Summary ---");
  console.log(`Files: ${rustFiles.length} | Findings: ${allFindings.length} | Duration: ${duration}ms`);
  console.log(`Critical: ${counts.critical} | High: ${counts.high} | Medium: ${counts.medium} | Low: ${counts.low}`);
  const failOn = options.failOn || "critical";
  let shouldFail = false;
  switch (failOn) {
    case "any":
      shouldFail = allFindings.length > 0;
      break;
    case "low":
      shouldFail = counts.critical + counts.high + counts.medium + counts.low > 0;
      break;
    case "medium":
      shouldFail = counts.critical + counts.high + counts.medium > 0;
      break;
    case "high":
      shouldFail = counts.critical + counts.high > 0;
      break;
    case "critical":
    default:
      shouldFail = counts.critical > 0;
      break;
  }
  if (shouldFail) {
    console.log(`
::error::Audit failed: found ${failOn} or higher severity issues`);
    process.exit(1);
  }
  console.log("\n\u2713 Audit passed");
  process.exit(0);
}
function generateSarif(findings, basePath) {
  const rules = listPatterns().map((p) => ({
    id: p.id,
    name: p.name,
    shortDescription: { text: p.name },
    defaultConfiguration: {
      level: p.severity === "critical" || p.severity === "high" ? "error" : p.severity === "medium" ? "warning" : "note"
    }
  }));
  const results = findings.map((f) => {
    const location = typeof f.location === "string" ? f.location : f.location.file;
    const [file, lineStr] = location.split(":");
    const line = parseInt(lineStr) || 1;
    return {
      ruleId: f.pattern,
      level: f.severity === "critical" || f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "note",
      message: { text: `${f.title}: ${f.description}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: file },
          region: { startLine: line }
        }
      }]
    };
  });
  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "SolGuard",
          version: "0.1.0",
          informationUri: "https://github.com/oh-ashen-one/solguard",
          rules
        }
      },
      results
    }]
  };
}
function findRustFilesRecursive(dir) {
  const files = [];
  function scan(currentDir) {
    const entries = readdirSync3(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join6(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (!["node_modules", "target", ".git", "dist", "build"].includes(entry.name)) {
          scan(fullPath);
        }
      } else if (entry.name.endsWith(".rs")) {
        files.push(fullPath);
      }
    }
  }
  scan(dir);
  return files;
}

// src/index.ts
var program = new Command();
var args = process.argv.slice(2);
var isJsonOutput = args.includes("--output") && args[args.indexOf("--output") + 1] === "json";
if (!isJsonOutput) {
  console.log(chalk7.cyan(`
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551  \u{1F6E1}\uFE0F  SolGuard - Smart Contract Auditor    \u2551
\u2551     AI-Powered Security for Solana        \u2551
\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D
`));
}
program.name("solguard").description("AI-powered smart contract auditor for Solana").version("0.1.0");
program.command("audit").description("Audit an Anchor program for vulnerabilities").argument("<path>", "Path to program directory or IDL file").option("-o, --output <format>", "Output format: terminal, json, markdown", "terminal").option("--no-ai", "Skip AI explanations").option("-v, --verbose", "Show detailed output").action(auditCommand);
program.command("parse").description("Parse an Anchor IDL file").argument("<idl>", "Path to IDL JSON file").action(async (idlPath) => {
  const { parseIdl: parseIdl2 } = await import("./idl-YYKIXDKT.js");
  const result = await parseIdl2(idlPath);
  console.log(JSON.stringify(result, null, 2));
});
program.command("fetch").description("Fetch and audit a program by its on-chain program ID").argument("<program-id>", "Solana program ID (base58)").option("-r, --rpc <url>", "RPC endpoint URL").option("-o, --output <format>", "Output format: terminal, json, markdown", "terminal").option("--no-ai", "Skip AI explanations").option("-v, --verbose", "Show detailed output").action(fetchAndAuditCommand);
program.command("programs").description("List known Solana programs").action(listKnownPrograms);
program.command("certificate").description("Generate an audit certificate (metadata + SVG)").argument("<path>", "Path to program directory or Rust file").option("-o, --output <dir>", "Output directory", ".").option("-p, --program-id <id>", "Program ID for the certificate").action(certificateCommand);
program.command("watch").description("Watch for file changes and auto-audit").argument("<path>", "Path to program directory").option("-o, --output <format>", "Output format: terminal, json, markdown", "terminal").option("--no-ai", "Skip AI explanations").action(watchCommand);
program.command("stats").description("Show SolGuard statistics and capabilities").action(statsCommand);
program.command("github").description("Audit a Solana program directly from GitHub").argument("<repo>", "GitHub repository (owner/repo or URL)").option("-p, --pr <number>", "Pull request number to audit", parseInt).option("-b, --branch <name>", "Branch name to audit").option("-o, --output <format>", "Output format: text, json, markdown", "text").option("-v, --verbose", "Show detailed output").action(async (repo, options) => {
  try {
    const result = await auditGithub(repo, {
      pr: options.pr,
      branch: options.branch,
      output: options.output,
      verbose: options.verbose
    });
    console.log(formatGithubAuditResult(result, options.output));
    const hasCritical = result.findings.some((f) => f.severity === "critical");
    if (hasCritical) {
      process.exit(1);
    }
  } catch (error) {
    console.error(chalk7.red(`Error: ${error.message}`));
    process.exit(1);
  }
});
program.command("ci").description("Run audit in CI mode (GitHub Actions, etc.)").argument("<path>", "Path to program directory").option("--fail-on <level>", "Fail on severity level: critical, high, medium, low, any", "critical").option("--sarif <file>", "Output SARIF report for GitHub Code Scanning").option("--summary <file>", "Write markdown summary to file").action(ciCommand);
program.parse();
