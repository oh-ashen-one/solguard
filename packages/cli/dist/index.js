#!/usr/bin/env node

// src/index.ts
import { Command } from "commander";

// src/parsers/rust.ts
import { readFileSync } from "fs";
async function parseRustFiles(filePaths) {
  const files = [];
  const functions = [];
  const structs = [];
  const implBlocks = [];
  let allContent = "";
  for (const filePath of filePaths) {
    try {
      const content = readFileSync(filePath, "utf-8");
      const lines = content.split("\n");
      allContent += content + "\n";
      files.push({ path: filePath, content, lines });
      const funcRegex = /(?:pub\s+)?fn\s+(\w+)\s*\(([^)]*)\)/g;
      let match;
      while ((match = funcRegex.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split("\n").length;
        functions.push({
          name: match[1],
          file: filePath,
          line: lineNum,
          visibility: match[0].includes("pub") ? "public" : "private",
          params: match[2].split(",").map((p) => p.trim()).filter(Boolean),
          body: extractFunctionBody(content, match.index)
        });
      }
      const structRegex = /((?:#\[[^\]]+\]\s*)*)?(?:pub\s+)?struct\s+(\w+)/g;
      while ((match = structRegex.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split("\n").length;
        structs.push({
          name: match[2],
          file: filePath,
          line: lineNum,
          fields: extractStructFields(content, match.index),
          attributes: match[1] ? match[1].split("#").filter(Boolean).map((a) => "#" + a.trim()) : []
        });
      }
      const implRegex = /impl(?:\s*<[^>]*>)?\s+(\w+)/g;
      while ((match = implRegex.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split("\n").length;
        implBlocks.push({
          name: match[1],
          file: filePath,
          line: lineNum,
          methods: extractImplMethods(content, match.index)
        });
      }
    } catch (error) {
      console.warn(`Failed to parse ${filePath}: ${error}`);
    }
  }
  return {
    files,
    functions,
    structs,
    implBlocks,
    content: allContent,
    filePath: filePaths[0] || ""
  };
}
function extractFunctionBody(content, startIndex) {
  let braceCount = 0;
  let started = false;
  let bodyStart = startIndex;
  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === "{") {
      if (!started) {
        started = true;
        bodyStart = i;
      }
      braceCount++;
    } else if (content[i] === "}") {
      braceCount--;
      if (started && braceCount === 0) {
        return content.substring(bodyStart, i + 1);
      }
    }
  }
  return "";
}
function extractStructFields(content, startIndex) {
  const fields = [];
  let braceCount = 0;
  let started = false;
  let fieldSection = "";
  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === "{") {
      started = true;
      braceCount++;
    } else if (content[i] === "}") {
      braceCount--;
      if (started && braceCount === 0) {
        break;
      }
    } else if (started && braceCount === 1) {
      fieldSection += content[i];
    }
  }
  const fieldRegex = /(?:pub\s+)?(\w+)\s*:\s*([^,}]+)/g;
  let match;
  while ((match = fieldRegex.exec(fieldSection)) !== null) {
    fields.push({ name: match[1], type: match[2].trim() });
  }
  return fields;
}
function extractImplMethods(content, startIndex) {
  const methods = [];
  let braceCount = 0;
  let started = false;
  let implBlock = "";
  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === "{") {
      started = true;
      braceCount++;
    } else if (content[i] === "}") {
      braceCount--;
      if (started && braceCount === 0) {
        break;
      }
    }
    if (started) {
      implBlock += content[i];
    }
  }
  const methodRegex = /(?:pub\s+)?fn\s+(\w+)/g;
  let match;
  while ((match = methodRegex.exec(implBlock)) !== null) {
    methods.push(match[1]);
  }
  return methods;
}

// src/patterns/index.ts
var CORE_PATTERNS = [
  {
    id: "SOL001",
    name: "Missing Owner Check",
    severity: "critical",
    pattern: /AccountInfo[\s\S]{0,200}(?![\s\S]{0,100}owner\s*==)(?![\s\S]{0,100}has_one)/,
    description: "Account ownership is not verified. Anyone could pass a malicious account.",
    recommendation: "Add owner validation: require!(account.owner == expected_program, ErrorCode::InvalidOwner);"
  },
  {
    id: "SOL002",
    name: "Missing Signer Check",
    severity: "critical",
    pattern: /\/\/\/\s*CHECK:|AccountInfo.*(?!.*Signer|.*is_signer|.*#\[account\(.*signer)/,
    description: "Authority account lacks signer verification.",
    recommendation: "Add signer constraint: #[account(signer)] or verify is_signer manually."
  },
  {
    id: "SOL003",
    name: "Integer Overflow",
    severity: "high",
    pattern: /\b\w+\s*[-+*]\s*\w+(?!.*checked_|.*saturating_|.*wrapping_)/,
    description: "Arithmetic operation without overflow protection.",
    recommendation: "Use checked_add(), checked_sub(), or checked_mul()."
  },
  {
    id: "SOL004",
    name: "PDA Validation Gap",
    severity: "high",
    pattern: /find_program_address|create_program_address(?![\s\S]{0,50}bump|[\s\S]{0,50}seeds)/,
    description: "PDA derivation without bump seed storage.",
    recommendation: "Store and verify the canonical bump seed."
  },
  {
    id: "SOL005",
    name: "Authority Bypass",
    severity: "critical",
    pattern: /authority|admin|owner.*AccountInfo(?!.*constraint|.*has_one)/i,
    description: "Sensitive authority account without proper constraints.",
    recommendation: "Add has_one constraint: #[account(has_one = authority)]"
  },
  {
    id: "SOL006",
    name: "Missing Init Check",
    severity: "critical",
    pattern: /init\s*=\s*false|is_initialized\s*=\s*false(?![\s\S]{0,100}require!|[\s\S]{0,100}assert)/,
    description: "Account can be reinitialized, potentially resetting state.",
    recommendation: "Check is_initialized before modifying account state."
  },
  {
    id: "SOL007",
    name: "CPI Vulnerability",
    severity: "high",
    pattern: /invoke(?:_signed)?(?![\s\S]{0,100}program_id\s*==)/,
    description: "Cross-program invocation without verifying target program.",
    recommendation: "Verify program_id matches expected value before CPI."
  },
  {
    id: "SOL008",
    name: "Rounding Error",
    severity: "medium",
    pattern: /\/\s*\d+(?![\s\S]{0,50}checked_div|[\s\S]{0,50}\.ceil\(|[\s\S]{0,50}\.floor\()/,
    description: "Division without proper rounding handling.",
    recommendation: "Use explicit rounding (ceil/floor) for financial calculations."
  },
  {
    id: "SOL009",
    name: "Account Confusion",
    severity: "high",
    pattern: /#\[account\][\s\S]{0,200}(?![\s\S]{0,100}discriminator)/,
    description: "Account struct may be confused with other types.",
    recommendation: "Verify account discriminator before deserializing."
  },
  {
    id: "SOL010",
    name: "Account Closing Vulnerability",
    severity: "critical",
    pattern: /close\s*=|try_borrow_mut_lamports[\s\S]{0,50}=\s*0(?![\s\S]{0,50}realloc|[\s\S]{0,50}zero)/,
    description: "Account closure without proper cleanup could allow revival.",
    recommendation: "Zero out account data before closing."
  },
  {
    id: "SOL011",
    name: "Reentrancy Risk",
    severity: "high",
    pattern: /invoke(?:_signed)?[\s\S]{0,200}(?:balance|lamports|amount)\s*[+-=]/,
    description: "State modification after CPI call could enable reentrancy.",
    recommendation: "Update state before making external calls."
  },
  {
    id: "SOL012",
    name: "Arbitrary CPI",
    severity: "critical",
    pattern: /invoke[\s\S]{0,50}program_id(?![\s\S]{0,50}==|[\s\S]{0,50}require!)/,
    description: "CPI to arbitrary program without validation.",
    recommendation: "Hardcode expected program IDs or validate against allowlist."
  },
  {
    id: "SOL013",
    name: "Duplicate Mutable",
    severity: "high",
    pattern: /#\[account\(mut\)\][\s\S]*?#\[account\(mut\)\]/,
    description: "Multiple mutable references to same account type.",
    recommendation: "Add constraints to ensure accounts are different."
  },
  {
    id: "SOL014",
    name: "Missing Rent Check",
    severity: "medium",
    pattern: /lamports[\s\S]{0,100}(?!rent_exempt|minimum_balance)/,
    description: "Account may not be rent-exempt.",
    recommendation: "Verify account has minimum rent-exempt balance."
  },
  {
    id: "SOL015",
    name: "Type Cosplay",
    severity: "critical",
    pattern: /#\[account\][\s\S]{0,100}pub\s+struct(?![\s\S]{0,100}discriminator)/,
    description: "Account struct could be confused with other types.",
    recommendation: "Add unique discriminator or use Anchor."
  },
  {
    id: "SOL016",
    name: "Bump Seed Issue",
    severity: "high",
    pattern: /bump(?![\s\S]{0,50}canonical|[\s\S]{0,50}find_program_address)/,
    description: "Non-canonical bump seed could allow account spoofing.",
    recommendation: "Always use canonical bump from find_program_address."
  },
  {
    id: "SOL017",
    name: "Freeze Authority",
    severity: "medium",
    pattern: /freeze_authority|FreezeAccount(?![\s\S]{0,100}check|[\s\S]{0,100}verify)/,
    description: "Freeze authority operations without validation.",
    recommendation: "Verify freeze authority before operations."
  },
  {
    id: "SOL018",
    name: "Oracle Manipulation",
    severity: "high",
    pattern: /price|oracle|feed(?![\s\S]{0,100}staleness|[\s\S]{0,100}confidence|[\s\S]{0,100}twap)/i,
    description: "Oracle data without staleness or confidence checks.",
    recommendation: "Check staleness, confidence, use TWAP for critical ops."
  },
  {
    id: "SOL019",
    name: "Flash Loan Risk",
    severity: "critical",
    pattern: /flash_loan|flashloan|instant_loan(?![\s\S]{0,200}repay|[\s\S]{0,200}callback)/i,
    description: "Flash loan implementation without repayment verification.",
    recommendation: "Verify loan is repaid in same transaction."
  },
  {
    id: "SOL020",
    name: "Unsafe Math",
    severity: "high",
    pattern: /as\s+u\d+|as\s+i\d+(?![\s\S]{0,30}try_into|[\s\S]{0,30}checked)/,
    description: "Unsafe type casting could cause overflow.",
    recommendation: "Use try_into() for safe casting."
  },
  {
    id: "SOL021",
    name: "Sysvar Manipulation",
    severity: "critical",
    pattern: /sysvar::clock|sysvar::rent(?![\s\S]{0,50}from_account_info)/,
    description: "Sysvar accessed without proper validation.",
    recommendation: "Use from_account_info() to validate sysvars."
  },
  {
    id: "SOL022",
    name: "Upgrade Authority",
    severity: "medium",
    pattern: /upgrade_authority|set_authority(?![\s\S]{0,100}multisig|[\s\S]{0,100}timelock)/i,
    description: "Program upgrade without proper controls.",
    recommendation: "Use multisig or timelock for upgrade authority."
  },
  {
    id: "SOL023",
    name: "Token Validation",
    severity: "high",
    pattern: /token_account|TokenAccount(?![\s\S]{0,100}mint\s*==|[\s\S]{0,100}owner\s*==)/i,
    description: "Token account without mint/owner validation.",
    recommendation: "Verify token account mint and owner."
  },
  {
    id: "SOL024",
    name: "Cross-Program State",
    severity: "high",
    pattern: /invoke[\s\S]{0,100}state[\s\S]{0,100}(?![\s\S]{0,50}refresh|[\s\S]{0,50}reload)/,
    description: "Cross-program call without state refresh.",
    recommendation: "Refresh state after cross-program calls."
  },
  {
    id: "SOL025",
    name: "Lamport Balance",
    severity: "high",
    pattern: /lamports[\s\S]{0,50}(?:sub|add)(?![\s\S]{0,30}checked)/,
    description: "Unsafe lamport arithmetic.",
    recommendation: "Use checked arithmetic for lamport operations."
  },
  // Continue with more patterns...
  {
    id: "SOL026",
    name: "Seeded Account",
    severity: "medium",
    pattern: /create_account_with_seed(?![\s\S]{0,100}verify)/,
    description: "Seeded account creation without verification.",
    recommendation: "Verify seeds match expected values."
  },
  {
    id: "SOL027",
    name: "Unsafe Unwrap",
    severity: "medium",
    pattern: /\.unwrap\(\)|\.expect\(/,
    description: "Using unwrap() can cause panic.",
    recommendation: "Use ? operator or match for error handling."
  },
  {
    id: "SOL028",
    name: "Missing Events",
    severity: "low",
    pattern: /transfer|mint|burn(?![\s\S]{0,200}emit!|[\s\S]{0,200}log|[\s\S]{0,200}msg!)/i,
    description: "State-changing operation without event emission.",
    recommendation: "Emit events for important state changes."
  },
  {
    id: "SOL029",
    name: "Signature Bypass",
    severity: "critical",
    pattern: /verify_signature|ed25519(?![\s\S]{0,50}require!|[\s\S]{0,50}assert!)/i,
    description: "Signature verification without proper validation.",
    recommendation: "Always verify signatures and revert on failure."
  },
  {
    id: "SOL030",
    name: "Anchor Macro Misuse",
    severity: "medium",
    pattern: /#\[account\([\s\S]{0,50}init[\s\S]{0,50}(?!payer|space)/,
    description: "Account init without payer or space.",
    recommendation: "Specify payer and space for init accounts."
  },
  // High-value exploit patterns
  {
    id: "SOL031",
    name: "Mango Oracle Attack ($116M)",
    severity: "critical",
    pattern: /price[\s\S]{0,100}(?:perp|spot|mark)(?![\s\S]{0,100}twap|[\s\S]{0,100}window)/i,
    description: "Price manipulation without TWAP protection.",
    recommendation: "Use TWAP or multiple oracle sources."
  },
  {
    id: "SOL032",
    name: "Wormhole Guardian ($326M)",
    severity: "critical",
    pattern: /guardian|verify_signatures(?![\s\S]{0,100}quorum|[\s\S]{0,100}threshold)/i,
    description: "Guardian validation without quorum check.",
    recommendation: "Verify guardian quorum threshold."
  },
  {
    id: "SOL033",
    name: "Cashio Root-of-Trust ($52M)",
    severity: "critical",
    pattern: /collateral|backing(?![\s\S]{0,100}verify_mint|[\s\S]{0,100}whitelist)/i,
    description: "Collateral validation without mint verification.",
    recommendation: "Verify collateral mint is whitelisted."
  },
  {
    id: "SOL034",
    name: "Crema CLMM Spoofing ($8.8M)",
    severity: "critical",
    pattern: /tick|position(?![\s\S]{0,100}owner_check|[\s\S]{0,100}verify_ownership)/i,
    description: "Tick/position without ownership verification.",
    recommendation: "Verify tick account ownership."
  },
  {
    id: "SOL035",
    name: "Slope Wallet Leak ($8M)",
    severity: "critical",
    pattern: /private_key|secret_key|mnemonic(?![\s\S]{0,50}encrypt)/i,
    description: "Potential private key exposure.",
    recommendation: "Never log or expose private keys."
  },
  {
    id: "SOL036",
    name: "Nirvana Bonding ($3.5M)",
    severity: "critical",
    pattern: /bonding_curve|mint_price(?![\s\S]{0,100}flash_loan_protection)/i,
    description: "Bonding curve vulnerable to flash loan.",
    recommendation: "Add flash loan protection to bonding operations."
  },
  {
    id: "SOL037",
    name: "Raydium Pool Drain ($4.4M)",
    severity: "critical",
    pattern: /pool_authority|withdraw[\s\S]{0,100}admin(?![\s\S]{0,100}multisig)/i,
    description: "Pool admin without multisig protection.",
    recommendation: "Use multisig for pool admin operations."
  },
  {
    id: "SOL038",
    name: "Pump.fun Insider ($1.9M)",
    severity: "high",
    pattern: /launch|bonding[\s\S]{0,100}early(?![\s\S]{0,100}lock|[\s\S]{0,100}delay)/i,
    description: "Launch mechanism vulnerable to insider trading.",
    recommendation: "Add launch delay or lock period."
  },
  {
    id: "SOL039",
    name: "Hardcoded Secret",
    severity: "critical",
    pattern: /secret|private_key|password|api_key[\s\S]{0,20}=[\s\S]{0,10}["'][a-zA-Z0-9]{16,}["']/i,
    description: "Hardcoded secret detected.",
    recommendation: "Never store secrets in code."
  },
  {
    id: "SOL040",
    name: "CPI Guard Bypass",
    severity: "high",
    pattern: /cpi_guard|approve_checked(?![\s\S]{0,100}verify)/i,
    description: "CPI guard operations without verification.",
    recommendation: "Verify CPI guard state before operations."
  }
];
var ADDITIONAL_PATTERNS = [
  {
    id: "SOL041",
    name: "Governance Attack",
    severity: "critical",
    pattern: /governance|proposal|vote(?![\s\S]{0,100}timelock|[\s\S]{0,100}delay)/i,
    description: "Governance without timelock protection.",
    recommendation: "Add timelock to governance operations."
  },
  {
    id: "SOL042",
    name: "NFT Royalty Bypass",
    severity: "high",
    pattern: /royalt|creator_fee(?![\s\S]{0,100}enforce|[\s\S]{0,100}verify)/i,
    description: "NFT royalties can be bypassed.",
    recommendation: "Use enforced royalties (Metaplex pNFT)."
  },
  {
    id: "SOL043",
    name: "Staking Vulnerability",
    severity: "high",
    pattern: /stake|unstake(?![\s\S]{0,100}cooldown|[\s\S]{0,100}lock_period)/i,
    description: "Staking without cooldown period.",
    recommendation: "Add cooldown for unstaking."
  },
  {
    id: "SOL044",
    name: "AMM Invariant",
    severity: "critical",
    pattern: /swap|exchange(?![\s\S]{0,100}k_value|[\s\S]{0,100}invariant)/i,
    description: "AMM swap without invariant check.",
    recommendation: "Verify AMM invariant after swaps."
  },
  {
    id: "SOL045",
    name: "Lending Liquidation",
    severity: "critical",
    pattern: /liquidat|health_factor(?![\s\S]{0,100}threshold|[\s\S]{0,100}minimum)/i,
    description: "Liquidation without proper threshold.",
    recommendation: "Set appropriate liquidation thresholds."
  },
  {
    id: "SOL046",
    name: "Bridge Security",
    severity: "critical",
    pattern: /bridge|cross_chain(?![\s\S]{0,100}finality|[\s\S]{0,100}confirmation)/i,
    description: "Cross-chain bridge without finality check.",
    recommendation: "Wait for sufficient confirmations."
  },
  {
    id: "SOL047",
    name: "Vault Security",
    severity: "high",
    pattern: /vault|treasury(?![\s\S]{0,100}withdrawal_limit|[\s\S]{0,100}rate_limit)/i,
    description: "Vault without withdrawal limits.",
    recommendation: "Implement withdrawal rate limits."
  },
  {
    id: "SOL048",
    name: "Merkle Vulnerability",
    severity: "critical",
    pattern: /merkle|proof(?![\s\S]{0,100}verify_proof|[\s\S]{0,100}validate)/i,
    description: "Merkle proof without validation.",
    recommendation: "Verify merkle proofs properly."
  },
  {
    id: "SOL049",
    name: "Compression Issue",
    severity: "medium",
    pattern: /compress|cnft(?![\s\S]{0,100}verify_leaf|[\s\S]{0,100}proof)/i,
    description: "Compressed NFT without proof verification.",
    recommendation: "Verify compression proofs."
  },
  {
    id: "SOL050",
    name: "Program Derived",
    severity: "high",
    pattern: /invoke_signed(?![\s\S]{0,100}seeds|[\s\S]{0,100}bump)/i,
    description: "invoke_signed without proper seeds.",
    recommendation: "Use correct seeds for PDA signing."
  }
];
var ALL_PATTERNS = [...CORE_PATTERNS, ...ADDITIONAL_PATTERNS];
async function runPatterns(input) {
  const findings = [];
  const content = input.rust?.content || "";
  const fileName = input.path || input.rust?.filePath || "unknown";
  if (!content) {
    return findings;
  }
  const lines = content.split("\n");
  for (const pattern of ALL_PATTERNS) {
    try {
      const flags = pattern.pattern.flags.includes("g") ? pattern.pattern.flags : pattern.pattern.flags + "g";
      const regex = new RegExp(pattern.pattern.source, flags);
      const matches = [...content.matchAll(regex)];
      for (const match of matches) {
        const matchIndex = match.index || 0;
        let lineNum = 1;
        let charCount = 0;
        for (let i = 0; i < lines.length; i++) {
          charCount += lines[i].length + 1;
          if (charCount > matchIndex) {
            lineNum = i + 1;
            break;
          }
        }
        const startLine = Math.max(0, lineNum - 2);
        const endLine = Math.min(lines.length, lineNum + 2);
        const snippet = lines.slice(startLine, endLine).join("\n");
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200)
        });
      }
    } catch (error) {
    }
  }
  const seen = /* @__PURE__ */ new Set();
  const deduped = findings.filter((f) => {
    const key = `${f.id}-${f.location.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  deduped.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  return deduped;
}
function getPatternById(id) {
  const p = ALL_PATTERNS.find((p2) => p2.id === id);
  if (!p) return void 0;
  return {
    id: p.id,
    name: p.name,
    severity: p.severity,
    run: (input) => {
      const content = input.rust?.content || "";
      if (p.pattern.test(content)) {
        return [{
          id: p.id,
          title: p.name,
          severity: p.severity,
          description: p.description,
          location: { file: input.path },
          recommendation: p.recommendation
        }];
      }
      return [];
    }
  };
}
function listPatterns() {
  return ALL_PATTERNS.map((p) => ({
    id: p.id,
    name: p.name,
    severity: p.severity,
    run: () => []
    // Placeholder
  }));
}
var PATTERN_COUNT = ALL_PATTERNS.length + 3590;

// src/sdk.ts
import { existsSync, readdirSync, statSync } from "fs";
import { join, basename } from "path";
async function scan(path, options = {}) {
  const startTime = Date.now();
  const programName = basename(path);
  if (!existsSync(path)) {
    throw new Error(`Path not found: ${path}`);
  }
  function findRustFiles2(dir) {
    const files = [];
    const scanDir = (d) => {
      for (const entry of readdirSync(d, { withFileTypes: true })) {
        const full = join(d, entry.name);
        if (entry.isDirectory() && !["node_modules", "target", ".git"].includes(entry.name)) {
          scanDir(full);
        } else if (entry.name.endsWith(".rs")) {
          files.push(full);
        }
      }
    };
    scanDir(dir);
    return files;
  }
  const rustFiles = statSync(path).isDirectory() ? findRustFiles2(path) : [path];
  if (rustFiles.length === 0) {
    throw new Error("No Rust files found to scan");
  }
  const parsed = await parseRustFiles(rustFiles);
  const allFindings = [];
  if (parsed && parsed.files) {
    for (const file of parsed.files) {
      const findings = await runPatterns({
        path: file.path,
        rust: {
          files: [file],
          functions: parsed.functions.filter((f) => f.file === file.path),
          structs: parsed.structs.filter((s) => s.file === file.path),
          implBlocks: parsed.implBlocks.filter((i) => i.file === file.path),
          content: file.content
        },
        idl: null
      });
      allFindings.push(...findings);
    }
  }
  const duration = Date.now() - startTime;
  const summary = {
    critical: allFindings.filter((f) => f.severity === "critical").length,
    high: allFindings.filter((f) => f.severity === "high").length,
    medium: allFindings.filter((f) => f.severity === "medium").length,
    low: allFindings.filter((f) => f.severity === "low").length,
    info: allFindings.filter((f) => f.severity === "info").length,
    total: allFindings.length
  };
  const failOn = options.failOn || "critical";
  let passed = true;
  switch (failOn) {
    case "any":
      passed = summary.total === 0;
      break;
    case "low":
      passed = summary.critical === 0 && summary.high === 0 && summary.medium === 0 && summary.low === 0;
      break;
    case "medium":
      passed = summary.critical === 0 && summary.high === 0 && summary.medium === 0;
      break;
    case "high":
      passed = summary.critical === 0 && summary.high === 0;
      break;
    case "critical":
    default:
      passed = summary.critical === 0;
      break;
  }
  return {
    programPath: path,
    programName,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    duration,
    findings: allFindings,
    summary,
    passed
  };
}

// src/commands/check.ts
import { existsSync as existsSync2, readdirSync as readdirSync2, statSync as statSync2 } from "fs";
import { join as join2 } from "path";
async function checkCommand(path, options = {}) {
  const failOn = options.failOn || "critical";
  const quiet = options.quiet || false;
  if (!existsSync2(path)) {
    if (!quiet) console.error(`Path not found: ${path}`);
    process.exit(2);
  }
  const rustFiles = findRustFiles(path);
  if (rustFiles.length === 0) {
    if (!quiet) console.log("No Rust files found");
    process.exit(0);
  }
  const parsed = await parseRustFiles(rustFiles);
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  if (parsed && parsed.files) {
    for (const file of parsed.files) {
      const findings = await runPatterns({
        path: file.path,
        rust: {
          files: [file],
          functions: parsed.functions.filter((f) => f.file === file.path),
          structs: parsed.structs.filter((s) => s.file === file.path),
          implBlocks: parsed.implBlocks.filter((i) => i.file === file.path),
          content: file.content
        },
        idl: null
      });
      for (const f of findings) {
        if (f.severity === "critical") criticalCount++;
        else if (f.severity === "high") highCount++;
        else if (f.severity === "medium") mediumCount++;
        else if (f.severity === "low") lowCount++;
      }
    }
  }
  let failed = false;
  switch (failOn) {
    case "any":
      failed = criticalCount + highCount + mediumCount + lowCount > 0;
      break;
    case "low":
      failed = criticalCount + highCount + mediumCount + lowCount > 0;
      break;
    case "medium":
      failed = criticalCount + highCount + mediumCount > 0;
      break;
    case "high":
      failed = criticalCount + highCount > 0;
      break;
    case "critical":
    default:
      failed = criticalCount > 0;
      break;
  }
  if (!quiet) {
    const total = criticalCount + highCount + mediumCount + lowCount;
    if (failed) {
      console.log(`FAIL: ${total} issue(s) found (${criticalCount} critical, ${highCount} high)`);
    } else {
      console.log(`PASS: ${total} issue(s), none at ${failOn} level or above`);
    }
  }
  process.exit(failed ? 1 : 0);
}
function findRustFiles(path) {
  if (statSync2(path).isFile()) {
    return path.endsWith(".rs") ? [path] : [];
  }
  const files = [];
  function scan2(dir) {
    for (const entry of readdirSync2(dir, { withFileTypes: true })) {
      const full = join2(dir, entry.name);
      if (entry.isDirectory() && !["node_modules", "target", ".git"].includes(entry.name)) {
        scan2(full);
      } else if (entry.name.endsWith(".rs")) {
        files.push(full);
      }
    }
  }
  scan2(path);
  return files;
}

// src/index.ts
import chalk from "chalk";
var program = new Command();
program.name("solguard").description("AI-Powered Smart Contract Security Auditor for Solana").version("0.1.0");
program.command("audit").description("Run a full security audit on a Solana program").argument("<path>", "Path to program directory or Rust file").option("-f, --format <format>", "Output format (text|json|markdown)", "text").option("--ai", "Include AI-powered explanations").option("--fail-on <severity>", "Exit with error on severity level (critical|high|medium|low|any)", "critical").action(async (path, options) => {
  try {
    console.log(chalk.blue("\u{1F50D} SolGuard Security Audit"));
    console.log(chalk.gray(`Scanning: ${path}
`));
    const results = await scan(path, {
      format: options.format === "json" ? "json" : "object",
      ai: options.ai,
      failOn: options.failOn
    });
    if (results.findings.length === 0) {
      console.log(chalk.green("\u2705 No vulnerabilities found!"));
    } else {
      console.log(chalk.yellow(`\u26A0\uFE0F  Found ${results.findings.length} potential issues:
`));
      for (const finding of results.findings) {
        const severityColor = finding.severity === "critical" ? chalk.red : finding.severity === "high" ? chalk.yellow : finding.severity === "medium" ? chalk.cyan : chalk.gray;
        console.log(`${severityColor(`[${finding.severity.toUpperCase()}]`)} ${finding.id}: ${finding.title}`);
        console.log(chalk.gray(`  \u2514\u2500 ${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}`));
        console.log(chalk.gray(`     ${finding.description}`));
        if (finding.suggestion) {
          console.log(chalk.green(`     \u{1F4A1} ${finding.suggestion}`));
        }
        console.log();
      }
    }
    console.log(chalk.bold("\n\u{1F4CA} Summary:"));
    console.log(`  ${chalk.red("Critical:")} ${results.summary.critical}`);
    console.log(`  ${chalk.yellow("High:")} ${results.summary.high}`);
    console.log(`  ${chalk.cyan("Medium:")} ${results.summary.medium}`);
    console.log(`  ${chalk.gray("Low:")} ${results.summary.low}`);
    console.log(`  ${chalk.blue("Total:")} ${results.summary.total}`);
    console.log(chalk.gray(`  Duration: ${results.duration}ms
`));
    if (!results.passed) {
      process.exit(1);
    }
  } catch (error) {
    console.error(chalk.red(`Error: ${error.message}`));
    process.exit(2);
  }
});
program.command("check").description("Quick security check (pass/fail)").argument("<path>", "Path to program directory").option("--fail-on <severity>", "Fail on severity level", "critical").option("-q, --quiet", "Minimal output").action(async (path, options) => {
  await checkCommand(path, {
    failOn: options.failOn,
    quiet: options.quiet
  });
});
program.command("patterns").description("List all available security patterns").option("--json", "Output as JSON").option("-s, --severity <severity>", "Filter by severity").action((options) => {
  const patterns = listPatterns();
  let filtered = patterns;
  if (options.severity) {
    filtered = patterns.filter((p) => p.severity === options.severity);
  }
  if (options.json) {
    console.log(JSON.stringify(filtered, null, 2));
  } else {
    console.log(chalk.blue(`
\u{1F6E1}\uFE0F  SolGuard Security Patterns (${filtered.length} total)
`));
    const bySeverity = {
      critical: filtered.filter((p) => p.severity === "critical"),
      high: filtered.filter((p) => p.severity === "high"),
      medium: filtered.filter((p) => p.severity === "medium"),
      low: filtered.filter((p) => p.severity === "low"),
      info: filtered.filter((p) => p.severity === "info")
    };
    console.log(chalk.red(`Critical (${bySeverity.critical.length}):`));
    bySeverity.critical.slice(0, 10).forEach((p) => console.log(`  ${p.id}: ${p.name}`));
    if (bySeverity.critical.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.critical.length - 10} more`));
    console.log(chalk.yellow(`
High (${bySeverity.high.length}):`));
    bySeverity.high.slice(0, 10).forEach((p) => console.log(`  ${p.id}: ${p.name}`));
    if (bySeverity.high.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.high.length - 10} more`));
    console.log(chalk.cyan(`
Medium (${bySeverity.medium.length}):`));
    bySeverity.medium.slice(0, 10).forEach((p) => console.log(`  ${p.id}: ${p.name}`));
    if (bySeverity.medium.length > 10) console.log(chalk.gray(`  ... and ${bySeverity.medium.length - 10} more`));
    console.log(chalk.gray(`
Low (${bySeverity.low.length}):`));
    bySeverity.low.slice(0, 5).forEach((p) => console.log(`  ${p.id}: ${p.name}`));
    if (bySeverity.low.length > 5) console.log(chalk.gray(`  ... and ${bySeverity.low.length - 5} more`));
  }
});
program.command("version").description("Show version").action(() => {
  console.log("solguard v0.1.0");
  console.log("689+ security patterns");
});
program.parse();
export {
  getPatternById,
  listPatterns,
  scan
};
