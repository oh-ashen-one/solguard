#!/usr/bin/env node
import {
  getAccountsWithoutSigner,
  getMutableAccountsWithoutOwnerCheck,
  parseIdl
} from "./chunk-HWAQQY7Q.js";

// src/index.ts
import { Command } from "commander";
import chalk4 from "chalk";

// src/commands/audit.ts
import chalk2 from "chalk";
import ora from "ora";

// src/parsers/rust.ts
import { readFileSync } from "fs";
async function parseRustFiles(paths) {
  const files = paths.map((path) => {
    const content = readFileSync(path, "utf-8");
    return {
      path,
      content,
      lines: content.split("\n")
    };
  });
  const functions = [];
  const structs = [];
  const implBlocks = [];
  for (const file of files) {
    const fnMatches = file.content.matchAll(/^(\s*)(pub\s+)?fn\s+(\w+)/gm);
    for (const match of fnMatches) {
      const line = file.content.substring(0, match.index).split("\n").length;
      functions.push({
        name: match[3],
        file: file.path,
        line,
        isPublic: !!match[2],
        content: extractBlock(file.content, match.index)
      });
    }
    const structMatches = file.content.matchAll(/((?:#\[[\w\(\)]+\]\s*)+)?pub\s+struct\s+(\w+)/gm);
    for (const match of structMatches) {
      const line = file.content.substring(0, match.index).split("\n").length;
      const attributes = match[1] ? match[1].match(/#\[[\w\(\),\s=]+\]/g) || [] : [];
      structs.push({
        name: match[2],
        file: file.path,
        line,
        fields: [],
        // Would need proper parsing for fields
        attributes
      });
    }
    const implMatches = file.content.matchAll(/impl(?:<[^>]+>)?\s+(\w+)/gm);
    for (const match of implMatches) {
      const line = file.content.substring(0, match.index).split("\n").length;
      implBlocks.push({
        structName: match[1],
        file: file.path,
        line,
        methods: []
      });
    }
  }
  return { files, functions, structs, implBlocks };
}
function extractBlock(content, startIndex) {
  let braceCount = 0;
  let started = false;
  let endIndex = startIndex;
  for (let i = startIndex; i < content.length; i++) {
    if (content[i] === "{") {
      braceCount++;
      started = true;
    } else if (content[i] === "}") {
      braceCount--;
      if (started && braceCount === 0) {
        endIndex = i + 1;
        break;
      }
    }
  }
  return content.substring(startIndex, endIndex);
}
function findUncheckedArithmetic(rust) {
  const results = [];
  const arithmeticPattern = /(\w+)\s*[\+\-\*]\s*(\w+)(?!\s*\.checked_)/g;
  for (const file of rust.files) {
    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      if (line.trim().startsWith("//")) continue;
      const matches = line.matchAll(arithmeticPattern);
      for (const match of matches) {
        if (!line.includes("checked_") && !line.includes(".saturating_")) {
          results.push({
            file: file.path,
            line: i + 1,
            code: line.trim()
          });
        }
      }
    }
  }
  return results;
}
function findMissingOwnerChecks(rust) {
  const results = [];
  const externalAccountTypes = ["TokenAccount", "Mint", "AssociatedTokenAccount"];
  for (const file of rust.files) {
    const content = file.content;
    for (const extType of externalAccountTypes) {
      const pattern = new RegExp(`pub\\s+(\\w+):\\s*Account<'info,\\s*${extType}>`, "g");
      const ownerPattern = /#\[account\([^)]*(?:owner|token::authority|associated_token::authority)\s*=/;
      const matches2 = content.matchAll(pattern);
      for (const match of matches2) {
        const lineIndex = content.substring(0, match.index).split("\n").length - 1;
        const precedingLines = file.lines.slice(Math.max(0, lineIndex - 5), lineIndex + 1).join("\n");
        if (!ownerPattern.test(precedingLines)) {
          results.push({
            file: file.path,
            line: lineIndex + 1,
            account: match[1]
          });
        }
      }
    }
    const accountInfoPattern = /pub\s+(\w+):\s*(?:UncheckedAccount|AccountInfo)<'info>/g;
    const matches = content.matchAll(accountInfoPattern);
    for (const match of matches) {
      const lineIndex = content.substring(0, match.index).split("\n").length - 1;
      const accountName = match[1];
      const precedingLines = file.lines.slice(Math.max(0, lineIndex - 3), lineIndex + 1).join("\n");
      if (/\/\/\/?\s*CHECK:/.test(precedingLines)) continue;
      if (/system_program|rent|clock|token_program|associated_token_program/i.test(accountName)) continue;
      const ownerCheckPattern = new RegExp(`${accountName}\\s*\\.\\s*owner|owner.*${accountName}|require.*${accountName}.*owner`, "i");
      if (!ownerCheckPattern.test(content)) {
        results.push({
          file: file.path,
          line: lineIndex + 1,
          account: accountName
        });
      }
    }
  }
  return results;
}
function findMissingSignerChecks(rust) {
  const results = [];
  const accountInfoPattern = /pub\s+(\w+):\s*AccountInfo<'info>/g;
  for (const file of rust.files) {
    const matches = file.content.matchAll(accountInfoPattern);
    for (const match of matches) {
      const lineIndex = file.content.substring(0, match.index).split("\n").length;
      const accountName = match[1];
      if (/authority|admin|owner|signer|payer/i.test(accountName)) {
        results.push({
          file: file.path,
          line: lineIndex,
          account: accountName
        });
      }
    }
  }
  return results;
}

// src/patterns/owner-check.ts
function checkMissingOwner(input) {
  const findings = [];
  if (input.idl) {
    const issues = getMutableAccountsWithoutOwnerCheck(input.idl);
    for (const issue of issues) {
      findings.push({
        id: `SOL001-${findings.length + 1}`,
        pattern: "Missing Owner Check",
        severity: "critical",
        title: `Mutable account '${issue.account}' may lack owner verification`,
        description: `In instruction '${issue.instruction}', the account '${issue.account}' is mutable but may not have proper owner verification. An attacker could pass a fake account owned by a different program.`,
        location: {
          file: "IDL",
          line: void 0
        },
        suggestion: `Add owner constraint: #[account(owner = expected_program_id)]`
      });
    }
  }
  if (input.rust) {
    const issues = findMissingOwnerChecks(input.rust);
    for (const issue of issues) {
      findings.push({
        id: `SOL001-${findings.length + 1}`,
        pattern: "Missing Owner Check",
        severity: "critical",
        title: `Account '${issue.account}' may lack owner constraint`,
        description: `The account '${issue.account}' is declared as Account<'info, T> but may not have an owner constraint. Without this, an attacker could pass an account owned by a malicious program with matching data layout.`,
        location: {
          file: issue.file,
          line: issue.line
        },
        suggestion: `Add owner constraint to the account:
#[account(owner = crate::ID)]
pub ${issue.account}: Account<'info, YourType>,`
      });
    }
  }
  return findings;
}

// src/patterns/signer-check.ts
function checkMissingSigner(input) {
  const findings = [];
  if (input.idl) {
    const issues = getAccountsWithoutSigner(input.idl);
    for (const issue of issues) {
      findings.push({
        id: `SOL002-${findings.length + 1}`,
        pattern: "Missing Signer Check",
        severity: "critical",
        title: `Instruction '${issue.instruction}' has no signer requirement`,
        description: `The instruction '${issue.instruction}' doesn't require any account to sign the transaction. This means anyone can call this instruction, which may allow unauthorized actions.`,
        location: {
          file: "IDL",
          line: void 0
        },
        suggestion: `Add a signer account:
pub authority: Signer<'info>,`
      });
    }
  }
  if (input.rust) {
    const issues = findMissingSignerChecks(input.rust);
    for (const issue of issues) {
      findings.push({
        id: `SOL002-${findings.length + 1}`,
        pattern: "Missing Signer Check",
        severity: "critical",
        title: `Authority account '${issue.account}' is not a Signer`,
        description: `The account '${issue.account}' appears to be an authority/admin account but is declared as AccountInfo instead of Signer. This means anyone could pass any account as the authority without proving ownership.`,
        location: {
          file: issue.file,
          line: issue.line
        },
        code: `pub ${issue.account}: AccountInfo<'info>`,
        suggestion: `Change to Signer:
pub ${issue.account}: Signer<'info>,`
      });
    }
  }
  return findings;
}

// src/patterns/overflow.ts
function checkIntegerOverflow(input) {
  const findings = [];
  if (!input.rust) return findings;
  const issues = findUncheckedArithmetic(input.rust);
  for (const issue of issues) {
    if (isSafeArithmetic(issue.code)) continue;
    findings.push({
      id: `SOL003-${findings.length + 1}`,
      pattern: "Integer Overflow",
      severity: "high",
      title: "Potential integer overflow in arithmetic operation",
      description: `Unchecked arithmetic operation found. In Rust, integer overflow in release mode wraps around silently, which can lead to serious vulnerabilities like incorrect balances or bypassed checks.`,
      location: {
        file: issue.file,
        line: issue.line
      },
      code: issue.code,
      suggestion: `Use checked arithmetic:
let result = a.checked_add(b).ok_or(ErrorCode::Overflow)?;

Or saturating arithmetic:
let result = a.saturating_add(b);`
    });
  }
  return findings;
}
function isSafeArithmetic(code) {
  if (/\.checked_|\.saturating_|\.overflowing_/.test(code)) return true;
  if (/\".*\"/.test(code)) return true;
  if (/for\s+\w+\s+in/.test(code)) return true;
  if (/\[\s*\w+\s*\+\s*\d+\s*\]/.test(code)) return true;
  if (/\+\s*1\s*[;\)]/.test(code) && !/amount|balance|value|price|total/i.test(code)) return true;
  if (/space\s*=.*\+/.test(code)) return true;
  if (/INIT_SPACE/.test(code)) return true;
  return false;
}

// src/patterns/pda-validation.ts
function checkPdaValidation(input) {
  const findings = [];
  if (!input.rust) return findings;
  for (const file of input.rust.files) {
    const lines = file.lines;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/find_program_address/.test(line) || /Pubkey::find_program_address/.test(line)) {
        const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join("\n");
        if (!/bump\s*==|bump\.eq|assert.*bump|require.*bump/.test(context)) {
          findings.push({
            id: `SOL004-${findings.length + 1}`,
            pattern: "PDA Validation Gap",
            severity: "high",
            title: "PDA derived without bump verification",
            description: `A PDA is derived using find_program_address but the bump may not be verified. An attacker could potentially pass a PDA with a different bump, leading to account confusion.`,
            location: {
              file: file.path,
              line: i + 1
            },
            code: line.trim(),
            suggestion: `Store and verify the bump:
let (pda, bump) = Pubkey::find_program_address(&seeds, &program_id);
assert!(bump == expected_bump);`
          });
        }
      }
      if (/create_program_address/.test(line) && !/\?|unwrap_or|ok_or/.test(line)) {
        findings.push({
          id: `SOL004-${findings.length + 1}`,
          pattern: "PDA Validation Gap",
          severity: "medium",
          title: "Unhandled PDA creation error",
          description: `create_program_address can fail if the seeds produce an invalid PDA (on-curve point). The error should be handled gracefully.`,
          location: {
            file: file.path,
            line: i + 1
          },
          code: line.trim(),
          suggestion: `Handle the Result:
let pda = Pubkey::create_program_address(&seeds, &program_id)
    .map_err(|_| ErrorCode::InvalidPda)?;`
        });
      }
      if (/#\[account\(.*seeds\s*=/.test(line) && !/#\[account\(.*bump/.test(line)) {
        const context = lines.slice(i, Math.min(lines.length, i + 3)).join(" ");
        if (!context.includes("bump")) {
          findings.push({
            id: `SOL004-${findings.length + 1}`,
            pattern: "PDA Validation Gap",
            severity: "medium",
            title: "PDA seeds without bump constraint",
            description: `An account has a seeds constraint but no bump constraint. While Anchor will derive the bump, explicitly storing it is more gas-efficient and clearer.`,
            location: {
              file: file.path,
              line: i + 1
            },
            code: line.trim(),
            suggestion: `Add bump constraint:
#[account(
    seeds = [b"prefix", user.key().as_ref()],
    bump = pda_account.bump,
)]`
          });
        }
      }
    }
  }
  return findings;
}

// src/patterns/authority-bypass.ts
function checkAuthorityBypass(input) {
  const rust = input.rust;
  const findings = [];
  if (!rust?.files) return findings;
  let counter = 1;
  for (const file of rust.files) {
    const lines = file.content.split("\n");
    let inFunction = false;
    let functionName = "";
    let functionStart = 0;
    let hasAuthorityCheck = false;
    let isSensitiveOperation = false;
    let braceDepth = 0;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      const fnMatch = line.match(/pub\s+fn\s+(\w+)/);
      if (fnMatch) {
        if (inFunction && isSensitiveOperation && !hasAuthorityCheck) {
          if (!/^init|initialize|create|new/i.test(functionName)) {
            findings.push({
              id: `SOL005-${counter++}`,
              pattern: "authority-bypass",
              severity: "critical",
              title: `Function '${functionName}' may lack authority verification`,
              description: `The function '${functionName}' performs sensitive operations but doesn't appear to verify authority before execution. An attacker could potentially call this function and bypass intended access controls.`,
              location: {
                file: file.path,
                line: functionStart
              },
              suggestion: `Add authority verification at the start of the function:
require!(ctx.accounts.authority.key() == expected_authority, ErrorCode::Unauthorized);

Or use Anchor's has_one constraint:
#[account(has_one = authority)]`
            });
          }
        }
        inFunction = true;
        functionName = fnMatch[1];
        functionStart = lineNum;
        hasAuthorityCheck = false;
        isSensitiveOperation = false;
        braceDepth = 0;
      }
      braceDepth += (line.match(/{/g) || []).length;
      braceDepth -= (line.match(/}/g) || []).length;
      if (inFunction && braceDepth <= 0 && line.includes("}")) {
        if (isSensitiveOperation && !hasAuthorityCheck && !/^init|initialize|create|new/i.test(functionName)) {
          findings.push({
            id: `SOL005-${counter++}`,
            pattern: "authority-bypass",
            severity: "critical",
            title: `Function '${functionName}' may lack authority verification`,
            description: `The function '${functionName}' performs sensitive operations but doesn't appear to verify authority before execution. An attacker could potentially call this function and bypass intended access controls.`,
            location: {
              file: file.path,
              line: functionStart
            },
            suggestion: `Add authority verification at the start of the function:
require!(ctx.accounts.authority.key() == expected_authority, ErrorCode::Unauthorized);

Or use Anchor's has_one constraint:
#[account(has_one = authority)]`
          });
        }
        inFunction = false;
      }
      if (!inFunction) continue;
      const sensitivePatterns = [
        /\.transfer\s*\(/,
        // SOL transfers
        /\.withdraw\s*\(/,
        // Withdrawals
        /transfer_checked/,
        // SPL token transfers
        /invoke_signed/,
        // CPIs with signer seeds
        /set_authority/,
        // Authority changes
        /close_account/,
        // Account closure
        /\.sub\s*\(/,
        // Balance subtraction
        /balance\s*[-=]/,
        // Balance modification
        /mint_to/,
        // Token minting
        /burn/,
        // Token burning
        /freeze/,
        // Account freezing
        /\.authority\s*=/,
        // Authority assignment
        /admin/i
        // Admin operations
      ];
      for (const pattern of sensitivePatterns) {
        if (pattern.test(line)) {
          isSensitiveOperation = true;
          break;
        }
      }
      const authCheckPatterns = [
        /require!\s*\([^)]*authority/i,
        /require!\s*\([^)]*admin/i,
        /require!\s*\([^)]*owner/i,
        /require_keys_eq!/,
        // Anchor's key comparison macro
        /\.key\(\)\s*==\s*.*authority/,
        /has_one\s*=\s*authority/,
        /has_one\s*=\s*owner/,
        /has_one\s*=\s*admin/,
        /constraint\s*=.*authority/,
        /Signer<'info>/,
        // If authority is a Signer, it's implicitly checked
        /authority:\s*Signer/
        // Authority declared as Signer in struct
      ];
      for (const pattern of authCheckPatterns) {
        if (pattern.test(line)) {
          hasAuthorityCheck = true;
          break;
        }
      }
      if (/has_one\s*=/.test(line) || /constraint\s*=.*==/.test(line)) {
        hasAuthorityCheck = true;
      }
    }
  }
  return findings;
}

// src/patterns/init-check.ts
function checkMissingInitCheck(input) {
  const rust = input.rust;
  const findings = [];
  if (!rust?.files) return findings;
  let counter = 1;
  for (const file of rust.files) {
    const lines = file.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      if (line.includes("UncheckedAccount") && !line.includes("/// CHECK:")) {
        const prevLines = lines.slice(Math.max(0, i - 3), i).join("\n");
        if (!prevLines.includes("/// CHECK:") && !prevLines.includes("// CHECK:")) {
          findings.push({
            id: `SOL006-${counter++}`,
            pattern: "unchecked-account",
            severity: "high",
            title: "UncheckedAccount without safety documentation",
            description: "UncheckedAccount is used without a /// CHECK: comment explaining why it's safe. While sometimes necessary, unchecked accounts are a common source of vulnerabilities and should be documented.",
            location: {
              file: file.path,
              line: lineNum
            },
            code: line.trim(),
            suggestion: `Add a CHECK comment explaining why this account is safe:
/// CHECK: This account is safe because [your reason here]
pub my_account: UncheckedAccount<'info>,

Or use a typed Account with appropriate constraints if possible.`
          });
        }
      }
    }
  }
  return findings;
}

// src/patterns/cpi-check.ts
function checkCpiVulnerabilities(input) {
  const rust = input.rust;
  const findings = [];
  if (!rust?.files) return findings;
  let counter = 1;
  for (const file of rust.files) {
    const lines = file.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      if (/\binvoke\s*\(/.test(line) && !line.includes("invoke_signed")) {
        const context = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 5)).join("\n");
        if (!/(program_id|program\.key\(\)).*==|require.*program/.test(context)) {
          findings.push({
            id: `SOL007-${counter++}`,
            pattern: "cpi-vulnerability",
            severity: "high",
            title: "CPI invoke() without program ID verification",
            description: "Cross-program invocation (invoke) is called without verifying the target program ID. An attacker could substitute a malicious program with the same interface, leading to arbitrary code execution with your program's privileges.",
            location: {
              file: file.path,
              line: lineNum
            },
            code: line.trim(),
            suggestion: `Verify the program ID before CPI:
require_keys_eq!(target_program.key(), expected_program::ID, ErrorCode::InvalidProgram);
invoke(&instruction, &account_infos)?;`
          });
        }
      }
      if (/invoke_signed\s*\(/.test(line)) {
        const context = lines.slice(i, Math.min(lines.length, i + 10)).join("\n");
        if (/seeds\s*=\s*\[\s*b"[^"]+"\s*\]/.test(context) && !context.includes(".key()") && !context.includes(".as_ref()")) {
          findings.push({
            id: `SOL007-${counter++}`,
            pattern: "cpi-static-seeds",
            severity: "medium",
            title: "invoke_signed() with static-only seeds",
            description: "The PDA seeds for invoke_signed appear to contain only static values without any dynamic components (like user pubkey). This could lead to a single global PDA that any user can interact with, potentially causing unauthorized access.",
            location: {
              file: file.path,
              line: lineNum
            },
            code: line.trim(),
            suggestion: `Include dynamic seeds to create user-specific PDAs:
let seeds = &[
    b"prefix",
    user.key().as_ref(),
    &[bump],
];`
          });
        }
      }
      if (/AccountInfo.*program/.test(line) && !/Program<'info/.test(line)) {
        const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join("\n");
        if (/invoke/.test(context) && !/(executable|key\(\)\s*==|CHECK:)/.test(context)) {
          findings.push({
            id: `SOL007-${counter++}`,
            pattern: "cpi-unchecked-program",
            severity: "critical",
            title: "CPI to unverified program account",
            description: "A program account is passed as AccountInfo and used for CPI without verification. The account might not be executable or could be a different program than expected. Use Anchor's Program<> type or manually verify the executable flag and program ID.",
            location: {
              file: file.path,
              line: lineNum
            },
            code: line.trim(),
            suggestion: `Use Anchor's Program type for automatic verification:
pub token_program: Program<'info, Token>,

Or manually verify:
require!(program_account.executable, ErrorCode::NotExecutable);
require_keys_eq!(program_account.key(), expected::ID, ErrorCode::InvalidProgram);`
          });
        }
      }
    }
  }
  return findings;
}

// src/patterns/rounding.ts
function checkRoundingErrors(input) {
  const rust = input.rust;
  const findings = [];
  if (!rust?.files) return findings;
  let counter = 1;
  for (const file of rust.files) {
    const lines = file.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      if (line.trim().startsWith("//")) continue;
      if (/\/.*\*/.test(line) || /\bdiv\s*\(.*\).*mul/.test(line)) {
        if (!/(ceil|floor|round|checked_div.*checked_mul)/.test(line)) {
          findings.push({
            id: `SOL008-${counter++}`,
            pattern: "rounding-division-first",
            severity: "medium",
            title: "Division before multiplication may cause precision loss",
            description: "Performing division before multiplication can lead to precision loss due to integer truncation. In financial calculations, this can result in users receiving fewer tokens than expected, or protocol fees being under-collected.",
            location: {
              file: file.path,
              line: lineNum
            },
            code: line.trim(),
            suggestion: `Reorder to multiply before divide:
// Instead of: (amount / total) * shares
// Use: (amount * shares) / total

// Or use fixed-point math:
let result = amount
    .checked_mul(shares)?
    .checked_div(total)?;`
          });
        }
      }
      if (/(amount|balance|tokens?).*\/.*10/.test(line) || /\/ 1_?000_?000/.test(line)) {
        if (!/decimals|DECIMALS|checked_div/.test(line)) {
          findings.push({
            id: `SOL008-${counter++}`,
            pattern: "rounding-decimal-truncation",
            severity: "low",
            title: "Potential decimal truncation in token calculation",
            description: "Division by powers of 10 (often for decimal conversion) without proper rounding may truncate small amounts. Consider whether rounding up or down is appropriate for your use case.",
            location: {
              file: file.path,
              line: lineNum
            },
            code: line.trim(),
            suggestion: `Consider explicit rounding direction:
// Round down (default, favors protocol):
let amount = raw_amount / 10u64.pow(decimals);

// Round up (favors user):
let amount = (raw_amount + 10u64.pow(decimals) - 1) / 10u64.pow(decimals);`
          });
        }
      }
      if (/(fee|commission|tax).*[*\/]/.test(line.toLowerCase())) {
        const context = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 3)).join("\n");
        if (!/(min|minimum|max|\.max\(|\.min\()/.test(context.toLowerCase())) {
          findings.push({
            id: `SOL008-${counter++}`,
            pattern: "rounding-zero-fee",
            severity: "medium",
            title: "Fee calculation may round to zero",
            description: "Fee calculations on small amounts may truncate to zero, allowing users to transact without paying fees. Consider enforcing a minimum fee or using ceiling division for fee calculations.",
            location: {
              file: file.path,
              line: lineNum
            },
            code: line.trim(),
            suggestion: `Enforce minimum fee or use ceiling division:
// Option 1: Minimum fee
let fee = calculated_fee.max(MINIMUM_FEE);

// Option 2: Ceiling division (rounds up)
let fee = (amount * fee_rate + FEE_DENOMINATOR - 1) / FEE_DENOMINATOR;`
          });
        }
      }
      if (/(shares?|lp_?tokens?|mint_amount).*[=].*[\/]/.test(line.toLowerCase())) {
        if (!/(checked_|ceil|floor|round)/.test(line)) {
          findings.push({
            id: `SOL008-${counter++}`,
            pattern: "rounding-share-calculation",
            severity: "medium",
            title: "Share calculation may have rounding issues",
            description: "LP token or share calculations using division may lead to rounding exploits. First depositor attacks and share inflation attacks often exploit rounding in these calculations.",
            location: {
              file: file.path,
              line: lineNum
            },
            code: line.trim(),
            suggestion: `Use safe share calculation patterns:
// For minting (round down to protect protocol):
let shares = if total_supply == 0 {
    deposit_amount
} else {
    deposit_amount
        .checked_mul(total_supply)?
        .checked_div(total_assets)?
};

// Consider minimum share requirements for first deposit`
          });
        }
      }
    }
  }
  return findings;
}

// src/patterns/account-confusion.ts
function checkAccountConfusion(input) {
  const rust = input.rust;
  const findings = [];
  if (!rust?.files) return findings;
  let counter = 1;
  for (const file of rust.files) {
    const lines = file.content.split("\n");
    const content = file.content;
    const structPattern = /#\[derive\(Accounts\)\]\s*pub\s+struct\s+(\w+)[^{]*\{([^}]+)\}/g;
    let structMatch;
    while ((structMatch = structPattern.exec(content)) !== null) {
      const structName = structMatch[1];
      const structBody = structMatch[2];
      const structStartLine = content.substring(0, structMatch.index).split("\n").length;
      const accountPattern = /pub\s+(\w+):\s*Account<'info,\s*(\w+)>/g;
      const accounts = [];
      let accountMatch;
      while ((accountMatch = accountPattern.exec(structBody)) !== null) {
        const lineOffset = structBody.substring(0, accountMatch.index).split("\n").length;
        accounts.push({
          name: accountMatch[1],
          dataType: accountMatch[2],
          line: structStartLine + lineOffset
        });
      }
      for (let i = 0; i < accounts.length; i++) {
        for (let j = i + 1; j < accounts.length; j++) {
          const a = accounts[i];
          const b = accounts[j];
          if (a.dataType === b.dataType && a.name !== b.name) {
            const hasDiscrimination = new RegExp(
              `${a.name}.*!=.*${b.name}|${b.name}.*!=.*${a.name}|constraint.*${a.name}.*${b.name}|constraint.*${b.name}.*${a.name}`
            ).test(structBody);
            if (!hasDiscrimination) {
              findings.push({
                id: `SOL009-${counter++}`,
                pattern: "account-confusion",
                severity: "high",
                title: `Accounts '${a.name}' and '${b.name}' in '${structName}' may be confusable`,
                description: `Both '${a.name}' and '${b.name}' are of type ${a.dataType} within the same instruction context. An attacker might pass the same account for both, or swap them, leading to unexpected behavior. This is especially dangerous in transfer/swap operations.`,
                location: {
                  file: file.path,
                  line: a.line
                },
                suggestion: `Add constraints to ensure accounts are different:
#[account(
    constraint = ${a.name}.key() != ${b.name}.key() @ ErrorCode::SameAccount
)]

Or use different account types/discriminators for different purposes.`
              });
            }
          }
        }
      }
    }
    const accountInfoPattern = /pub\s+(\w+):\s*(AccountInfo|UncheckedAccount)<'info>/g;
    let aiMatch;
    while ((aiMatch = accountInfoPattern.exec(content)) !== null) {
      const accountName = aiMatch[1];
      const accountType = aiMatch[2];
      const lineNum = content.substring(0, aiMatch.index).split("\n").length;
      if (/system_program|rent|clock|token_program|^_/.test(accountName)) continue;
      const prevLines = lines.slice(Math.max(0, lineNum - 4), lineNum).join("\n");
      if (prevLines.includes("CHECK:")) continue;
      const usagePattern = new RegExp(`${accountName}\\s*\\.\\s*(data|try_borrow_data|deserialize)`);
      if (usagePattern.test(content)) {
        findings.push({
          id: `SOL009-${counter++}`,
          pattern: "untyped-account-data-access",
          severity: "high",
          title: `Untyped account '${accountName}' has data accessed`,
          description: `The account '${accountName}' is declared as ${accountType} but its data is accessed. Without type validation, an attacker could pass any account with arbitrary data, potentially bypassing security checks.`,
          location: {
            file: file.path,
            line: lineNum
          },
          code: lines[lineNum - 1]?.trim() || "",
          suggestion: `Use a typed Account instead:
pub ${accountName}: Account<'info, YourDataType>,

Or manually validate the account discriminator:
let data = ${accountName}.try_borrow_data()?;
require!(data[..8] == YourDataType::DISCRIMINATOR, ErrorCode::InvalidAccount);`
        });
      }
    }
  }
  return findings;
}

// src/patterns/closing-account.ts
function checkClosingVulnerabilities(input) {
  const rust = input.rust;
  const findings = [];
  if (!rust?.files) return findings;
  let counter = 1;
  for (const file of rust.files) {
    const lines = file.content.split("\n");
    const content = file.content;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      if (/lamports.*=\s*0|\.sub\(.*lamports\)|transfer.*lamports/.test(line)) {
        const context = lines.slice(i, Math.min(lines.length, i + 10)).join("\n");
        if (!/(realloc|data.*=.*\[0|zero|clear|close\s*=)/.test(context)) {
          findings.push({
            id: `SOL010-${counter++}`,
            pattern: "closing-without-zeroing",
            severity: "critical",
            title: "Account closed without zeroing data",
            description: 'Lamports are being removed from an account (closing it) but the data is not being zeroed. An attacker can "revive" the account by sending lamports back before the runtime garbage collects it, potentially reusing stale data for exploits.',
            location: {
              file: file.path,
              line: lineNum
            },
            code: line.trim(),
            suggestion: `Zero the account data before closing:
// Zero the data
account.data.borrow_mut().fill(0);

// Or use Anchor's close constraint:
#[account(mut, close = recipient)]
pub account_to_close: Account<'info, MyData>,`
          });
        }
      }
      if (/#\[account\([^)]*close\s*[,\)]/.test(line) && !/#\[account\([^)]*close\s*=/.test(line)) {
        findings.push({
          id: `SOL010-${counter++}`,
          pattern: "close-missing-recipient",
          severity: "medium",
          title: "Account close without explicit recipient",
          description: "The close constraint is used but no recipient is specified for the rent refund. This could lead to funds being sent to an unintended address.",
          location: {
            file: file.path,
            line: lineNum
          },
          code: line.trim(),
          suggestion: `Specify the recipient for the rent refund:
#[account(mut, close = authority)]
pub account_to_close: Account<'info, MyData>,`
        });
      }
      if (/#\[account\([^)]*close\s*=\s*(\w+)/.test(line)) {
        const match = line.match(/close\s*=\s*(\w+)/);
        if (match) {
          const recipient = match[1];
          const recipientPattern = new RegExp(`${recipient}.*Signer|${recipient}.*authority|has_one.*${recipient}`, "i");
          if (!recipientPattern.test(content)) {
            findings.push({
              id: `SOL010-${counter++}`,
              pattern: "close-to-unvalidated",
              severity: "high",
              title: `Account closes to unvalidated recipient '${recipient}'`,
              description: `The account is closed with rent sent to '${recipient}', but this recipient doesn't appear to be validated. An attacker might be able to specify their own address to receive the rent.`,
              location: {
                file: file.path,
                line: lineNum
              },
              code: line.trim(),
              suggestion: `Ensure the close recipient is validated:
#[account(
    mut,
    close = authority,
    has_one = authority  // Validate authority owns this account
)]
pub account_to_close: Account<'info, MyData>,

pub authority: Signer<'info>,  // Must sign`
            });
          }
        }
      }
      if (/realloc\s*\(\s*0/.test(line)) {
        const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5)).join("\n");
        if (!/close|lamports/.test(context)) {
          findings.push({
            id: `SOL010-${counter++}`,
            pattern: "realloc-zero-incomplete",
            severity: "medium",
            title: "Account reallocated to zero size",
            description: "The account is reallocated to zero size but may not be properly closed. The account will still exist with zero data but non-zero lamports, which could cause confusion.",
            location: {
              file: file.path,
              line: lineNum
            },
            code: line.trim(),
            suggestion: `Use Anchor's close constraint for proper account closure:
#[account(mut, close = recipient)]

Or manually transfer all lamports after realloc.`
          });
        }
      }
    }
  }
  return findings;
}

// src/patterns/index.ts
var patterns = [
  {
    id: "SOL001",
    name: "Missing Owner Check",
    severity: "critical",
    run: checkMissingOwner
  },
  {
    id: "SOL002",
    name: "Missing Signer Check",
    severity: "critical",
    run: checkMissingSigner
  },
  {
    id: "SOL003",
    name: "Integer Overflow",
    severity: "high",
    run: checkIntegerOverflow
  },
  {
    id: "SOL004",
    name: "PDA Validation Gap",
    severity: "high",
    run: checkPdaValidation
  },
  {
    id: "SOL005",
    name: "Authority Bypass",
    severity: "critical",
    run: checkAuthorityBypass
  },
  {
    id: "SOL006",
    name: "Missing Initialization Check",
    severity: "critical",
    run: checkMissingInitCheck
  },
  {
    id: "SOL007",
    name: "CPI Vulnerability",
    severity: "high",
    run: checkCpiVulnerabilities
  },
  {
    id: "SOL008",
    name: "Rounding Error",
    severity: "medium",
    run: checkRoundingErrors
  },
  {
    id: "SOL009",
    name: "Account Confusion",
    severity: "high",
    run: checkAccountConfusion
  },
  {
    id: "SOL010",
    name: "Account Closing Vulnerability",
    severity: "critical",
    run: checkClosingVulnerabilities
  }
];
async function runPatterns(input) {
  const findings = [];
  for (const pattern of patterns) {
    try {
      const patternFindings = pattern.run(input);
      findings.push(...patternFindings);
    } catch (error) {
      console.warn(`Pattern ${pattern.id} failed: ${error}`);
    }
  }
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  return findings;
}

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

// src/index.ts
var program = new Command();
var args = process.argv.slice(2);
var isJsonOutput = args.includes("--output") && args[args.indexOf("--output") + 1] === "json";
if (!isJsonOutput) {
  console.log(chalk4.cyan(`
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
program.parse();
