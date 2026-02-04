import { getDocsForPattern, getDocsForTopic, fetchDocContent, type DocReference } from '../docs-mapping.js';
import { getPatternById, listPatterns } from '../patterns/index.js';

const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
};

/**
 * Learn command - fetches official Solana documentation for patterns or topics
 * Leverages Solana's LLM-ready docs (.md format)
 * 
 * Usage:
 *   solshield learn SOL001        # Learn about Missing Owner Check
 *   solshield learn pda           # Learn about PDAs
 *   solshield learn cpi           # Learn about Cross Program Invocation
 */
export async function learnCommand(query: string, options: { 
  raw?: boolean;
  brief?: boolean;
  urls?: boolean;
}): Promise<void> {
  const { raw = false, brief = false, urls = false } = options;

  if (!query) {
    console.log(`${COLORS.cyan}${COLORS.bold}📚 SolShield Learn${COLORS.reset}`);
    console.log(`\nUsage: solshield learn <pattern-id|topic>\n`);
    console.log(`${COLORS.bold}Examples:${COLORS.reset}`);
    console.log(`  solshield learn SOL001     # Learn about Missing Owner Check`);
    console.log(`  solshield learn SOL004     # Learn about PDA Validation`);
    console.log(`  solshield learn pda        # Learn about PDAs in general`);
    console.log(`  solshield learn cpi        # Learn about Cross Program Invocation`);
    console.log(`  solshield learn tokens     # Learn about Solana tokens`);
    console.log(`\n${COLORS.bold}Available topics:${COLORS.reset}`);
    console.log(`  accounts, pda, cpi, tokens, transactions, programs, fees, rent, anchor, rust`);
    console.log(`\n${COLORS.bold}Options:${COLORS.reset}`);
    console.log(`  --urls     Show only documentation URLs`);
    console.log(`  --brief    Show summary only (no full content)`);
    console.log(`  --raw      Output raw markdown (for piping to LLMs)`);
    return;
  }

  // Check if it's a pattern ID (SOLxxx)
  const isPatternId = /^SOL\d{3}$/i.test(query);
  
  let docs: DocReference[] = [];
  let contextTitle = '';

  if (isPatternId) {
    const patternId = query.toUpperCase();
    const pattern = getPatternById(patternId);
    
    if (!pattern) {
      console.error(`${COLORS.yellow}Pattern ${patternId} not found.${COLORS.reset}`);
      console.log(`\nUse 'solshield list' to see all available patterns.`);
      return;
    }

    docs = getDocsForPattern(patternId);
    contextTitle = `${patternId}: ${pattern.name}`;

    if (!urls) {
      console.log(`\n${COLORS.cyan}${COLORS.bold}🛡️ ${contextTitle}${COLORS.reset}`);
      console.log(`${COLORS.dim}Severity: ${pattern.severity}${COLORS.reset}\n`);
    }

  } else {
    // It's a topic
    docs = getDocsForTopic(query);
    contextTitle = query.charAt(0).toUpperCase() + query.slice(1);
    
    if (docs.length === 0) {
      console.error(`${COLORS.yellow}Topic "${query}" not recognized.${COLORS.reset}`);
      console.log(`\nAvailable topics: accounts, pda, cpi, tokens, transactions, programs, fees, rent, anchor, rust`);
      return;
    }

    if (!urls) {
      console.log(`\n${COLORS.cyan}${COLORS.bold}📚 Learning: ${contextTitle}${COLORS.reset}\n`);
    }
  }

  if (docs.length === 0) {
    console.log(`${COLORS.yellow}No documentation mapped for this pattern yet.${COLORS.reset}`);
    console.log(`\nGeneral Solana security docs: https://solana.com/docs/programs/anchor`);
    return;
  }

  // URLs only mode
  if (urls) {
    console.log(`\n${COLORS.bold}📖 Documentation URLs:${COLORS.reset}\n`);
    for (const doc of docs) {
      console.log(`${COLORS.green}${doc.title}${COLORS.reset}`);
      console.log(`  Web:      ${doc.url}`);
      console.log(`  LLM-Ready: ${doc.mdUrl}`);
      if (doc.section) {
        console.log(`  ${COLORS.dim}Section: ${doc.section}${COLORS.reset}`);
      }
      console.log('');
    }
    console.log(`${COLORS.dim}💡 Tip: Use the .md URLs to feed documentation directly to AI assistants.${COLORS.reset}`);
    return;
  }

  // Brief mode - just show links
  if (brief) {
    console.log(`${COLORS.bold}📖 Related Documentation:${COLORS.reset}\n`);
    for (const doc of docs) {
      console.log(`  ${COLORS.green}•${COLORS.reset} ${doc.title}${doc.section ? ` (${doc.section})` : ''}`);
      console.log(`    ${COLORS.blue}${doc.url}${COLORS.reset}`);
    }
    console.log(`\n${COLORS.dim}Use --raw to fetch full content for LLM processing.${COLORS.reset}`);
    return;
  }

  // Fetch and display documentation content
  console.log(`${COLORS.bold}📖 Official Solana Documentation:${COLORS.reset}\n`);
  
  for (const doc of docs) {
    console.log(`${COLORS.magenta}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLORS.reset}`);
    console.log(`${COLORS.green}${COLORS.bold}${doc.title}${COLORS.reset}${doc.section ? ` → ${doc.section}` : ''}`);
    console.log(`${COLORS.dim}${doc.mdUrl}${COLORS.reset}`);
    console.log(`${COLORS.magenta}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLORS.reset}\n`);

    try {
      const content = await fetchDocContent(doc.mdUrl);
      
      if (raw) {
        // Raw mode - output markdown directly (good for piping to LLMs)
        console.log(content);
      } else {
        // Pretty print with truncation
        const lines = content.split('\n');
        const maxLines = 60;
        
        // Skip frontmatter
        let startLine = 0;
        if (lines[0] === '---') {
          for (let i = 1; i < lines.length; i++) {
            if (lines[i] === '---') {
              startLine = i + 1;
              break;
            }
          }
        }
        
        const displayLines = lines.slice(startLine, startLine + maxLines);
        console.log(displayLines.join('\n'));
        
        if (lines.length > startLine + maxLines) {
          console.log(`\n${COLORS.dim}... (${lines.length - startLine - maxLines} more lines)${COLORS.reset}`);
          console.log(`${COLORS.dim}Use --raw for full content or visit: ${doc.url}${COLORS.reset}`);
        }
      }
    } catch (error) {
      console.error(`${COLORS.yellow}Could not fetch content: ${error}${COLORS.reset}`);
      console.log(`${COLORS.dim}Visit: ${doc.url}${COLORS.reset}`);
    }
    
    console.log('');
  }

  if (!raw) {
    console.log(`\n${COLORS.cyan}💡 Pro tip:${COLORS.reset} Use 'solshield learn ${query} --raw | claude' to feed docs to your AI assistant.`);
  }
}
