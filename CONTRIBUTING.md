# Contributing to SolShield AI

Thank you for your interest in contributing to SolShield AI! 🛡️

## Quick Start

```bash
# Clone the repo
git clone https://github.com/oh-ashen-one/solshield
cd SolShield AI

# Install dependencies
pnpm install

# Build CLI
cd packages/cli
pnpm build

# Run tests
pnpm test
```

## Project Structure

```
SolShield AI/
├── packages/
│   ├── cli/          # TypeScript CLI
│   ├── web/          # Next.js frontend
│   └── program/      # Anchor on-chain program
├── examples/         # Example contracts
├── schemas/          # JSON schemas
└── docs/             # Documentation
```

## Adding a New Pattern

1. Create a new file in `packages/cli/src/patterns/`:

```typescript
// packages/cli/src/patterns/my-pattern.ts
import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkMyPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  
  if (!input.rust?.content) return findings;
  
  // Your detection logic here
  
  return findings;
}
```

2. Register in `packages/cli/src/patterns/index.ts`:

```typescript
import { checkMyPattern } from './my-pattern.js';

// Add to patterns array:
{
  id: 'SOL016',
  name: 'My Pattern Name',
  severity: 'high',
  run: checkMyPattern,
},
```

3. Add tests in `packages/cli/src/test/patterns.test.ts`

4. Update the pattern count in stats and web UI

## Running Tests

```bash
cd packages/cli
pnpm test        # Run all tests
pnpm test:watch  # Watch mode
```

## Code Style

- TypeScript with strict mode
- Use `async/await` over callbacks
- Document public functions with JSDoc
- Keep functions small and focused

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Run tests: `pnpm test`
5. Commit with conventional commits: `feat: add X`
6. Push and open a PR

## Conventional Commits

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Tests
- `chore:` Maintenance

## Questions?

Open an issue or reach out on Discord!

---

Built with 🐉 by Midir for the Solana Agent Hackathon 2026
