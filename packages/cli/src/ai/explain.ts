import Anthropic from '@anthropic-ai/sdk';
import type { Finding } from '../commands/audit.js';

const client = new Anthropic();

export async function explainFindings(findings: Finding[]): Promise<void> {
  // Skip if no API key
  if (!process.env.ANTHROPIC_API_KEY) {
    console.warn('ANTHROPIC_API_KEY not set, skipping AI explanations');
    return;
  }

  // Batch findings to reduce API calls
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

async function generateExplanations(findings: Finding[]): Promise<string[]> {
  const prompt = `You are a Solana security expert. For each vulnerability finding below, provide a brief, actionable explanation in 2-3 sentences that:
1. Explains why this is dangerous in plain English
2. Describes the potential exploit scenario
3. Confirms or refines the suggested fix

Findings:
${findings.map((f, i) => `
${i + 1}. ${f.pattern} (${f.severity.toUpperCase()})
   Location: ${f.location.file}${f.location.line ? `:${f.location.line}` : ''}
   ${f.code ? `Code: ${f.code}` : ''}
   Current suggestion: ${f.suggestion || 'None'}
`).join('\n')}

Respond with a JSON array of explanations, one per finding:
["explanation for finding 1", "explanation for finding 2", ...]`;

  const response = await client.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 1024,
    messages: [{ role: 'user', content: prompt }],
  });

  // Extract text content
  const text = response.content
    .filter(block => block.type === 'text')
    .map(block => (block as any).text)
    .join('');

  // Parse JSON response
  try {
    const jsonMatch = text.match(/\[[\s\S]*\]/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
  } catch {
    // If JSON parsing fails, split by newlines
    return text.split('\n').filter(line => line.trim());
  }

  return [];
}

export async function generateFullReport(findings: Finding[], programName: string): Promise<string> {
  if (!process.env.ANTHROPIC_API_KEY || findings.length === 0) {
    return '';
  }

  const response = await client.messages.create({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 2048,
    messages: [{
      role: 'user',
      content: `Generate a professional security audit summary for "${programName}".

Findings:
${findings.map(f => `- ${f.severity.toUpperCase()}: ${f.title}`).join('\n')}

Total: ${findings.length} findings (${findings.filter(f => f.severity === 'critical').length} critical, ${findings.filter(f => f.severity === 'high').length} high)

Write a 2-3 paragraph executive summary that:
1. Summarizes the overall security posture
2. Highlights the most critical issues
3. Recommends priority fixes
4. Notes any positive security patterns observed (if applicable)

Keep it professional but accessible.`
    }],
  });

  const text = response.content
    .filter(block => block.type === 'text')
    .map(block => (block as any).text)
    .join('');

  return text;
}
