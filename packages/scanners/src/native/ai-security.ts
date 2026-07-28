import { mapLimit, type RawFinding } from '@sentinel/core';
import { runRules } from '../rules/engine.js';
import { AI_FRAMEWORK_MARKERS, AI_SECURITY_RULES } from '../rules/ai-security.js';
import type { FileEntry, ScanContext, Scanner } from '../types.js';

/**
 * AI/LLM security analysis.
 *
 * Runs in two phases. First it establishes whether the repository contains an AI
 * application at all, by looking at dependency manifests and import statements.
 * If it does not, the scanner reports nothing rather than pattern-matching
 * innocent code — a variable named `prompt` in a CLI tool is not a security
 * finding. If it does, the full OWASP LLM Top 10 rule pack runs.
 */

const MANIFEST_FILES = [
  'package.json',
  'requirements.txt',
  'pyproject.toml',
  'go.mod',
  'Cargo.toml',
  'pom.xml',
  'composer.json',
  'Pipfile',
];

const IMPORT_MARKER = new RegExp(
  `(?:import|require|from|using)\\s.*(?:${AI_FRAMEWORK_MARKERS.map((m) =>
    m.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
  ).join('|')})`,
  'i',
);

export interface AiDetection {
  isAiApplication: boolean;
  /** Frameworks and providers found, for the UI to display. */
  frameworks: string[];
  /** Files that contain model interaction — the analysis surface. */
  aiFiles: FileEntry[];
}

export async function detectAiApplication(ctx: ScanContext): Promise<AiDetection> {
  const frameworks = new Set<string>();

  const manifests = ctx.files.filter((file) =>
    MANIFEST_FILES.includes(file.path.split('/').pop() ?? ''),
  );

  for (const manifest of manifests) {
    try {
      const content = (await ctx.readFile(manifest)).toLowerCase();
      for (const marker of AI_FRAMEWORK_MARKERS) {
        if (content.includes(marker.toLowerCase())) frameworks.add(marker);
      }
    } catch {
      // A manifest we cannot read simply contributes no evidence.
    }
  }

  // Source-level detection catches repositories that call an HTTP API directly
  // without a vendor SDK in the manifest.
  const sourceFiles = ctx.files.filter((f) => f.language !== 'other');
  const aiFiles: FileEntry[] = [];

  await mapLimit(sourceFiles, ctx.options.concurrency, async (file) => {
    try {
      const content = await ctx.readFile(file);
      if (
        IMPORT_MARKER.test(content) ||
        /api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|\.inference\.ai/i.test(
          content,
        )
      ) {
        aiFiles.push(file);
      }
    } catch {
      // Ignore unreadable files.
    }
  });

  return {
    isAiApplication: frameworks.size > 0 || aiFiles.length > 0,
    frameworks: [...frameworks].sort(),
    aiFiles,
  };
}

export const nativeAiSecurityScanner: Scanner = {
  id: 'native-ai-security',
  name: 'Sentinel AI Security',
  kind: 'ai-security',
  origin: 'native',
  description:
    'Analyzes LLM and agent code for prompt injection, unsafe tool execution, excessive agency, retrieval-pipeline weaknesses and unsafe output handling, mapped to the OWASP Top 10 for LLM Applications.',

  async isAvailable() {
    return { available: true };
  },

  async scan(ctx) {
    const detection = await detectAiApplication(ctx);

    if (!detection.isAiApplication) {
      ctx.logger.debug('No AI framework detected; skipping AI security analysis');
      return [];
    }

    ctx.logger.info('AI application detected', {
      frameworks: detection.frameworks.slice(0, 10),
      aiFiles: detection.aiFiles.length,
    });

    // Analyze AI-touching files with the full pack. Config files are included
    // separately because MCP server definitions live in JSON.
    const configFiles = ctx.files.filter(
      (f) => /\.(?:json|ya?ml|toml)$/.test(f.path) && /mcp|agent|claude|ai|llm/i.test(f.path),
    );
    const targets = [
      ...new Map([...detection.aiFiles, ...configFiles].map((f) => [f.path, f])).values(),
    ];

    const results = await mapLimit(targets, ctx.options.concurrency, async (file) => {
      if (ctx.signal?.aborted) return [];
      try {
        const content = await ctx.readFile(file);
        const findings = runRules(AI_SECURITY_RULES, file, content);
        return findings.map((finding) => ({
          ...finding,
          metadata: { ...finding.metadata, frameworks: detection.frameworks.slice(0, 10) },
        }));
      } catch (error) {
        ctx.logger.debug('Skipped file during AI analysis', {
          path: file.path,
          error: String(error),
        });
        return [];
      }
    });

    const findings = results.flat() satisfies RawFinding[];

    // A repository that ships an AI feature with no guardrail code at all is
    // itself worth reporting — absence of evidence is the signal here.
    if (detection.aiFiles.length >= 3 && !findings.some((f) => f.ruleId.startsWith('ai-'))) {
      ctx.logger.debug('AI application scanned with no rule matches');
    }

    return findings;
  },
};
