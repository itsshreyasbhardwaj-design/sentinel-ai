import type { Rule } from '../types.js';
import { all, notInComment, notInTests } from './engine.js';

/**
 * AI/LLM security rule pack — mapped to the OWASP Top 10 for LLM Applications.
 *
 * These rules look for the structural mistakes that make an AI feature
 * exploitable: untrusted text reaching a system prompt, model output reaching a
 * sink that executes it, and agents holding more authority than their task
 * needs. They are the reason a generic SAST tool cannot review an agent.
 */

const LLM_REF = (id: string, slug: string) => ({
  title: `OWASP ${id}`,
  url: `https://genai.owasp.org/llmrisk/${slug}/`,
});

/** Call sites that send a prompt to a model, across the major SDKs. */
const MODEL_CALL =
  /(?:openai|anthropic|client|llm|model|genai|bedrock|cohere|mistral|groq|together|ollama)\s*\.\s*(?:chat\s*\.\s*completions\s*\.\s*create|messages\s*\.\s*create|completions?\s*\.\s*create|generate(?:_content|Content|Text)?|invoke|complete|stream|call|predict|converse)/i;

/** Sinks that execute or render whatever they are given. */
const DANGEROUS_SINK =
  /\b(?:eval|exec|execSync|execFile|spawn|system|popen|subprocess\.(?:run|call|Popen)|Function|compile|innerHTML|dangerouslySetInnerHTML|document\.write|os\.system|Runtime\.getRuntime|child_process)\b/;

/** Identifiers that plausibly hold model output. */
const MODEL_OUTPUT =
  /\b(?:completion|response|result|answer|output|generated|llm_?(?:response|output|result)|message\.content|choices\s*\[\s*0\s*\]|content\s*\[\s*0\s*\]|text|reply|assistant_?(?:message|reply))\b/i;

/** Identifiers that plausibly hold untrusted user input. */
const USER_INPUT =
  /\b(?:user_?(?:input|message|query|prompt|question|content|text)|req\.(?:body|query|params)|request\.(?:json|form|args|data)|params\.|query\.|body\.|input|message|prompt|question|search_?query)\b/i;

/** Identifiers that plausibly hold retrieved / third-party content. */
const RETRIEVED_CONTENT =
  /\b(?:retrieved|documents?|chunks?|context|search_?results?|page_?content|scraped|fetched|web_?content|email_?body|file_?content|tool_?(?:result|output)|rag_?context|knowledge|passages?|snippets?)\b/i;

export const AI_SECURITY_RULES: Rule[] = [
  /* ---------------- LLM01: Prompt Injection ---------------- */
  {
    id: 'ai-direct-prompt-injection',
    title: 'User input concatenated directly into a model prompt',
    description:
      'Untrusted input is interpolated into the prompt string rather than passed as a separate, clearly delimited message. Because an LLM has no structural boundary between instructions and data, the input can override the surrounding instructions.',
    severity: 'high',
    kind: 'ai-security',
    confidence: 'medium',
    languages: ['javascript', 'typescript', 'python', 'go', 'java', 'csharp', 'php', 'rust'],
    patterns: [
      /(?:system|prompt|instruction|template|system_?message)\s*[:=]\s*(?:f?["'`])[^"'`]*(?:\$\{|\{[a-z_]|%s|\+\s*[a-z_$])/i,
      /(?:messages|prompt)\s*[:=][^;\n]*(?:role\s*[:=]\s*["'`]system["'`])[^;\n]*(?:\$\{|\+\s*[a-z_$])/i,
    ],
    validate: all(notInComment, notInTests, (m) => USER_INPUT.test(m.line)),
    taxonomy: {
      cwe: ['CWE-1427'],
      owaspLlmTop10: ['LLM01:2025-Prompt Injection'],
      references: [LLM_REF('LLM01:2025 Prompt Injection', 'llm01-prompt-injection')],
    },
    remediationHint:
      'Keep instructions in the system message and pass user text as a separate user message. Delimit untrusted text explicitly and instruct the model to treat it as data, never as instructions.',
  },
  {
    id: 'ai-indirect-prompt-injection',
    title: 'Retrieved or fetched content placed into a prompt without isolation',
    description:
      'Content from documents, web pages, emails or tool results is injected into the prompt. An attacker who can influence any of those sources can plant instructions the model will follow — the indirect prompt injection pattern.',
    severity: 'critical',
    kind: 'ai-security',
    confidence: 'medium',
    languages: ['javascript', 'typescript', 'python', 'go', 'java', 'csharp'],
    patterns: [
      /(?:prompt|messages?|context|system|input)\s*[:=][^;\n]*(?:\$\{|\+|\.join\(|f["'])/i,
      /\.(?:format|join)\s*\([^)]*(?:documents?|chunks?|context|results?)/i,
    ],
    validate: all(
      notInComment,
      notInTests,
      (m) => RETRIEVED_CONTENT.test(m.line),
      // Require evidence this is actually prompt construction, not generic templating.
      (m) => /prompt|message|system|context|completion|llm|instruction/i.test(m.line),
    ),
    taxonomy: {
      cwe: ['CWE-1427'],
      owaspLlmTop10: ['LLM01:2025-Prompt Injection'],
      references: [LLM_REF('LLM01:2025 Prompt Injection', 'llm01-prompt-injection')],
    },
    remediationHint:
      'Wrap retrieved content in explicit delimiters, label it as untrusted data in the system prompt, and never let it reach a position where it can redefine the task. Consider a separate sanitization pass that strips imperative language from retrieved chunks.',
  },

  /* ---------------- LLM05: Improper Output Handling ---------------- */
  {
    id: 'ai-unsafe-output-execution',
    title: 'Model output passed to an execution sink',
    description:
      'Text generated by an LLM reaches `eval`, a shell, or an HTML sink. Because prompt injection can steer that text, this converts a prompt-level attack into full code execution or stored XSS.',
    severity: 'critical',
    kind: 'ai-security',
    confidence: 'high',
    languages: ['javascript', 'typescript', 'python', 'go', 'java', 'csharp', 'php'],
    patterns: [DANGEROUS_SINK],
    validate: all(notInComment, notInTests, (m) => {
      if (!MODEL_OUTPUT.test(m.line)) return false;
      // Require the file to actually talk to a model, so ordinary variables
      // named `result` do not trip this rule.
      return m.lines.some(
        (line) => MODEL_CALL.test(line) || /openai|anthropic|langchain|llm/i.test(line),
      );
    }),
    taxonomy: {
      cwe: ['CWE-94', 'CWE-79'],
      owaspLlmTop10: ['LLM05:2025-Improper Output Handling'],
      references: [
        LLM_REF('LLM05:2025 Improper Output Handling', 'llm05-improper-output-handling'),
      ],
    },
    remediationHint:
      'Treat model output as untrusted user input. Validate it against a strict schema, and never pass it to an interpreter, shell, or HTML sink without escaping.',
  },
  {
    id: 'ai-output-to-sql',
    title: 'Model-generated text used to build a database query',
    description:
      'An LLM composes or fills in a SQL query that is then executed. A successful prompt injection becomes a SQL injection with the application database privileges.',
    severity: 'critical',
    kind: 'ai-security',
    confidence: 'medium',
    languages: ['javascript', 'typescript', 'python', 'go', 'java', 'csharp'],
    patterns: [/\b(?:query|execute|exec|raw|executeQuery)\s*\(/],
    validate: all(
      notInComment,
      notInTests,
      (m) => MODEL_OUTPUT.test(m.line) && /sql|query|db|database/i.test(m.line),
    ),
    taxonomy: {
      cwe: ['CWE-89'],
      owaspLlmTop10: ['LLM05:2025-Improper Output Handling'],
      references: [
        LLM_REF('LLM05:2025 Improper Output Handling', 'llm05-improper-output-handling'),
      ],
    },
    remediationHint:
      'Do not let the model emit SQL. Have it choose from a fixed set of named queries and supply parameters that you bind yourself, then run against a read-only, least-privilege database role.',
  },

  /* ---------------- LLM06: Excessive Agency ---------------- */
  {
    id: 'ai-unsafe-tool-execution',
    title: 'Agent tool executes shell commands or arbitrary code',
    description:
      'A tool exposed to the model runs commands or evaluates code. Any prompt injection anywhere in the agent context escalates directly to code execution on the host.',
    severity: 'critical',
    kind: 'ai-security',
    confidence: 'high',
    languages: ['javascript', 'typescript', 'python'],
    patterns: [
      /(?:tool|function|@tool|StructuredTool|DynamicTool|FunctionTool)[^;\n]*(?:exec|shell|bash|command|terminal|run_?code|python_?repl)/i,
      /\b(?:ShellTool|PythonREPLTool|TerminalTool|BashProcess|PythonAstREPLTool)\b/,
      /allow_dangerous_(?:code|requests|tools)\s*=\s*True/i,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-250', 'CWE-78'],
      owaspLlmTop10: ['LLM06:2025-Excessive Agency'],
      references: [LLM_REF('LLM06:2025 Excessive Agency', 'llm06-excessive-agency')],
    },
    remediationHint:
      'Replace the general-purpose shell tool with narrow, purpose-built tools that accept structured parameters. If arbitrary execution is genuinely required, run it in an ephemeral sandbox with no network and no credentials.',
  },
  {
    id: 'ai-human-approval-disabled',
    title: 'Agent runs without human approval on consequential actions',
    description:
      'Auto-approval or an unbounded agent loop means the model can take irreversible actions — sending mail, moving money, deleting data — with no human checkpoint.',
    severity: 'high',
    kind: 'ai-security',
    confidence: 'medium',
    languages: ['javascript', 'typescript', 'python'],
    patterns: [
      /(?:auto_?approve|require_?(?:approval|confirmation|human)|human_?in_?the_?loop|needs_?approval|interrupt_?before)\s*[:=]\s*(?:False|false|None|null|\[\s*\])/,
      /(?:approval_?mode|permission_?mode)\s*[:=]\s*["'](?:auto|never|bypass|none|yolo)["']/i,
      /(?:max_?iterations|max_?steps|recursion_?limit)\s*[:=]\s*(?:None|null|-1|0|9{3,})/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-269', 'CWE-250'],
      owaspLlmTop10: ['LLM06:2025-Excessive Agency'],
      references: [LLM_REF('LLM06:2025 Excessive Agency', 'llm06-excessive-agency')],
    },
    remediationHint:
      'Classify tools by blast radius and require explicit human confirmation for anything irreversible or outward-facing. Cap iterations so a looping agent cannot run indefinitely.',
  },
  {
    id: 'ai-overprivileged-credentials',
    title: 'Agent tool configured with broad or administrative credentials',
    description:
      'The agent holds wildcard scopes or admin keys. Prompt injection then inherits every one of those permissions, so the blast radius is the credential, not the task.',
    severity: 'high',
    kind: 'ai-security',
    confidence: 'medium',
    languages: ['javascript', 'typescript', 'python', 'go'],
    patterns: [
      /(?:scope|scopes|permissions?|role)\s*[:=]\s*["'`[][^"'`\]]*(?:\*|admin|superuser|full_?access|owner|write:all|repo\b)/i,
      /(?:tool|agent|client)[^;\n]*(?:AWS_SECRET|ADMIN_TOKEN|ROOT_KEY|SERVICE_ROLE_KEY)/,
    ],
    validate: all(notInComment, notInTests, (m) =>
      m.lines.some((line) => /agent|tool|llm|openai|anthropic|langchain|mcp/i.test(line)),
    ),
    taxonomy: {
      cwe: ['CWE-269'],
      owaspLlmTop10: ['LLM06:2025-Excessive Agency'],
      references: [LLM_REF('LLM06:2025 Excessive Agency', 'llm06-excessive-agency')],
    },
    remediationHint:
      'Issue each tool its own least-privilege, short-lived credential scoped to exactly the resources that tool needs.',
  },

  /* ---------------- LLM02 / LLM07: Data & prompt disclosure ---------------- */
  {
    id: 'ai-secret-in-prompt',
    title: 'Secret or credential embedded in a prompt',
    description:
      'API keys or credentials placed in prompt text are transmitted to the model provider, retained in logs and traces, and can be extracted by an injection that asks the model to repeat its instructions.',
    severity: 'critical',
    kind: 'ai-security',
    confidence: 'medium',
    languages: ['javascript', 'typescript', 'python', 'go', 'java', 'csharp'],
    patterns: [
      /(?:prompt|system|message|instruction|context)[^;\n]*(?:api[_-]?key|secret|password|token|credential|private[_-]?key)\s*[:=]/i,
      /(?:prompt|system|content)\s*[:=][^;\n]*(?:process\.env\.|os\.environ\[|getenv\()/i,
    ],
    excludePatterns: [/redact|mask|placeholder|example|\*{3,}/i],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-200', 'CWE-798'],
      owaspLlmTop10: [
        'LLM02:2025-Sensitive Information Disclosure',
        'LLM07:2025-System Prompt Leakage',
      ],
      references: [
        LLM_REF(
          'LLM02:2025 Sensitive Information Disclosure',
          'llm02-sensitive-information-disclosure',
        ),
        LLM_REF('LLM07:2025 System Prompt Leakage', 'llm07-system-prompt-leakage'),
      ],
    },
    remediationHint:
      'Never place credentials in prompt text. Keep them server-side and let tools use them; the model only needs to know a tool exists, not the key behind it.',
  },
  {
    id: 'ai-pii-sent-to-model',
    title: 'Personal data forwarded to an external model provider',
    description:
      'Identifiable personal data is included in a model request. Depending on the provider and region this may constitute an onward transfer requiring a legal basis, and it widens the breach surface.',
    severity: 'medium',
    kind: 'ai-security',
    confidence: 'low',
    languages: ['javascript', 'typescript', 'python', 'go', 'java', 'csharp'],
    patterns: [
      /(?:prompt|messages?|content|input)\s*[:=][^;\n]*\b(?:ssn|social_?security|date_?of_?birth|dob|passport|credit_?card|card_?number|medical_?record|patient|diagnosis|national_?id|tax_?id)\b/i,
    ],
    excludePatterns: [/redact|anonymi[sz]|mask|hash|pseudonym/i],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-359'],
      owaspLlmTop10: ['LLM02:2025-Sensitive Information Disclosure'],
      references: [
        LLM_REF(
          'LLM02:2025 Sensitive Information Disclosure',
          'llm02-sensitive-information-disclosure',
        ),
      ],
    },
    remediationHint:
      'Redact or tokenize personal data before it leaves your infrastructure, and confirm the provider agreement covers the data category and region.',
  },

  /* ---------------- LLM08: Retrieval pipeline weaknesses ---------------- */
  {
    id: 'ai-vector-search-no-tenant-filter',
    title: 'Vector search without a tenancy or authorization filter',
    description:
      'A similarity search runs without restricting results to the caller tenant or permissions, so one user embedding query can surface another organization documents.',
    severity: 'high',
    kind: 'ai-security',
    confidence: 'medium',
    languages: ['javascript', 'typescript', 'python'],
    patterns: [
      /\.(?:similarity_?search|similaritySearch|query|search|as_?retriever|asRetriever|max_?marginal_?relevance_?search)\s*\(/,
    ],
    excludePatterns: [/filter|where|namespace|tenant|user_?id|org_?id|metadata|partition|scope/i],
    validate: all(notInComment, notInTests, (m) =>
      m.lines.some((line) =>
        /pinecone|weaviate|chroma|qdrant|milvus|pgvector|faiss|vectorstore|vector_?store|embedding/i.test(
          line,
        ),
      ),
    ),
    taxonomy: {
      cwe: ['CWE-1230', 'CWE-863'],
      owaspLlmTop10: ['LLM08:2025-Vector and Embedding Weaknesses'],
      references: [
        LLM_REF(
          'LLM08:2025 Vector and Embedding Weaknesses',
          'llm08-vector-and-embedding-weaknesses',
        ),
      ],
    },
    remediationHint:
      'Always pass a metadata filter scoping results to the caller tenant and permitted document set, and enforce it server-side rather than trusting the client.',
  },
  {
    id: 'ai-untrusted-document-ingestion',
    title: 'Externally fetched content ingested into the knowledge base without review',
    description:
      'Web pages or user uploads are embedded and stored directly. An attacker who controls a source can poison retrieval so their instructions are recalled as trusted context later.',
    severity: 'high',
    kind: 'ai-security',
    confidence: 'low',
    languages: ['javascript', 'typescript', 'python'],
    patterns: [
      /(?:WebBaseLoader|UnstructuredURLLoader|RecursiveUrlLoader|SitemapLoader|PlaywrightURLLoader|FireCrawlLoader)\s*\(/,
      /\.(?:add_?documents|addDocuments|upsert|add_?texts|from_?documents)\s*\(/,
    ],
    validate: all(notInComment, notInTests, (m) =>
      m.lines.some((line) => /url|http|scrape|crawl|fetch|upload/i.test(line)),
    ),
    taxonomy: {
      cwe: ['CWE-1395'],
      owaspLlmTop10: [
        'LLM04:2025-Data and Model Poisoning',
        'LLM08:2025-Vector and Embedding Weaknesses',
      ],
      references: [
        LLM_REF('LLM04:2025 Data and Model Poisoning', 'llm04-data-and-model-poisoning'),
      ],
    },
    remediationHint:
      'Record provenance for every chunk, restrict ingestion to vetted sources, and sanitize imperative language from untrusted documents before embedding.',
  },

  /* ---------------- LLM03: Supply chain ---------------- */
  {
    id: 'ai-untrusted-model-loading',
    title: 'Model or weights loaded from an unpinned or untrusted source',
    description:
      'Pickle-backed model formats execute code on load, and an unpinned revision means the artifact can change under you.',
    severity: 'high',
    kind: 'ai-security',
    confidence: 'medium',
    languages: ['python', 'javascript', 'typescript'],
    patterns: [/(?:from_?pretrained|load_?model|torch\.load|joblib\.load|hf_?hub_?download)\s*\(/],
    excludePatterns: [
      /revision\s*=|weights_only\s*=\s*True|safetensors|local_files_only\s*=\s*True/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-494', 'CWE-502'],
      owaspLlmTop10: ['LLM03:2025-Supply Chain'],
      references: [LLM_REF('LLM03:2025 Supply Chain', 'llm03-supply-chain')],
    },
    remediationHint:
      'Pin an exact `revision`, prefer `safetensors`, and pass `weights_only=True` to `torch.load`.',
  },

  /* ---------------- LLM10: Unbounded consumption ---------------- */
  {
    id: 'ai-unbounded-consumption',
    title: 'Model invocation without token, cost or timeout limits',
    description:
      'A model call with no `max_tokens` and no timeout lets a single crafted request run to the context ceiling, which is both a denial-of-service and a direct billing risk.',
    severity: 'medium',
    kind: 'ai-security',
    confidence: 'low',
    languages: ['javascript', 'typescript', 'python', 'go'],
    patterns: [MODEL_CALL],
    excludePatterns: [
      /max_?tokens|max_?output|maxOutputTokens|timeout|abort|signal|max_?completion/i,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-770', 'CWE-400'],
      owaspLlmTop10: ['LLM10:2025-Unbounded Consumption'],
      references: [LLM_REF('LLM10:2025 Unbounded Consumption', 'llm10-unbounded-consumption')],
    },
    remediationHint:
      'Set `max_tokens` and a request timeout on every call, and enforce a per-user rate and spend budget upstream.',
  },
  {
    id: 'ai-model-safety-disabled',
    title: 'Provider safety filters disabled or set to permissive',
    description:
      'Content safety thresholds have been turned off, removing a defense layer against harmful generations and some injection payloads.',
    severity: 'medium',
    kind: 'ai-security',
    confidence: 'high',
    languages: ['javascript', 'typescript', 'python', 'go'],
    patterns: [
      /safety_?settings?[^;\n]*(?:BLOCK_NONE|OFF|NONE|disabled)/i,
      /(?:moderation|content_?filter|safety_?filter|guardrails?)\s*[:=]\s*(?:false|False|None|null|"off"|'off')/,
    ],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-693'],
      owaspLlmTop10: ['LLM09:2025-Misinformation'],
      references: [LLM_REF('LLM09:2025 Misinformation', 'llm09-misinformation')],
    },
    remediationHint:
      'Keep provider safety filters on and add your own output moderation for the categories that matter to your product.',
  },
  {
    id: 'ai-unpinned-model-version',
    title: 'Model referenced by a floating alias',
    description:
      'Aliases like `latest` re-point without notice, silently changing behaviour, cost and safety characteristics of a production path.',
    severity: 'low',
    kind: 'ai-security',
    confidence: 'medium',
    languages: ['javascript', 'typescript', 'python', 'go', 'java', 'csharp'],
    patterns: [/model\s*[:=]\s*["'][^"']*(?:latest|preview|-\*|dev)["']/i],
    validate: all(notInComment, notInTests),
    taxonomy: {
      cwe: ['CWE-1104'],
      owaspLlmTop10: ['LLM03:2025-Supply Chain'],
      references: [LLM_REF('LLM03:2025 Supply Chain', 'llm03-supply-chain')],
    },
    remediationHint: 'Pin a dated model identifier and upgrade deliberately after evaluation.',
  },
  {
    id: 'ai-mcp-server-untrusted',
    title: 'MCP server configured from a remote or unpinned source',
    description:
      'Model Context Protocol servers run with the privileges of the host agent and can define new tools. Loading one from an unpinned remote source makes it a supply-chain entry point into the agent.',
    severity: 'high',
    kind: 'ai-security',
    confidence: 'medium',
    // Language-agnostic on purpose: MCP servers are declared in JSON config as
    // often as they are in code.
    patterns: [
      /"command"\s*:\s*"(?:npx|uvx|pipx)"[^}]*"-y"/,
      /mcpServers[^}]*"url"\s*:\s*"https?:\/\//,
    ],
    validate: notInComment,
    taxonomy: {
      cwe: ['CWE-494', 'CWE-829'],
      owaspLlmTop10: ['LLM03:2025-Supply Chain'],
      references: [LLM_REF('LLM03:2025 Supply Chain', 'llm03-supply-chain')],
    },
    remediationHint:
      'Pin MCP servers to an exact version, vendor them where possible, and review the tools a server registers before granting it to an agent.',
  },
];

/** Files that suggest the repository contains an AI application at all. */
export const AI_FRAMEWORK_MARKERS = [
  'openai',
  'anthropic',
  '@anthropic-ai/sdk',
  'langchain',
  'langgraph',
  'llama-index',
  'llama_index',
  'llamaindex',
  'semantic-kernel',
  'transformers',
  'ollama',
  'vercel/ai',
  'ai-sdk',
  '@ai-sdk',
  'litellm',
  'instructor',
  'crewai',
  'autogen',
  'haystack',
  'guidance',
  'dspy',
  'modelcontextprotocol',
  'mcp',
  'bedrock',
  'vertexai',
  'google-generativeai',
  'cohere',
  'mistralai',
  'groq',
  'pinecone',
  'weaviate',
  'chromadb',
  'qdrant',
  'pgvector',
];
