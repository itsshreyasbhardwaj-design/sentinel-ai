import { maxSeverity } from './severity.js';
import type {
  ComplianceFramework,
  ComplianceReport,
  ControlAssessment,
  Finding,
  ScanKind,
} from './types.js';

/**
 * Compliance mapping works off *taxonomy tags*, not rule ids, so a control stays
 * satisfied when scanners are swapped out. A tag is any of:
 *   - `CWE-79`            — from `finding.taxonomy.cwe`
 *   - `A03:2021`          — OWASP Web Top 10 category prefix
 *   - `LLM01:2025`        — OWASP LLM Top 10 category prefix
 *   - `kind:secrets`      — the analysis domain that produced the finding
 */
export function taxonomyTags(finding: Finding): string[] {
  const tags = new Set<string>([`kind:${finding.kind}`]);
  for (const cwe of finding.taxonomy?.cwe ?? []) tags.add(cwe.toUpperCase());
  for (const owasp of finding.taxonomy?.owaspTop10 ?? []) tags.add(owasp.split('-')[0]!.trim());
  for (const llm of finding.taxonomy?.owaspLlmTop10 ?? []) tags.add(llm.split('-')[0]!.trim());
  if (finding.taxonomy?.cve?.length) tags.add('has:cve');
  return [...tags];
}

export const OWASP_TOP_10_2021: ComplianceFramework = {
  id: 'owasp-top-10-2021',
  name: 'OWASP Top 10',
  version: '2021',
  description: 'The ten most critical web application security risks.',
  url: 'https://owasp.org/Top10/',
  controls: [
    {
      id: 'A01:2021',
      title: 'Broken Access Control',
      description: 'Restrictions on authenticated users are not properly enforced.',
      mappedTaxonomy: ['A01:2021', 'CWE-22', 'CWE-284', 'CWE-285', 'CWE-639', 'CWE-862', 'CWE-863'],
    },
    {
      id: 'A02:2021',
      title: 'Cryptographic Failures',
      description: 'Weak, missing or misapplied cryptography exposes sensitive data.',
      mappedTaxonomy: [
        'A02:2021',
        'CWE-259',
        'CWE-327',
        'CWE-328',
        'CWE-330',
        'CWE-338',
        'CWE-798',
      ],
    },
    {
      id: 'A03:2021',
      title: 'Injection',
      description: 'Untrusted input is interpreted as code or query structure.',
      mappedTaxonomy: [
        'A03:2021',
        'CWE-77',
        'CWE-78',
        'CWE-79',
        'CWE-89',
        'CWE-90',
        'CWE-94',
        'CWE-943',
      ],
    },
    {
      id: 'A04:2021',
      title: 'Insecure Design',
      description: 'Missing or ineffective control design, not merely implementation bugs.',
      mappedTaxonomy: ['A04:2021', 'CWE-209', 'CWE-256', 'CWE-501', 'CWE-522'],
    },
    {
      id: 'A05:2021',
      title: 'Security Misconfiguration',
      description: 'Insecure defaults, verbose errors, or unhardened configuration.',
      mappedTaxonomy: [
        'A05:2021',
        'CWE-16',
        'CWE-611',
        'CWE-1004',
        'CWE-1032',
        'kind:iac',
        'kind:config',
        'kind:container',
      ],
    },
    {
      id: 'A06:2021',
      title: 'Vulnerable and Outdated Components',
      description: 'Dependencies with known vulnerabilities are in use.',
      mappedTaxonomy: ['A06:2021', 'CWE-1104', 'CWE-937', 'has:cve', 'kind:dependencies'],
    },
    {
      id: 'A07:2021',
      title: 'Identification and Authentication Failures',
      description: 'Authentication, session management or credential handling is weak.',
      mappedTaxonomy: ['A07:2021', 'CWE-287', 'CWE-295', 'CWE-306', 'CWE-384', 'CWE-613'],
    },
    {
      id: 'A08:2021',
      title: 'Software and Data Integrity Failures',
      description: 'Code or data is trusted without integrity verification.',
      mappedTaxonomy: ['A08:2021', 'CWE-345', 'CWE-494', 'CWE-502', 'CWE-829'],
    },
    {
      id: 'A09:2021',
      title: 'Security Logging and Monitoring Failures',
      description: 'Breaches go undetected because logging or alerting is inadequate.',
      mappedTaxonomy: ['A09:2021', 'CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'],
    },
    {
      id: 'A10:2021',
      title: 'Server-Side Request Forgery',
      description: 'The server fetches a remote resource from an unvalidated URL.',
      mappedTaxonomy: ['A10:2021', 'CWE-918'],
    },
  ],
};

export const OWASP_LLM_TOP_10: ComplianceFramework = {
  id: 'owasp-llm-top-10-2025',
  name: 'OWASP Top 10 for LLM Applications',
  version: '2025',
  description: 'The most critical security risks for applications built on large language models.',
  url: 'https://genai.owasp.org/llm-top-10/',
  controls: [
    {
      id: 'LLM01:2025',
      title: 'Prompt Injection',
      description: 'User or retrieved content manipulates model instructions.',
      mappedTaxonomy: ['LLM01:2025', 'CWE-1427'],
    },
    {
      id: 'LLM02:2025',
      title: 'Sensitive Information Disclosure',
      description: 'Secrets, PII or proprietary data reach the model or its output.',
      mappedTaxonomy: ['LLM02:2025', 'CWE-200', 'CWE-359'],
    },
    {
      id: 'LLM03:2025',
      title: 'Supply Chain',
      description: 'Untrusted models, adapters or datasets are loaded.',
      mappedTaxonomy: ['LLM03:2025', 'CWE-494', 'CWE-502'],
    },
    {
      id: 'LLM04:2025',
      title: 'Data and Model Poisoning',
      description: 'Training or retrieval corpora can be influenced by attackers.',
      mappedTaxonomy: ['LLM04:2025', 'CWE-1395'],
    },
    {
      id: 'LLM05:2025',
      title: 'Improper Output Handling',
      description: 'Model output is executed, rendered or trusted without validation.',
      mappedTaxonomy: ['LLM05:2025', 'CWE-79', 'CWE-94', 'CWE-95'],
    },
    {
      id: 'LLM06:2025',
      title: 'Excessive Agency',
      description: 'Agents hold more permission, autonomy or tool access than the task requires.',
      mappedTaxonomy: ['LLM06:2025', 'CWE-250', 'CWE-269'],
    },
    {
      id: 'LLM07:2025',
      title: 'System Prompt Leakage',
      description: 'System instructions containing secrets or logic can be extracted.',
      mappedTaxonomy: ['LLM07:2025', 'CWE-200', 'CWE-798'],
    },
    {
      id: 'LLM08:2025',
      title: 'Vector and Embedding Weaknesses',
      description: 'Retrieval pipelines lack tenancy isolation, provenance or sanitization.',
      mappedTaxonomy: ['LLM08:2025', 'CWE-1230'],
    },
    {
      id: 'LLM09:2025',
      title: 'Misinformation',
      description: 'Unverified model output is relied on for consequential decisions.',
      mappedTaxonomy: ['LLM09:2025', 'CWE-1426'],
    },
    {
      id: 'LLM10:2025',
      title: 'Unbounded Consumption',
      description: 'No limits on tokens, cost, recursion or tool-call depth.',
      mappedTaxonomy: ['LLM10:2025', 'CWE-770', 'CWE-400'],
    },
  ],
};

export const CWE_TOP_25: ComplianceFramework = {
  id: 'cwe-top-25',
  name: 'CWE Top 25 Most Dangerous Software Weaknesses',
  version: '2024',
  description: 'The most common and impactful software weakness classes.',
  url: 'https://cwe.mitre.org/top25/',
  controls: (
    [
      ['CWE-79', 'Cross-site Scripting'],
      ['CWE-787', 'Out-of-bounds Write'],
      ['CWE-89', 'SQL Injection'],
      ['CWE-352', 'Cross-Site Request Forgery'],
      ['CWE-22', 'Path Traversal'],
      ['CWE-125', 'Out-of-bounds Read'],
      ['CWE-78', 'OS Command Injection'],
      ['CWE-416', 'Use After Free'],
      ['CWE-862', 'Missing Authorization'],
      ['CWE-434', 'Unrestricted Upload of Dangerous File Type'],
      ['CWE-94', 'Code Injection'],
      ['CWE-20', 'Improper Input Validation'],
      ['CWE-77', 'Command Injection'],
      ['CWE-287', 'Improper Authentication'],
      ['CWE-269', 'Improper Privilege Management'],
      ['CWE-502', 'Deserialization of Untrusted Data'],
      ['CWE-200', 'Exposure of Sensitive Information'],
      ['CWE-863', 'Incorrect Authorization'],
      ['CWE-918', 'Server-Side Request Forgery'],
      ['CWE-119', 'Improper Restriction of Operations within Memory Buffer'],
      ['CWE-476', 'NULL Pointer Dereference'],
      ['CWE-798', 'Use of Hard-coded Credentials'],
      ['CWE-190', 'Integer Overflow or Wraparound'],
      ['CWE-400', 'Uncontrolled Resource Consumption'],
      ['CWE-306', 'Missing Authentication for Critical Function'],
    ] as const
  ).map(([id, title]) => ({
    id,
    title,
    description: `Presence of ${id} class weaknesses in the codebase.`,
    mappedTaxonomy: [id],
  })),
};

export const NIST_SSDF: ComplianceFramework = {
  id: 'nist-ssdf-1.1',
  name: 'NIST Secure Software Development Framework',
  version: 'SP 800-218 v1.1',
  description: 'Practices for reducing vulnerabilities in released software.',
  url: 'https://csrc.nist.gov/pubs/sp/800/218/final',
  controls: [
    {
      id: 'PW.4.1',
      title: 'Acquire well-secured software components',
      description: 'Third-party components are vetted and free of known vulnerabilities.',
      mappedTaxonomy: ['kind:dependencies', 'has:cve'],
    },
    {
      id: 'PW.4.4',
      title: 'Verify component integrity and provenance',
      description: 'Components are inventoried with an SBOM and license posture is known.',
      mappedTaxonomy: ['kind:license', 'kind:sbom'],
    },
    {
      id: 'PW.5.1',
      title: 'Follow secure coding practices',
      description: 'Source code is free of well-understood insecure patterns.',
      mappedTaxonomy: ['kind:sast'],
    },
    {
      id: 'PW.7.2',
      title: 'Perform automated code review',
      description: 'Static analysis runs against every change.',
      mappedTaxonomy: ['kind:sast'],
    },
    {
      id: 'PW.9.1',
      title: 'Configure software with secure defaults',
      description: 'Default configuration and infrastructure definitions are hardened.',
      mappedTaxonomy: ['kind:config', 'kind:iac', 'kind:container'],
    },
    {
      id: 'PS.1.1',
      title: 'Protect all forms of code from unauthorized access',
      description: 'Credentials are not committed to source control.',
      mappedTaxonomy: ['kind:secrets', 'CWE-798'],
    },
  ],
};

export const SOC2_COMMON_CRITERIA: ComplianceFramework = {
  id: 'soc2-cc',
  name: 'SOC 2 Common Criteria',
  version: '2017 (rev. 2022)',
  description: 'Trust Services Criteria relevant to application security evidence.',
  url: 'https://www.aicpa-cima.com/',
  controls: [
    {
      id: 'CC6.1',
      title: 'Logical access security',
      description: 'Access controls restrict unauthorized use of protected information assets.',
      mappedTaxonomy: ['A01:2021', 'A07:2021', 'CWE-284', 'CWE-287', 'CWE-862'],
    },
    {
      id: 'CC6.6',
      title: 'Protection against external threats',
      description: 'Boundary protections guard against threats from outside system boundaries.',
      mappedTaxonomy: ['A03:2021', 'A10:2021', 'CWE-918', 'kind:iac'],
    },
    {
      id: 'CC6.7',
      title: 'Transmission and disposal of information',
      description: 'Confidential data is protected in transit and secrets are managed.',
      mappedTaxonomy: ['A02:2021', 'kind:secrets', 'CWE-319', 'CWE-798'],
    },
    {
      id: 'CC7.1',
      title: 'Detection of configuration changes and vulnerabilities',
      description: 'Vulnerabilities and misconfigurations are detected and evaluated.',
      mappedTaxonomy: ['kind:dependencies', 'kind:config', 'has:cve'],
    },
    {
      id: 'CC8.1',
      title: 'Change management',
      description: 'Changes are authorized, designed, tested and approved before deployment.',
      mappedTaxonomy: ['kind:sast', 'A08:2021'],
    },
  ],
};

export const PCI_DSS_4: ComplianceFramework = {
  id: 'pci-dss-4.0',
  name: 'PCI DSS',
  version: '4.0',
  description: 'Requirements applicable to software that handles cardholder data.',
  url: 'https://www.pcisecuritystandards.org/',
  controls: [
    {
      id: '3.5',
      title: 'Protect stored account data',
      description: 'Strong cryptography protects stored sensitive data.',
      mappedTaxonomy: ['A02:2021', 'CWE-327', 'CWE-328'],
    },
    {
      id: '6.2.4',
      title: 'Prevent common software attacks',
      description: 'Software engineering techniques prevent injection and related attacks.',
      mappedTaxonomy: ['A03:2021', 'CWE-89', 'CWE-79', 'CWE-78', 'CWE-94'],
    },
    {
      id: '6.3.1',
      title: 'Identify and manage security vulnerabilities',
      description: 'Known vulnerabilities in components are identified and ranked.',
      mappedTaxonomy: ['kind:dependencies', 'has:cve'],
    },
    {
      id: '6.3.2',
      title: 'Maintain an inventory of bespoke and third-party software',
      description: 'A component inventory (SBOM) is maintained to support patching.',
      mappedTaxonomy: ['kind:sbom'],
    },
    {
      id: '8.3.1',
      title: 'Strong authentication',
      description: 'Authentication factors are implemented and credentials are not hard-coded.',
      mappedTaxonomy: ['kind:secrets', 'CWE-798', 'CWE-287'],
    },
  ],
};

export const ISO_27001_A8: ComplianceFramework = {
  id: 'iso-27001-2022-a8',
  name: 'ISO/IEC 27001:2022 Annex A.8',
  version: '2022',
  description: 'Technological controls relevant to secure development.',
  url: 'https://www.iso.org/standard/27001',
  controls: [
    {
      id: 'A.8.8',
      title: 'Management of technical vulnerabilities',
      description: 'Technical vulnerabilities are identified and remediated in a timely fashion.',
      mappedTaxonomy: ['kind:dependencies', 'has:cve', 'kind:sast'],
    },
    {
      id: 'A.8.9',
      title: 'Configuration management',
      description: 'Secure configurations are defined, implemented and monitored.',
      mappedTaxonomy: ['kind:config', 'kind:iac', 'kind:container'],
    },
    {
      id: 'A.8.24',
      title: 'Use of cryptography',
      description: 'Rules for effective use of cryptography are implemented.',
      mappedTaxonomy: ['A02:2021', 'CWE-327', 'CWE-330'],
    },
    {
      id: 'A.8.28',
      title: 'Secure coding',
      description: 'Secure coding principles are applied to software development.',
      mappedTaxonomy: ['kind:sast', 'A03:2021'],
    },
    {
      id: 'A.8.31',
      title: 'Separation of environments',
      description:
        'Development, test and production environments are separated and secrets scoped.',
      mappedTaxonomy: ['kind:secrets', 'kind:config'],
    },
  ],
};

export const NIST_AI_RMF: ComplianceFramework = {
  id: 'nist-ai-rmf-1.0',
  name: 'NIST AI Risk Management Framework',
  version: '1.0',
  description: 'Governance of risks introduced by AI and generative AI systems.',
  url: 'https://www.nist.gov/itl/ai-risk-management-framework',
  controls: [
    {
      id: 'MAP-5.1',
      title: 'AI system impacts are identified',
      description: 'Likelihood and magnitude of AI system impacts are characterized.',
      mappedTaxonomy: ['kind:ai-security'],
    },
    {
      id: 'MEASURE-2.7',
      title: 'AI system security and resilience are evaluated',
      description: 'Security of the AI system, including prompt handling, is measured.',
      mappedTaxonomy: ['LLM01:2025', 'LLM05:2025', 'LLM08:2025'],
    },
    {
      id: 'MEASURE-2.10',
      title: 'Privacy risk of the AI system is examined',
      description: 'Data leakage and sensitive information disclosure risks are assessed.',
      mappedTaxonomy: ['LLM02:2025', 'LLM07:2025'],
    },
    {
      id: 'MANAGE-2.2',
      title: 'Mechanisms to limit AI system autonomy',
      description: 'Controls bound the autonomy and permissions granted to AI agents.',
      mappedTaxonomy: ['LLM06:2025', 'LLM10:2025'],
    },
  ],
};

export const FRAMEWORKS: ComplianceFramework[] = [
  OWASP_TOP_10_2021,
  OWASP_LLM_TOP_10,
  CWE_TOP_25,
  NIST_SSDF,
  SOC2_COMMON_CRITERIA,
  PCI_DSS_4,
  ISO_27001_A8,
  NIST_AI_RMF,
];

export function getFramework(id: string): ComplianceFramework | undefined {
  return FRAMEWORKS.find((f) => f.id === id);
}

/**
 * Assess a framework against a scan.
 *
 * A control is only marked `pass` when the scan actually covered the relevant
 * domain. Otherwise it is `needs-review` — reporting "pass" for something we
 * never looked at would be the single most damaging bug this module could have.
 */
export function assessCompliance(
  framework: ComplianceFramework,
  findings: readonly Finding[],
  scanId: string,
  analyzedKinds: readonly ScanKind[],
): ComplianceReport {
  const active = findings.filter((f) => !f.suppressed && f.status !== 'false-positive');
  const tagged = active.map((f) => ({ finding: f, tags: new Set(taxonomyTags(f)) }));
  const coveredKinds = new Set(analyzedKinds.map((k) => `kind:${k}`));

  const assessments: ControlAssessment[] = framework.controls.map((control) => {
    const matched = tagged.filter(({ tags }) =>
      control.mappedTaxonomy.some((tag) => tags.has(tag)),
    );

    if (matched.length) {
      const worst = maxSeverity(matched.map((m) => m.finding.severity));
      return {
        controlId: control.id,
        title: control.title,
        status: 'fail',
        findingIds: matched.map((m) => m.finding.id),
        ...(worst ? { worstSeverity: worst } : {}),
        evidence: `${matched.length} finding(s) map to this control; highest severity ${worst ?? 'info'}.`,
      };
    }

    // Did the scan look at anything that could have triggered this control?
    const kindTags = control.mappedTaxonomy.filter((t) => t.startsWith('kind:'));
    const wasCovered = kindTags.length
      ? kindTags.some((t) => coveredKinds.has(t))
      : analyzedKinds.includes('sast');

    return {
      controlId: control.id,
      title: control.title,
      status: wasCovered ? 'pass' : 'needs-review',
      findingIds: [],
      evidence: wasCovered
        ? 'No findings mapped to this control in the analyzed scope.'
        : 'The scan did not cover the analysis domains required to evaluate this control.',
    };
  });

  const passed = assessments.filter((a) => a.status === 'pass').length;
  const failed = assessments.filter((a) => a.status === 'fail').length;
  const needsReview = assessments.filter((a) => a.status === 'needs-review').length;
  const notApplicable = assessments.filter((a) => a.status === 'not-applicable').length;
  const applicable = passed + failed;

  return {
    frameworkId: framework.id,
    frameworkName: framework.name,
    frameworkVersion: framework.version,
    scanId,
    generatedAt: new Date().toISOString(),
    coveragePercent: applicable ? Math.round((passed / applicable) * 100) : 0,
    passed,
    failed,
    notApplicable,
    needsReview,
    assessments,
  };
}
