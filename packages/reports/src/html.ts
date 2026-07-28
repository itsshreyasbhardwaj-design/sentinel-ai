import {
  assessCompliance,
  getFramework,
  type Finding,
  type ScanResult,
  type Severity,
} from '@sentinel/core';
import type { ExecutiveSummary, PrioritizedFinding } from '@sentinel/ai';

/**
 * Self-contained HTML report.
 *
 * Everything is inlined — no CDN, no fonts, no scripts from anywhere. The file
 * has to open correctly from an email attachment, from a USB stick in an
 * air-gapped review room, and from an S3 bucket with a strict CSP. That rules
 * out every external reference.
 */

export interface HtmlOptions {
  summary?: ExecutiveSummary;
  priorities?: PrioritizedFinding[];
  frameworks?: string[];
  maxFindings?: number;
  /** Emit print-optimized CSS for PDF generation. */
  forPrint?: boolean;
}

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#facc15',
  low: '#38bdf8',
  info: '#94a3b8',
};

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function gradeColor(grade: string): string {
  if (grade === 'A') return '#34d399';
  if (grade === 'B') return '#a3e635';
  if (grade === 'C') return '#facc15';
  if (grade === 'D') return '#fb923c';
  return '#f43f5e';
}

function styles(forPrint: boolean): string {
  return `
    :root {
      color-scheme: dark;
      --bg: #08090c;
      --panel: #0f1116;
      --panel-2: #14171e;
      --border: #232733;
      --text: #e8eaf0;
      --muted: #949cb0;
      --accent: #6366f1;
    }
    ${forPrint ? ':root { color-scheme: light; --bg:#fff; --panel:#fff; --panel-2:#f8f9fb; --border:#dfe3ea; --text:#12141a; --muted:#5a6274; }' : ''}
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 15px/1.65 ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    .wrap { max-width: 1080px; margin: 0 auto; padding: 48px 28px 96px; }
    header { border-bottom: 1px solid var(--border); padding-bottom: 28px; margin-bottom: 36px; }
    .eyebrow { color: var(--muted); font-size: 12px; letter-spacing: .14em; text-transform: uppercase; font-weight: 600; }
    h1 { font-size: 32px; line-height: 1.2; margin: 10px 0 6px; letter-spacing: -0.02em; }
    h2 { font-size: 20px; margin: 44px 0 16px; letter-spacing: -0.01em; }
    h3 { font-size: 16px; margin: 0 0 6px; letter-spacing: -0.01em; }
    p { margin: 0 0 12px; }
    a { color: var(--accent); }
    .muted { color: var(--muted); }
    .small { font-size: 13px; }
    .grid { display: grid; gap: 14px; }
    .cards { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px 18px;
    }
    .metric { font-size: 30px; font-weight: 650; letter-spacing: -0.03em; line-height: 1.1; }
    .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; margin-top: 4px; }
    .score-hero { display: flex; align-items: center; gap: 22px; flex-wrap: wrap; }
    .grade {
      width: 84px; height: 84px; border-radius: 18px;
      display: flex; align-items: center; justify-content: center;
      font-size: 40px; font-weight: 700; color: #08090c;
    }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .07em; font-weight: 600; }
    td.num, th.num { text-align: right; }
    .pill {
      display: inline-block; padding: 2px 9px; border-radius: 999px;
      font-size: 11px; font-weight: 650; text-transform: uppercase; letter-spacing: .05em; color: #08090c;
    }
    .finding {
      background: var(--panel); border: 1px solid var(--border);
      border-left: 3px solid var(--border);
      border-radius: 10px; padding: 18px 20px; margin-bottom: 14px;
      break-inside: avoid;
    }
    .finding .meta { color: var(--muted); font-size: 13px; margin: 6px 0 12px; }
    .impact {
      background: var(--panel-2); border-left: 2px solid var(--accent);
      padding: 10px 14px; border-radius: 0 8px 8px 0; margin: 12px 0; font-size: 14px;
    }
    pre {
      background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px;
      padding: 12px 14px; overflow-x: auto; font-size: 12.5px; line-height: 1.55;
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      margin: 10px 0;
    }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.92em; }
    .tag {
      display: inline-block; background: var(--panel-2); border: 1px solid var(--border);
      border-radius: 6px; padding: 1px 7px; font-size: 11.5px; margin: 2px 4px 2px 0; color: var(--muted);
    }
    .bar { height: 6px; border-radius: 3px; background: var(--panel-2); overflow: hidden; margin-top: 8px; }
    .bar > span { display: block; height: 100%; border-radius: 3px; }
    ul { margin: 0 0 12px; padding-left: 20px; }
    li { margin-bottom: 5px; }
    footer { margin-top: 56px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12.5px; }
    @media print {
      body { background: #fff; }
      .finding, .card { break-inside: avoid; }
      h2 { break-after: avoid; }
      .wrap { padding: 0; max-width: none; }
    }
  `;
}

function renderFinding(finding: Finding, priority?: PrioritizedFinding): string {
  const color = SEVERITY_COLOR[finding.severity];
  const taxonomy = [
    ...(finding.taxonomy?.cwe ?? []),
    ...(finding.taxonomy?.owaspTop10 ?? []),
    ...(finding.taxonomy?.owaspLlmTop10 ?? []),
    ...(finding.taxonomy?.cve ?? []),
  ];

  const parts: string[] = [];
  parts.push(`<article class="finding" style="border-left-color:${color}">`);
  parts.push(
    `<h3><span class="pill" style="background:${color}">${finding.severity}</span> ${escapeHtml(finding.title)}</h3>`,
  );
  parts.push(
    `<div class="meta">${
      finding.location
        ? `<code>${escapeHtml(finding.location.path)}:${finding.location.startLine}</code> · `
        : ''
    }confidence ${finding.confidence} · scanner <code>${escapeHtml(finding.scanner)}</code>${
      priority ? ` · priority #${priority.rank} (${priority.priorityScore}/100)` : ''
    }</div>`,
  );

  if (finding.explanation) {
    parts.push(`<p>${escapeHtml(finding.explanation.plainEnglish)}</p>`);
    parts.push(
      `<div class="impact"><strong>Business impact.</strong> ${escapeHtml(finding.explanation.businessImpact)}</div>`,
    );
    parts.push(
      `<p class="small"><strong>How it happens.</strong> ${escapeHtml(finding.explanation.howItHappens)}</p>`,
    );
  } else if (finding.description) {
    parts.push(`<p>${escapeHtml(finding.description)}</p>`);
  }

  if (finding.location?.snippet) {
    parts.push(`<pre>${escapeHtml(finding.location.snippet)}</pre>`);
  }

  const fixes = finding.explanation?.suggestedFixes ?? [];
  if (fixes.length) {
    parts.push('<p class="small"><strong>How to fix</strong></p><ul class="small">');
    for (const fix of fixes) {
      parts.push(
        `<li><strong>${escapeHtml(fix.title)}</strong> (${fix.effort}) — ${escapeHtml(fix.description)}`,
      );
      if (fix.code) parts.push(`<pre>${escapeHtml(fix.code)}</pre>`);
      parts.push('</li>');
    }
    parts.push('</ul>');
  } else if (finding.remediationHint) {
    parts.push(
      `<p class="small"><strong>How to fix.</strong> ${escapeHtml(finding.remediationHint)}</p>`,
    );
  }

  if (taxonomy.length) {
    parts.push(
      `<div>${taxonomy.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join('')}</div>`,
    );
  }

  parts.push('</article>');
  return parts.join('\n');
}

export function toHtml(result: ScanResult, options: HtmlOptions = {}): string {
  const active = result.findings.filter((f) => !f.suppressed);
  const counts = result.scores.counts;
  const maxFindings = options.maxFindings ?? 100;
  const priorityById = new Map((options.priorities ?? []).map((p) => [p.findingId, p]));

  const ordered = [...active].sort(
    (a, b) =>
      (priorityById.get(b.id)?.priorityScore ?? b.riskScore) -
      (priorityById.get(a.id)?.priorityScore ?? a.riskScore),
  );

  const body: string[] = [];

  body.push('<header>');
  body.push('<div class="eyebrow">Sentinel AI · Security Report</div>');
  body.push(`<h1>${escapeHtml(result.repository.name)}</h1>`);
  body.push(
    `<p class="muted small">${escapeHtml(result.repository.ref ?? 'default branch')}${
      result.repository.commit
        ? ` · <code>${escapeHtml(result.repository.commit.slice(0, 8))}</code>`
        : ''
    } · ${result.repository.fileCount.toLocaleString()} files · scanned ${new Date(result.startedAt).toUTCString()}</p>`,
  );
  body.push('</header>');

  if (result.status === 'failed') {
    body.push(
      `<div class="card" style="border-color:${SEVERITY_COLOR.critical}"><h3>Scan did not complete</h3><p class="muted">${escapeHtml(result.error ?? 'Unknown error.')}</p></div>`,
    );
    return wrap(result, body.join('\n'), options);
  }

  /* Score hero */
  body.push('<section class="score-hero">');
  body.push(
    `<div class="grade" style="background:${gradeColor(result.scores.grade)}">${result.scores.grade}</div>`,
  );
  body.push(
    `<div><div class="metric">${result.scores.overall}<span class="muted" style="font-size:18px">/100</span></div><div class="label">Overall security score · ${escapeHtml(result.scores.riskLevel)} risk</div></div>`,
  );
  body.push('</section>');

  if (options.summary) {
    body.push(
      `<p style="margin-top:22px;font-size:16px">${escapeHtml(options.summary.headline)}</p>`,
    );
    body.push(`<p class="muted">${escapeHtml(options.summary.posture)}</p>`);
  }

  /* Severity cards */
  body.push('<div class="grid cards" style="margin-top:26px">');
  for (const severity of ['critical', 'high', 'medium', 'low', 'info'] as const) {
    body.push(
      `<div class="card"><div class="metric" style="color:${SEVERITY_COLOR[severity]}">${counts[severity]}</div><div class="label">${severity}</div></div>`,
    );
  }
  body.push('</div>');

  /* Category scores */
  body.push('<h2>Repository health</h2>');
  body.push(
    '<table><thead><tr><th>Category</th><th class="num">Score</th><th>Grade</th><th class="num">Findings</th><th>Assessment</th></tr></thead><tbody>',
  );
  for (const category of result.scores.categories) {
    body.push(
      `<tr><td>${escapeHtml(category.category)}</td><td class="num">${
        category.analyzed ? category.score : '—'
      }<div class="bar"><span style="width:${category.analyzed ? category.score : 0}%;background:${gradeColor(category.grade)}"></span></div></td><td>${
        category.analyzed ? category.grade : '—'
      }</td><td class="num">${category.findingCount}</td><td class="muted small">${escapeHtml(category.rationale)}</td></tr>`,
    );
  }
  body.push('</tbody></table>');

  /* Recommended actions */
  if (options.summary?.recommendedActions.length) {
    body.push('<h2>Recommended actions</h2><ol>');
    for (const action of options.summary.recommendedActions)
      body.push(`<li>${escapeHtml(action)}</li>`);
    body.push('</ol>');
  }

  /* Findings */
  body.push(
    `<h2>Findings${ordered.length > maxFindings ? ` <span class="muted small">(top ${maxFindings} of ${ordered.length})</span>` : ''}</h2>`,
  );
  if (!ordered.length) {
    body.push('<div class="card"><p>No open findings in the analyzed scope.</p></div>');
  } else {
    for (const finding of ordered.slice(0, maxFindings)) {
      body.push(renderFinding(finding, priorityById.get(finding.id)));
    }
  }

  /* Compliance */
  if (options.frameworks?.length) {
    const analyzedKinds = [
      ...new Set(result.scannerRuns.filter((r) => r.status === 'ok').map((r) => r.kind)),
    ];
    body.push('<h2>Compliance</h2>');

    for (const frameworkId of options.frameworks) {
      const framework = getFramework(frameworkId);
      if (!framework) continue;
      const report = assessCompliance(framework, result.findings, result.id, analyzedKinds);

      body.push(
        `<h3 style="margin-top:22px">${escapeHtml(framework.name)} ${escapeHtml(framework.version)}</h3>`,
      );
      body.push(
        `<p class="muted small">${report.passed} passed · ${report.failed} failed · ${report.needsReview} need review · <strong>${report.coveragePercent}%</strong> of applicable controls passing</p>`,
      );
      body.push(
        '<table><thead><tr><th>Control</th><th>Status</th><th>Evidence</th></tr></thead><tbody>',
      );
      for (const assessment of report.assessments) {
        const color =
          assessment.status === 'pass'
            ? '#34d399'
            : assessment.status === 'fail'
              ? SEVERITY_COLOR.critical
              : '#facc15';
        body.push(
          `<tr><td><code>${escapeHtml(assessment.controlId)}</code> ${escapeHtml(assessment.title)}</td><td><span class="pill" style="background:${color}">${assessment.status}</span></td><td class="muted small">${escapeHtml(assessment.evidence)}</td></tr>`,
        );
      }
      body.push('</tbody></table>');
    }
  }

  /* Coverage */
  body.push('<h2>Scanner coverage</h2>');
  body.push(
    '<table><thead><tr><th>Scanner</th><th>Type</th><th>Status</th><th class="num">Findings</th><th>Notes</th></tr></thead><tbody>',
  );
  for (const run of result.scannerRuns) {
    const color =
      run.status === 'ok'
        ? '#34d399'
        : run.status === 'failed'
          ? SEVERITY_COLOR.critical
          : '#94a3b8';
    body.push(
      `<tr><td><code>${escapeHtml(run.scanner)}</code></td><td class="muted">${run.scannerKind}</td><td><span class="pill" style="background:${color}">${run.status}</span></td><td class="num">${run.findingCount}</td><td class="muted small">${escapeHtml(run.reason ?? '')}</td></tr>`,
    );
  }
  body.push('</tbody></table>');

  /* Caveats — never omitted */
  if (options.summary?.caveats.length) {
    body.push('<h2>Caveats and coverage limits</h2><ul class="small muted">');
    for (const caveat of options.summary.caveats) body.push(`<li>${escapeHtml(caveat)}</li>`);
    body.push('</ul>');
  }

  return wrap(result, body.join('\n'), options);
}

function wrap(result: ScanResult, body: string, options: HtmlOptions): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel AI — ${escapeHtml(result.repository.name)} security report</title>
<style>${styles(options.forPrint ?? false)}</style>
</head>
<body>
<div class="wrap">
${body}
<footer>
Generated by Sentinel AI 0.1.0 · scan <code>${escapeHtml(result.id)}</code> · ${(result.durationMs / 1000).toFixed(1)}s ·
${escapeHtml(new Date(result.completedAt ?? result.startedAt).toISOString())}
</footer>
</div>
</body>
</html>`;
}
