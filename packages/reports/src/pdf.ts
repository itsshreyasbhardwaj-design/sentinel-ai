import type { ScanResult, Severity } from '@sentinel/core';
import type { ExecutiveSummary, PrioritizedFinding } from '@sentinel/ai';

/**
 * PDF generation without a dependency.
 *
 * Every JavaScript PDF library either pulls in a headless browser (hundreds of
 * megabytes, and a sandbox escape surface) or a large font-embedding stack. For
 * a text report neither is warranted: PDF 1.7 with the standard Type 1 fonts
 * needs no embedding, so a compliant multi-page document is a few hundred lines
 * of writer.
 *
 * Output opens in every PDF reader, is selectable and searchable, and adds
 * nothing to the install footprint.
 */

const PAGE = { width: 595.28, height: 841.89 }; // A4 in points
const MARGIN = { top: 56, bottom: 56, left: 56, right: 56 };
const CONTENT_WIDTH = PAGE.width - MARGIN.left - MARGIN.right;

type FontName = 'F1' | 'F2' | 'F3';

interface TextRun {
  text: string;
  font: FontName;
  size: number;
  color: [number, number, number];
  /** Extra space before this line. */
  spaceBefore?: number;
  indent?: number;
}

/**
 * Approximate string width for the standard 14 fonts.
 *
 * Exact Helvetica metrics would need the AFM tables. These averages are within
 * a few percent, which is enough for wrapping a report and avoids embedding a
 * metrics table for cosmetic precision.
 */
const CHAR_WIDTH: Record<FontName, number> = {
  F1: 0.5, // Helvetica
  F2: 0.545, // Helvetica-Bold
  F3: 0.6, // Courier
};

function textWidth(text: string, font: FontName, size: number): number {
  return text.length * CHAR_WIDTH[font] * size;
}

/** Escape the three characters that are special inside a PDF string literal. */
function escapePdfText(text: string): string {
  return (
    text
      // Collapse newlines and tabs to spaces *first*. The non-ASCII strip below
      // would otherwise delete them outright and weld the surrounding words
      // together ("credential.In this case").
      .replace(/[\r\n\t]+/g, ' ')
      .replace(/\\/g, '\\\\')
      .replace(/\(/g, '\\(')
      .replace(/\)/g, '\\)')
      // The standard fonts use WinAnsiEncoding; drop anything outside it rather
      // than emitting bytes that render as garbage.
      .replace(/[^\x20-\x7E]/g, (char) => {
        const replacements: Record<string, string> = {
          '—': '-',
          '–': '-',
          '‘': "'",
          '’': "'",
          '“': '"',
          '”': '"',
          '…': '...',
          '·': '-',
          '→': '->',
          '✅': '[ok]',
          '❌': '[fail]',
          '⚠': '[!]',
          '⏭': '[skip]',
          '🔴': '[C]',
          '🟠': '[H]',
          '🟡': '[M]',
          '🔵': '[L]',
          '⚪': '[I]',
          '🟢': '[A]',
        };
        return replacements[char] ?? '';
      })
  );
}

function wrapText(text: string, font: FontName, size: number, maxWidth: number): string[] {
  const words = text.split(/\s+/).filter(Boolean);
  if (!words.length) return [''];

  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (textWidth(candidate, font, size) <= maxWidth) {
      current = candidate;
      continue;
    }
    if (current) lines.push(current);

    // A single word longer than the line (a long path or URL) is hard-split.
    if (textWidth(word, font, size) > maxWidth) {
      const charsPerLine = Math.max(1, Math.floor(maxWidth / (CHAR_WIDTH[font] * size)));
      for (let i = 0; i < word.length; i += charsPerLine) {
        lines.push(word.slice(i, i + charsPerLine));
      }
      current = lines.pop() ?? '';
    } else {
      current = word;
    }
  }

  if (current) lines.push(current);
  return lines;
}

const SEVERITY_RGB: Record<Severity, [number, number, number]> = {
  critical: [0.89, 0.25, 0.35],
  high: [0.98, 0.57, 0.24],
  medium: [0.9, 0.75, 0.15],
  low: [0.22, 0.6, 0.86],
  info: [0.55, 0.58, 0.65],
};

const BLACK: [number, number, number] = [0.09, 0.1, 0.13];
const GREY: [number, number, number] = [0.42, 0.45, 0.52];

class PdfBuilder {
  private readonly pages: string[][] = [];
  private current: string[] = [];
  private y = PAGE.height - MARGIN.top;

  private newPage(): void {
    if (this.current.length) this.pages.push(this.current);
    this.current = [];
    this.y = PAGE.height - MARGIN.top;
  }

  private ensureSpace(needed: number): void {
    if (this.y - needed < MARGIN.bottom) this.newPage();
  }

  write(run: TextRun): void {
    const indent = run.indent ?? 0;
    const leading = run.size * 1.42;
    const lines = wrapText(escapePdfText(run.text), run.font, run.size, CONTENT_WIDTH - indent);

    this.ensureSpace((run.spaceBefore ?? 0) + leading);
    this.y -= run.spaceBefore ?? 0;

    for (const line of lines) {
      this.ensureSpace(leading);
      this.y -= leading;
      const [r, g, b] = run.color;
      this.current.push(
        `BT /${run.font} ${run.size} Tf ${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} rg ` +
          `1 0 0 1 ${(MARGIN.left + indent).toFixed(2)} ${this.y.toFixed(2)} Tm (${line}) Tj ET`,
      );
    }
  }

  rule(color: [number, number, number] = [0.85, 0.87, 0.9]): void {
    this.ensureSpace(12);
    this.y -= 8;
    const [r, g, b] = color;
    this.current.push(
      `${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} RG 0.6 w ` +
        `${MARGIN.left} ${this.y.toFixed(2)} m ${(PAGE.width - MARGIN.right).toFixed(2)} ${this.y.toFixed(2)} l S`,
    );
    this.y -= 4;
  }

  /** Filled rectangle, used for the severity chips and the score block. */
  box(width: number, height: number, color: [number, number, number]): void {
    this.ensureSpace(height + 6);
    this.y -= height;
    const [r, g, b] = color;
    this.current.push(
      `${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} rg ` +
        `${MARGIN.left} ${this.y.toFixed(2)} ${width.toFixed(2)} ${height.toFixed(2)} re f`,
    );
  }

  gap(points: number): void {
    this.y -= points;
  }

  finish(): string[][] {
    if (this.current.length) this.pages.push(this.current);
    this.current = [];
    return this.pages;
  }
}

/** Assemble the PDF object graph with a correct xref table. */
function serialize(pages: string[][]): Buffer {
  const objects: string[] = [];
  const pageCount = Math.max(1, pages.length);

  // 1 catalog, 2 pages tree, 3-5 fonts, then per page: page object + content stream.
  const firstPageObject = 6;
  const pageIds = Array.from({ length: pageCount }, (_, i) => firstPageObject + i * 2);

  objects.push('<< /Type /Catalog /Pages 2 0 R >>');
  objects.push(
    `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageCount} >>`,
  );
  objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  objects.push(
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>',
  );
  objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>');

  for (let i = 0; i < pageCount; i += 1) {
    const contentId = pageIds[i]! + 1;
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE.width} ${PAGE.height}] ` +
        `/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents ${contentId} 0 R >>`,
    );
    const content = (pages[i] ?? []).join('\n');
    objects.push(
      `<< /Length ${Buffer.byteLength(content, 'latin1')} >>\nstream\n${content}\nendstream`,
    );
  }

  let pdf = '%PDF-1.7\n%\xE2\xE3\xCF\xD3\n';
  const offsets: number[] = [];

  for (let i = 0; i < objects.length; i += 1) {
    offsets.push(Buffer.byteLength(pdf, 'latin1'));
    pdf += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }

  const xrefOffset = Buffer.byteLength(pdf, 'latin1');
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) {
    pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;

  return Buffer.from(pdf, 'latin1');
}

export interface PdfOptions {
  summary?: ExecutiveSummary;
  priorities?: PrioritizedFinding[];
  maxFindings?: number;
}

export function toPdf(result: ScanResult, options: PdfOptions = {}): Buffer {
  const doc = new PdfBuilder();
  const active = result.findings.filter((f) => !f.suppressed);
  const maxFindings = options.maxFindings ?? 40;
  const priorityById = new Map((options.priorities ?? []).map((p) => [p.findingId, p]));

  /* ---------------- Cover ---------------- */
  doc.write({ text: 'SENTINEL AI  ·  SECURITY REPORT', font: 'F2', size: 9, color: GREY });
  doc.write({ text: result.repository.name, font: 'F2', size: 26, color: BLACK, spaceBefore: 10 });
  doc.write({
    text: `${result.repository.ref ?? 'default branch'}${result.repository.commit ? ` · ${result.repository.commit.slice(0, 8)}` : ''} · ${result.repository.fileCount.toLocaleString()} files · ${new Date(result.startedAt).toUTCString()}`,
    font: 'F1',
    size: 9.5,
    color: GREY,
    spaceBefore: 4,
  });
  doc.rule();

  if (result.status === 'failed') {
    doc.write({
      text: 'Scan did not complete',
      font: 'F2',
      size: 15,
      color: SEVERITY_RGB.critical,
      spaceBefore: 14,
    });
    doc.write({
      text: result.error ?? 'Unknown error.',
      font: 'F1',
      size: 11,
      color: BLACK,
      spaceBefore: 6,
    });
    return serialize(doc.finish());
  }

  /* ---------------- Score ---------------- */
  doc.gap(8);
  doc.write({
    text: `Overall score: ${result.scores.overall}/100   ·   Grade ${result.scores.grade}   ·   Risk level: ${result.scores.riskLevel}`,
    font: 'F2',
    size: 15,
    color: BLACK,
    spaceBefore: 10,
  });

  const counts = result.scores.counts;
  doc.write({
    text: `Critical ${counts.critical}   High ${counts.high}   Medium ${counts.medium}   Low ${counts.low}   Info ${counts.info}`,
    font: 'F1',
    size: 11,
    color: GREY,
    spaceBefore: 6,
  });

  if (options.summary) {
    doc.write({
      text: options.summary.headline,
      font: 'F1',
      size: 11.5,
      color: BLACK,
      spaceBefore: 16,
    });
    doc.write({
      text: options.summary.posture,
      font: 'F1',
      size: 10.5,
      color: GREY,
      spaceBefore: 8,
    });
  }

  /* ---------------- Category scores ---------------- */
  doc.write({ text: 'Repository health', font: 'F2', size: 14, color: BLACK, spaceBefore: 22 });
  doc.rule();
  for (const category of result.scores.categories) {
    doc.write({
      text: `${category.category.padEnd(16)}  ${category.analyzed ? `${String(category.score).padStart(3)}/100  (${category.grade})` : '  not analyzed'}   ${category.rationale}`,
      font: 'F1',
      size: 10,
      color: category.analyzed && category.score < 70 ? SEVERITY_RGB.high : BLACK,
      spaceBefore: 3,
    });
  }

  /* ---------------- Recommended actions ---------------- */
  if (options.summary?.recommendedActions.length) {
    doc.write({ text: 'Recommended actions', font: 'F2', size: 14, color: BLACK, spaceBefore: 22 });
    doc.rule();
    options.summary.recommendedActions.forEach((action, index) => {
      doc.write({
        text: `${index + 1}.  ${action}`,
        font: 'F1',
        size: 10.5,
        color: BLACK,
        spaceBefore: 5,
      });
    });
  }

  /* ---------------- Findings ---------------- */
  const ordered = [...active].sort(
    (a, b) =>
      (priorityById.get(b.id)?.priorityScore ?? b.riskScore) -
      (priorityById.get(a.id)?.priorityScore ?? a.riskScore),
  );

  doc.write({
    text: `Findings${ordered.length > maxFindings ? ` (top ${maxFindings} of ${ordered.length})` : ` (${ordered.length})`}`,
    font: 'F2',
    size: 14,
    color: BLACK,
    spaceBefore: 24,
  });
  doc.rule();

  if (!ordered.length) {
    doc.write({
      text: 'No open findings in the analyzed scope.',
      font: 'F1',
      size: 11,
      color: BLACK,
      spaceBefore: 8,
    });
  }

  for (const finding of ordered.slice(0, maxFindings)) {
    const priority = priorityById.get(finding.id);

    doc.write({
      text: `${finding.severity.toUpperCase()}   ${finding.title}`,
      font: 'F2',
      size: 11.5,
      color: SEVERITY_RGB[finding.severity],
      spaceBefore: 14,
    });

    doc.write({
      text: `${finding.location ? `${finding.location.path}:${finding.location.startLine}` : finding.component ? `${finding.component.name}@${finding.component.version}` : 'repository'}   ·   ${finding.scanner}   ·   confidence ${finding.confidence}${priority ? `   ·   priority #${priority.rank}` : ''}`,
      font: 'F3',
      size: 8.5,
      color: GREY,
      spaceBefore: 3,
    });

    if (finding.explanation) {
      doc.write({
        text: finding.explanation.plainEnglish,
        font: 'F1',
        size: 10,
        color: BLACK,
        spaceBefore: 6,
      });
      doc.write({
        text: `Business impact: ${finding.explanation.businessImpact}`,
        font: 'F1',
        size: 9.5,
        color: GREY,
        spaceBefore: 5,
        indent: 12,
      });
      const primaryFix = finding.explanation.suggestedFixes[0];
      if (primaryFix) {
        doc.write({
          text: `Fix: ${primaryFix.title} — ${primaryFix.description}`,
          font: 'F1',
          size: 9.5,
          color: BLACK,
          spaceBefore: 5,
          indent: 12,
        });
      }
    } else if (finding.description) {
      doc.write({ text: finding.description, font: 'F1', size: 10, color: BLACK, spaceBefore: 6 });
      if (finding.remediationHint) {
        doc.write({
          text: `Fix: ${finding.remediationHint}`,
          font: 'F1',
          size: 9.5,
          color: BLACK,
          spaceBefore: 5,
          indent: 12,
        });
      }
    }

    const taxonomy = [
      ...(finding.taxonomy?.cwe ?? []),
      ...(finding.taxonomy?.owaspTop10 ?? []),
      ...(finding.taxonomy?.owaspLlmTop10 ?? []),
      ...(finding.taxonomy?.cve ?? []),
    ];
    if (taxonomy.length) {
      doc.write({
        text: taxonomy.join('  ·  '),
        font: 'F3',
        size: 8,
        color: GREY,
        spaceBefore: 4,
        indent: 12,
      });
    }
  }

  /* ---------------- Coverage ---------------- */
  doc.write({ text: 'Scanner coverage', font: 'F2', size: 14, color: BLACK, spaceBefore: 26 });
  doc.rule();
  for (const run of result.scannerRuns) {
    doc.write({
      text: `${run.scanner.padEnd(24)} ${run.status.padEnd(8)} ${String(run.findingCount).padStart(4)} findings   ${run.reason ?? ''}`,
      font: 'F3',
      size: 8.5,
      color: run.status === 'failed' ? SEVERITY_RGB.critical : GREY,
      spaceBefore: 2,
    });
  }

  /* ---------------- Caveats ---------------- */
  if (options.summary?.caveats.length) {
    doc.write({
      text: 'Caveats and coverage limits',
      font: 'F2',
      size: 14,
      color: BLACK,
      spaceBefore: 22,
    });
    doc.rule();
    for (const caveat of options.summary.caveats) {
      doc.write({ text: `-  ${caveat}`, font: 'F1', size: 9.5, color: GREY, spaceBefore: 4 });
    }
  }

  doc.write({
    text: `Generated by Sentinel AI 0.1.0 · scan ${result.id} · ${(result.durationMs / 1000).toFixed(1)}s`,
    font: 'F1',
    size: 8,
    color: GREY,
    spaceBefore: 24,
  });

  return serialize(doc.finish());
}
