import type { ScoreHistoryPoint } from '@sentinel/core';
import { scoreColor } from '@/lib/ui';

/**
 * Score sparkline.
 *
 * Hand-drawn SVG rather than a charting library: this is one polyline, and
 * shipping a charting runtime to render it would be the single largest
 * dependency in the application.
 */
export function TrendSparkline({
  points,
  width = 120,
  height = 40,
  showArea = true,
}: {
  points: readonly ScoreHistoryPoint[];
  width?: number;
  height?: number;
  showArea?: boolean;
}) {
  if (points.length < 2) return null;

  const scores = points.map((point) => point.overall);
  const min = Math.min(...scores);
  const max = Math.max(...scores);
  // A flat line would otherwise collapse to zero height and disappear.
  const range = Math.max(max - min, 10);
  const padding = 3;

  const coordinates = scores.map((score, index) => {
    const x = padding + (index / (scores.length - 1)) * (width - padding * 2);
    const y = height - padding - ((score - min) / range) * (height - padding * 2);
    return { x, y };
  });

  const line = coordinates
    .map((c, i) => `${i === 0 ? 'M' : 'L'} ${c.x.toFixed(1)} ${c.y.toFixed(1)}`)
    .join(' ');
  const area = `${line} L ${coordinates[coordinates.length - 1]!.x.toFixed(1)} ${height} L ${coordinates[0]!.x.toFixed(1)} ${height} Z`;

  const latest = scores[scores.length - 1]!;
  const color = scoreColor(latest);
  const gradientId = `spark-${latest}-${points.length}-${Math.round(min)}`;

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="shrink-0 overflow-visible"
      role="img"
      aria-label={`Score trend over ${points.length} scans, currently ${latest} out of 100`}
    >
      {showArea && (
        <>
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity="0.22" />
              <stop offset="100%" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={area} fill={`url(#${gradientId})`} />
        </>
      )}
      <path
        d={line}
        fill="none"
        stroke={color}
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle
        cx={coordinates[coordinates.length - 1]!.x}
        cy={coordinates[coordinates.length - 1]!.y}
        r="2.5"
        fill={color}
      />
    </svg>
  );
}

/**
 * Larger trend chart with axis labels, for the project detail page.
 */
export function TrendChart({
  points,
  height = 200,
}: {
  points: readonly ScoreHistoryPoint[];
  height?: number;
}) {
  if (points.length < 2) {
    return (
      <div
        className="flex items-center justify-center rounded-lg border border-dashed border-[var(--color-border)] text-[13px] text-[var(--color-fg-subtle)]"
        style={{ height }}
      >
        At least two scans are needed to show a trend.
      </div>
    );
  }

  const width = 800;
  const padding = { top: 16, right: 16, bottom: 28, left: 34 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;

  const coordinates = points.map((point, index) => ({
    x: padding.left + (index / (points.length - 1)) * plotWidth,
    // Always plot against the full 0-100 range: an auto-scaled y-axis makes a
    // two-point wobble look like a collapse.
    y: padding.top + (1 - point.overall / 100) * plotHeight,
    point,
  }));

  const line = coordinates
    .map((c, i) => `${i === 0 ? 'M' : 'L'} ${c.x.toFixed(1)} ${c.y.toFixed(1)}`)
    .join(' ');
  const area = `${line} L ${coordinates[coordinates.length - 1]!.x.toFixed(1)} ${padding.top + plotHeight} L ${coordinates[0]!.x.toFixed(1)} ${padding.top + plotHeight} Z`;

  const latest = points[points.length - 1]!.overall;
  const color = scoreColor(latest);

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="w-full"
      style={{ height }}
      role="img"
      aria-label={`Security score across ${points.length} scans, currently ${latest} out of 100`}
      preserveAspectRatio="none"
    >
      <defs>
        <linearGradient id="trend-area" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.2" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>

      {[0, 25, 50, 75, 100].map((value) => {
        const y = padding.top + (1 - value / 100) * plotHeight;
        return (
          <g key={value}>
            <line
              x1={padding.left}
              y1={y}
              x2={width - padding.right}
              y2={y}
              stroke="var(--color-border)"
              strokeWidth="1"
              strokeDasharray={value === 0 || value === 100 ? undefined : '3 4'}
            />
            <text
              x={padding.left - 8}
              y={y + 3.5}
              textAnchor="end"
              fill="var(--color-fg-subtle)"
              fontSize="10"
            >
              {value}
            </text>
          </g>
        );
      })}

      <path d={area} fill="url(#trend-area)" />
      <path
        d={line}
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {coordinates.map((c) => (
        <circle key={c.point.scanId} cx={c.x} cy={c.y} r="3" fill={color}>
          <title>
            {new Date(c.point.timestamp).toLocaleDateString()} — score {c.point.overall}
          </title>
        </circle>
      ))}

      <text x={padding.left} y={height - 8} fill="var(--color-fg-subtle)" fontSize="10">
        {new Date(points[0]!.timestamp).toLocaleDateString()}
      </text>
      <text
        x={width - padding.right}
        y={height - 8}
        textAnchor="end"
        fill="var(--color-fg-subtle)"
        fontSize="10"
      >
        {new Date(points[points.length - 1]!.timestamp).toLocaleDateString()}
      </text>
    </svg>
  );
}
