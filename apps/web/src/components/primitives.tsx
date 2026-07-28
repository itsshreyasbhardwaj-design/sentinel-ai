import type { ComponentProps, ReactNode } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import type { Grade, Severity } from '@sentinel/core';
import { GRADE_STYLE, SEVERITY_STYLE, cn, scoreColor } from '@/lib/ui';

/**
 * Base UI primitives.
 *
 * Hand-built rather than pulled from a component library: the surface Sentinel
 * needs is small, and owning it keeps the visual language coherent and the
 * dependency tree of a *security* tool short.
 */

/* ------------------------------------------------------------------ */
/* Button                                                              */
/* ------------------------------------------------------------------ */

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-all ' +
    'disabled:pointer-events-none disabled:opacity-50 focus-visible:outline-2 ' +
    'focus-visible:outline-offset-2 focus-visible:outline-[var(--color-accent)] whitespace-nowrap',
  {
    variants: {
      variant: {
        primary:
          'bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] shadow-sm ' +
          'active:scale-[0.98]',
        secondary:
          'bg-[var(--color-surface-raised)] text-[var(--color-fg)] border border-[var(--color-border)] ' +
          'hover:bg-[var(--color-surface-hover)] hover:border-[var(--color-border-strong)]',
        ghost:
          'text-[var(--color-fg-muted)] hover:text-[var(--color-fg)] hover:bg-[var(--color-surface-raised)]',
        danger:
          'bg-[var(--color-critical)]/15 text-[var(--color-critical)] border border-[var(--color-critical)]/30 hover:bg-[var(--color-critical)]/25',
      },
      size: {
        sm: 'h-8 px-3 text-[13px]',
        md: 'h-10 px-4 text-sm',
        lg: 'h-12 px-6 text-[15px]',
        icon: 'h-9 w-9',
      },
    },
    defaultVariants: { variant: 'secondary', size: 'md' },
  },
);

export interface ButtonProps
  extends ComponentProps<'button'>, VariantProps<typeof buttonVariants> {}

export function Button({ className, variant, size, ...props }: ButtonProps) {
  return <button className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}

/* ------------------------------------------------------------------ */
/* Card                                                                */
/* ------------------------------------------------------------------ */

export function Card({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      className={cn(
        'rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]',
        className,
      )}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: ComponentProps<'div'>) {
  return <div className={cn('px-5 pt-5 pb-3', className)} {...props} />;
}

export function CardTitle({ className, ...props }: ComponentProps<'h3'>) {
  return (
    <h3
      className={cn('text-[15px] font-semibold tracking-tight text-[var(--color-fg)]', className)}
      {...props}
    />
  );
}

export function CardDescription({ className, ...props }: ComponentProps<'p'>) {
  return (
    <p className={cn('mt-1 text-[13px] text-[var(--color-fg-subtle)]', className)} {...props} />
  );
}

export function CardContent({ className, ...props }: ComponentProps<'div'>) {
  return <div className={cn('px-5 pb-5', className)} {...props} />;
}

/* ------------------------------------------------------------------ */
/* Badges                                                              */
/* ------------------------------------------------------------------ */

/**
 * Severity is communicated by colour *and* text. Colour alone fails for
 * colour-blind users, in grayscale print, and in high-contrast modes.
 */
export function SeverityBadge({
  severity,
  count,
  className,
}: {
  severity: Severity;
  count?: number;
  className?: string;
}) {
  const style = SEVERITY_STYLE[severity];
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide',
        style.bg,
        style.border,
        style.text,
        className,
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', style.dot)} aria-hidden="true" />
      {severity}
      {count !== undefined && <span className="tabular-nums opacity-80">{count}</span>}
    </span>
  );
}

export function Badge({
  children,
  className,
  tone = 'neutral',
}: {
  children: ReactNode;
  className?: string;
  tone?: 'neutral' | 'accent' | 'success' | 'warning';
}) {
  const tones = {
    neutral:
      'bg-[var(--color-surface-raised)] text-[var(--color-fg-muted)] border-[var(--color-border)]',
    accent:
      'bg-[var(--color-accent)]/12 text-[var(--color-accent)] border-[var(--color-accent)]/25',
    success:
      'bg-[var(--color-success)]/12 text-[var(--color-success)] border-[var(--color-success)]/25',
    warning: 'bg-[var(--color-high)]/12 text-[var(--color-high)] border-[var(--color-high)]/25',
  };

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium',
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Score display                                                       */
/* ------------------------------------------------------------------ */

/** Circular score gauge. Pure SVG — no chart library for one shape. */
export function ScoreRing({
  score,
  grade,
  size = 120,
  label,
}: {
  score: number;
  grade: Grade;
  size?: number;
  label?: string;
}) {
  const stroke = size / 12;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.max(0, Math.min(100, score)) / 100) * circumference;
  const color = scoreColor(score);

  return (
    <div
      className="relative inline-flex items-center justify-center"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Security score ${score} out of 100, grade ${grade}${label ? `, ${label}` : ''}`}
    >
      <svg width={size} height={size} className="-rotate-90" aria-hidden="true">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--color-surface-raised)"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-[stroke-dashoffset] duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className="font-semibold tabular-nums leading-none"
          style={{ fontSize: size / 3.4, color }}
        >
          {score}
        </span>
        <span
          className={cn('mt-1 font-semibold', GRADE_STYLE[grade].text)}
          style={{ fontSize: size / 9 }}
        >
          {grade}
        </span>
      </div>
    </div>
  );
}

/** Horizontal score bar for category breakdowns. */
export function ScoreBar({
  score,
  analyzed = true,
  className,
}: {
  score: number;
  analyzed?: boolean;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'h-1.5 w-full overflow-hidden rounded-full bg-[var(--color-surface-raised)]',
        className,
      )}
      role="img"
      aria-label={analyzed ? `Score ${score} out of 100` : 'Not analyzed'}
    >
      {analyzed && (
        <div
          className="h-full rounded-full transition-[width] duration-700 ease-out"
          style={{ width: `${Math.max(2, score)}%`, background: scoreColor(score) }}
        />
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* States                                                              */
/* ------------------------------------------------------------------ */

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
      {icon && <div className="mb-4 text-[var(--color-fg-subtle)]">{icon}</div>}
      <h3 className="text-[15px] font-semibold text-[var(--color-fg)]">{title}</h3>
      {description && (
        <p className="mt-1.5 max-w-sm text-[13px] text-[var(--color-fg-subtle)]">{description}</p>
      )}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-shimmer rounded-md', className)} aria-hidden="true" />;
}

/** Inline code / file path. */
export function Code({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <code
      className={cn(
        'rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 font-mono text-[12px] text-[var(--color-fg-muted)]',
        className,
      )}
    >
      {children}
    </code>
  );
}

export function Stat({ value, label, tone }: { value: ReactNode; label: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3">
      <div
        className="text-2xl font-semibold tabular-nums leading-none"
        style={tone ? { color: tone } : undefined}
      >
        {value}
      </div>
      <div className="mt-1.5 text-[11px] font-medium uppercase tracking-wider text-[var(--color-fg-subtle)]">
        {label}
      </div>
    </div>
  );
}
