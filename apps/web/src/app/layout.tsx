import type { Metadata, Viewport } from 'next';
import Link from 'next/link';
import { ShieldCheck } from 'lucide-react';
import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'Sentinel AI — AI-native application security',
    template: '%s · Sentinel AI',
  },
  description:
    'Scan repositories for vulnerabilities, exposed secrets, supply-chain risk and AI-specific weaknesses, with plain-English explanations and concrete fixes.',
  applicationName: 'Sentinel AI',
  // A security dashboard renders findings from private repositories; keep it
  // out of search indexes even if a deployment is briefly public.
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: '#08090c',
  width: 'device-width',
  initialScale: 1,
};

const NAV = [
  { href: '/', label: 'Overview' },
  { href: '/scan', label: 'New scan' },
  { href: '/scanners', label: 'Scanners' },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen antialiased">
        {/* Keyboard users must be able to bypass the nav on every page. */}
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-[var(--color-accent)] focus:px-4 focus:py-2 focus:text-sm focus:text-white"
        >
          Skip to content
        </a>

        <header className="sticky top-0 z-40 border-b border-[var(--color-border)] bg-[var(--color-canvas)]/85 backdrop-blur-xl">
          <div className="mx-auto flex h-14 max-w-7xl items-center gap-6 px-5">
            <Link
              href="/"
              className="flex items-center gap-2.5 text-[15px] font-semibold tracking-tight"
            >
              <ShieldCheck
                className="h-[18px] w-[18px] text-[var(--color-accent)]"
                aria-hidden="true"
              />
              Sentinel<span className="text-[var(--color-fg-subtle)]">AI</span>
            </Link>

            <nav aria-label="Main" className="flex items-center gap-1">
              {NAV.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className="rounded-md px-3 py-1.5 text-[13px] font-medium text-[var(--color-fg-muted)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-fg)]"
                >
                  {item.label}
                </Link>
              ))}
            </nav>

            <div className="ml-auto flex items-center gap-3">
              <a
                href="https://github.com/itsshreyasbhardwaj-design/sentinel-ai"
                target="_blank"
                rel="noreferrer noopener"
                className="text-[13px] text-[var(--color-fg-subtle)] transition-colors hover:text-[var(--color-fg)]"
              >
                GitHub
              </a>
            </div>
          </div>
        </header>

        <main id="main" className="mx-auto max-w-7xl px-5 py-8">
          {children}
        </main>

        <footer className="mx-auto max-w-7xl px-5 pb-10 pt-6 text-[12px] text-[var(--color-fg-subtle)]">
          <div className="border-t border-[var(--color-border)] pt-6">
            Sentinel AI 0.1.0 — open source under the MIT license. Static analysis cannot prove
            reachability; confirm each finding against how the code is actually invoked.
          </div>
        </footer>
      </body>
    </html>
  );
}
