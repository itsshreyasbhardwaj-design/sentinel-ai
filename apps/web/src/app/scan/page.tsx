'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertCircle, FolderOpen, Github, Loader2, Upload } from 'lucide-react';
import type { ScanProgress } from '@sentinel/core/constants';
import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/primitives';
import { cn } from '@/lib/ui';

type Mode = 'github' | 'local' | 'upload';

const KINDS = [
  { id: 'sast', label: 'Code (SAST)' },
  { id: 'dependencies', label: 'Dependencies' },
  { id: 'secrets', label: 'Secrets' },
  { id: 'ai-security', label: 'AI security' },
  { id: 'iac', label: 'Infrastructure' },
  { id: 'container', label: 'Containers' },
  { id: 'config', label: 'Configuration' },
  { id: 'license', label: 'Licenses' },
  { id: 'sbom', label: 'SBOM' },
] as const;

export default function ScanPage() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>('github');
  const [repo, setRepo] = useState('');
  const [ref, setRef] = useState('');
  const [localPath, setLocalPath] = useState('');
  const [file, setFile] = useState<File | undefined>();
  const [selectedKinds, setSelectedKinds] = useState<string[]>(KINDS.map((k) => k.id));
  const [allowNetwork, setAllowNetwork] = useState(false);

  const [submitting, setSubmitting] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | undefined>();
  const [error, setError] = useState<string | undefined>();
  const sourceRef = useRef<EventSource | undefined>(undefined);

  // An abandoned EventSource keeps a connection and a server-side subscriber
  // alive, so it must be closed when the component unmounts.
  useEffect(() => () => sourceRef.current?.close(), []);

  const follow = useCallback(
    (jobId: string) => {
      const source = new EventSource(`/api/scans/${jobId}/stream`);
      sourceRef.current = source;

      source.addEventListener('progress', (event) => {
        setProgress(JSON.parse((event as MessageEvent).data) as ScanProgress);
      });

      source.addEventListener('done', (event) => {
        const payload = JSON.parse((event as MessageEvent).data) as {
          status: string;
          result?: { scanId?: string };
          error?: string;
        };
        source.close();

        if (payload.status === 'completed' && payload.result?.scanId) {
          router.push(`/scans/${payload.result.scanId}`);
        } else {
          setError(payload.error ?? 'The scan did not complete.');
          setSubmitting(false);
        }
      });

      source.onerror = () => {
        source.close();
        setError('Lost connection to the scan. It may still be running — check the overview.');
        setSubmitting(false);
      };
    },
    [router],
  );

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(undefined);
    setSubmitting(true);
    setProgress(undefined);

    try {
      let response: Response;

      if (mode === 'upload') {
        if (!file) throw new Error('Choose a .zip archive to upload.');
        const form = new FormData();
        form.append('file', file);
        response = await fetch('/api/upload', { method: 'POST', body: form });
      } else {
        const target =
          mode === 'github'
            ? (() => {
                const [owner, name] = repo
                  .trim()
                  .replace(/^https:\/\/github\.com\//, '')
                  .split('/');
                if (!owner || !name) throw new Error('Enter a repository as owner/name.');
                return {
                  type: 'github' as const,
                  owner,
                  repo: name.replace(/\.git$/, ''),
                  ...(ref.trim() ? { ref: ref.trim() } : {}),
                };
              })()
            : { type: 'local' as const, path: localPath.trim() };

        if (mode === 'local' && !localPath.trim()) {
          throw new Error('Enter an absolute path to a directory.');
        }

        response = await fetch('/api/scans', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            target,
            options: {
              kinds: selectedKinds.length === KINDS.length ? undefined : selectedKinds,
              allowNetwork,
            },
          }),
        });
      }

      const payload = (await response.json()) as {
        jobId?: string;
        error?: { message?: string };
      };

      if (!response.ok || !payload.jobId) {
        throw new Error(payload.error?.message ?? `Request failed with status ${response.status}`);
      }

      follow(payload.jobId);
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : String(submitError));
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">New scan</h1>
        <p className="mt-1 text-sm text-[var(--color-fg-subtle)]">
          Analyze a repository for vulnerabilities, exposed secrets, supply-chain risk and
          AI-specific weaknesses.
        </p>
      </div>

      <AnimatePresence mode="wait">
        {submitting ? (
          <motion.div
            key="progress"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
          >
            <Card>
              <CardContent className="pt-5">
                <div className="flex items-center gap-3">
                  <Loader2
                    className="h-4 w-4 animate-spin text-[var(--color-accent)]"
                    aria-hidden="true"
                  />
                  <span className="text-sm font-medium">
                    {progress?.message ?? progress?.phase ?? 'Starting scan…'}
                  </span>
                  <span className="ml-auto text-sm tabular-nums text-[var(--color-fg-subtle)]">
                    {progress?.percent ?? 0}%
                  </span>
                </div>

                <div
                  className="mt-4 h-1.5 overflow-hidden rounded-full bg-[var(--color-surface-raised)]"
                  role="progressbar"
                  aria-valuenow={progress?.percent ?? 0}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-label="Scan progress"
                >
                  <motion.div
                    className="h-full rounded-full bg-[var(--color-accent)]"
                    animate={{ width: `${progress?.percent ?? 2}%` }}
                    transition={{ duration: 0.4, ease: 'easeOut' }}
                  />
                </div>

                {progress && progress.findingsSoFar > 0 && (
                  <p className="mt-3 text-[13px] text-[var(--color-fg-subtle)]">
                    {progress.findingsSoFar} findings so far · {progress.completedScanners.length}/
                    {progress.totalScanners} scanners complete
                  </p>
                )}
              </CardContent>
            </Card>
          </motion.div>
        ) : (
          <motion.form
            key="form"
            onSubmit={submit}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="space-y-5"
          >
            <Card>
              <CardHeader>
                <CardTitle>Source</CardTitle>
                <CardDescription>Where should Sentinel read the code from?</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div
                  className="grid grid-cols-3 gap-2"
                  role="radiogroup"
                  aria-label="Scan source type"
                >
                  {(
                    [
                      { id: 'github', label: 'GitHub', icon: Github },
                      { id: 'local', label: 'Local path', icon: FolderOpen },
                      { id: 'upload', label: 'Upload ZIP', icon: Upload },
                    ] as const
                  ).map(({ id, label, icon: Icon }) => (
                    <button
                      key={id}
                      type="button"
                      role="radio"
                      aria-checked={mode === id}
                      onClick={() => setMode(id)}
                      className={cn(
                        'flex flex-col items-center gap-2 rounded-lg border px-3 py-4 text-[13px] font-medium transition-all',
                        mode === id
                          ? 'border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-fg)]'
                          : 'border-[var(--color-border)] text-[var(--color-fg-muted)] hover:border-[var(--color-border-strong)] hover:bg-[var(--color-surface-raised)]',
                      )}
                    >
                      <Icon className="h-4 w-4" aria-hidden="true" />
                      {label}
                    </button>
                  ))}
                </div>

                {mode === 'github' && (
                  <div className="space-y-3">
                    <Field label="Repository" hint="owner/name">
                      <input
                        value={repo}
                        onChange={(e) => setRepo(e.target.value)}
                        placeholder="vercel/next.js"
                        autoComplete="off"
                        spellCheck={false}
                        className={inputClass}
                      />
                    </Field>
                    <Field label="Branch or tag" hint="optional">
                      <input
                        value={ref}
                        onChange={(e) => setRef(e.target.value)}
                        placeholder="main"
                        autoComplete="off"
                        spellCheck={false}
                        className={inputClass}
                      />
                    </Field>
                  </div>
                )}

                {mode === 'local' && (
                  <Field label="Absolute path" hint="a directory on this machine">
                    <input
                      value={localPath}
                      onChange={(e) => setLocalPath(e.target.value)}
                      placeholder="/Users/you/projects/my-app"
                      autoComplete="off"
                      spellCheck={false}
                      className={inputClass}
                    />
                  </Field>
                )}

                {mode === 'upload' && (
                  <Field label="Archive" hint=".zip, up to 100MB">
                    <input
                      type="file"
                      accept=".zip,application/zip"
                      onChange={(e) => setFile(e.target.files?.[0])}
                      className={cn(
                        inputClass,
                        'file:mr-3 file:rounded-md file:border-0 file:bg-[var(--color-surface-raised)] file:px-3 file:py-1 file:text-[13px] file:text-[var(--color-fg)] py-2',
                      )}
                    />
                  </Field>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Analysis</CardTitle>
                <CardDescription>
                  All domains run by default. Narrowing the scope makes a scan faster but leaves
                  gaps the report will call out.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <fieldset>
                  <legend className="sr-only">Analysis domains</legend>
                  <div className="flex flex-wrap gap-2">
                    {KINDS.map((kind) => {
                      const active = selectedKinds.includes(kind.id);
                      return (
                        <button
                          key={kind.id}
                          type="button"
                          aria-pressed={active}
                          onClick={() =>
                            setSelectedKinds((current) =>
                              active
                                ? current.filter((id) => id !== kind.id)
                                : [...current, kind.id],
                            )
                          }
                          className={cn(
                            'rounded-md border px-2.5 py-1 text-[12.5px] font-medium transition-all',
                            active
                              ? 'border-[var(--color-accent)]/40 bg-[var(--color-accent)]/12 text-[var(--color-accent)]'
                              : 'border-[var(--color-border)] text-[var(--color-fg-subtle)] hover:border-[var(--color-border-strong)]',
                          )}
                        >
                          {kind.label}
                        </button>
                      );
                    })}
                  </div>
                </fieldset>

                <label className="flex cursor-pointer items-start gap-2.5">
                  <input
                    type="checkbox"
                    checked={allowNetwork}
                    onChange={(e) => setAllowNetwork(e.target.checked)}
                    className="mt-0.5 h-4 w-4 rounded border-[var(--color-border-strong)] bg-[var(--color-surface-raised)] accent-[var(--color-accent)]"
                  />
                  <span className="text-[13px]">
                    <span className="font-medium">Query OSV.dev for live advisories</span>
                    <span className="block text-[var(--color-fg-subtle)]">
                      Sends package names and versions to osv.dev. Off by default so a scan never
                      leaves your network without you choosing it.
                    </span>
                  </span>
                </label>
              </CardContent>
            </Card>

            {error && (
              <div
                role="alert"
                className="flex items-start gap-2.5 rounded-lg border border-[var(--color-critical)]/30 bg-[var(--color-critical)]/8 px-4 py-3 text-[13px] text-[var(--color-critical)]"
              >
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                {error}
              </div>
            )}

            <Button type="submit" variant="primary" size="lg" className="w-full">
              Start scan
            </Button>
          </motion.form>
        )}
      </AnimatePresence>
    </div>
  );
}

const inputClass =
  'w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-canvas)] px-3 py-2 text-sm ' +
  'text-[var(--color-fg)] placeholder:text-[var(--color-fg-subtle)] transition-colors ' +
  'focus:border-[var(--color-accent)] focus:outline-none';

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1.5 flex items-baseline gap-2">
        <span className="text-[13px] font-medium">{label}</span>
        {hint && <span className="text-[12px] text-[var(--color-fg-subtle)]">{hint}</span>}
      </span>
      {children}
    </label>
  );
}
