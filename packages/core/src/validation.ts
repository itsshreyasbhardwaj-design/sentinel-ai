import { z } from 'zod';
import { errors } from './errors.js';
import { SCAN_KINDS, SEVERITIES, type ScanTarget } from './types.js';

/* ------------------------------------------------------------------ */
/* Targets                                                             */
/* ------------------------------------------------------------------ */

/** GitHub's own constraints: 1-39 chars, alphanumeric or hyphen, no leading/trailing hyphen. */
const githubOwner = z
  .string()
  .min(1)
  .max(39)
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/, 'Invalid GitHub owner');

const githubRepo = z
  .string()
  .min(1)
  .max(100)
  .regex(/^[A-Za-z0-9._-]+$/, 'Invalid GitHub repository name');

/**
 * Git refs are interpolated into `git` invocations, so anything that could be
 * read as an option or shell metacharacter is rejected outright.
 */
const gitRef = z
  .string()
  .min(1)
  .max(255)
  .regex(/^[A-Za-z0-9._\-/]+$/, 'Invalid git ref')
  .refine((v) => !v.startsWith('-'), 'Ref must not start with "-"')
  .refine((v) => !v.includes('..'), 'Ref must not contain ".."');

export const scanTargetSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('local'),
    path: z.string().min(1).max(4096),
    ref: gitRef.optional(),
  }),
  z.object({
    type: z.literal('github'),
    owner: githubOwner,
    repo: githubRepo,
    ref: gitRef.optional(),
    token: z.string().min(1).max(512).optional(),
  }),
  z.object({
    type: z.literal('archive'),
    archivePath: z.string().min(1).max(4096),
    originalName: z.string().max(255).optional(),
  }),
]);

export const scanOptionsSchema = z.object({
  kinds: z.array(z.enum(SCAN_KINDS)).min(1).optional(),
  exclude: z.array(z.string().max(512)).max(200).optional(),
  include: z.array(z.string().max(512)).max(200).optional(),
  maxFiles: z.number().int().positive().max(200_000).optional(),
  maxFileSizeBytes: z
    .number()
    .int()
    .positive()
    .max(64 * 1024 * 1024)
    .optional(),
  explain: z.boolean().optional(),
  explainMinSeverity: z.enum(SEVERITIES).optional(),
  allowNetwork: z.boolean().optional(),
  preferExternalScanners: z.boolean().optional(),
  incremental: z.boolean().optional(),
  concurrency: z.number().int().positive().max(64).optional(),
  failOn: z.enum(SEVERITIES).optional(),
  timeoutMs: z
    .number()
    .int()
    .positive()
    .max(60 * 60_000)
    .optional(),
});

export const createScanSchema = z.object({
  projectId: z.string().min(1).max(64).optional(),
  name: z.string().min(1).max(120).optional(),
  target: scanTargetSchema,
  options: scanOptionsSchema.optional(),
});

export type CreateScanInput = z.infer<typeof createScanSchema>;

export const listFindingsQuerySchema = z.object({
  severity: z.array(z.enum(SEVERITIES)).optional(),
  kind: z.array(z.enum(SCAN_KINDS)).optional(),
  status: z
    .array(z.enum(['open', 'triaged', 'fixed', 'accepted-risk', 'false-positive']))
    .optional(),
  scanner: z.array(z.string().max(64)).optional(),
  search: z.string().max(200).optional(),
  path: z.string().max(512).optional(),
  suppressed: z.boolean().optional(),
  limit: z.number().int().positive().max(500).default(50),
  offset: z.number().int().nonnegative().default(0),
});

export const exportFormatSchema = z.enum(['json', 'csv', 'markdown', 'html', 'sarif', 'pdf']);
export type ExportFormat = z.infer<typeof exportFormatSchema>;

/* ------------------------------------------------------------------ */
/* Upload validation                                                   */
/* ------------------------------------------------------------------ */

/** ZIP local file header. Anything else is not an archive we will extract. */
const ZIP_MAGIC = [0x50, 0x4b, 0x03, 0x04];
const ZIP_EMPTY_MAGIC = [0x50, 0x4b, 0x05, 0x06];

export interface UploadValidationOptions {
  maxBytes: number;
  filename: string;
  size: number;
  /** First bytes of the file, for content-sniffing. */
  head: Uint8Array;
}

/**
 * Validate an uploaded archive on three independent axes — declared size,
 * filename, and actual magic bytes. Trusting `Content-Type` or the extension
 * alone is how upload endpoints become file-write primitives.
 */
export function validateArchiveUpload(options: UploadValidationOptions): void {
  const { maxBytes, filename, size, head } = options;

  if (size <= 0) throw errors.validation('Uploaded file is empty');
  if (size > maxBytes) {
    throw errors.tooLarge(
      `Uploaded file is ${Math.round(size / 1024 / 1024)}MB, which exceeds the ${Math.round(maxBytes / 1024 / 1024)}MB limit`,
    );
  }

  const safeName = filename.replace(/\\/g, '/').split('/').pop() ?? '';
  if (!safeName || safeName.startsWith('.')) {
    throw errors.validation('Invalid upload filename');
  }
  if (!/\.zip$/i.test(safeName)) {
    throw errors.validation('Only .zip archives are supported');
  }

  const matchesMagic = (magic: number[]) => magic.every((byte, i) => head[i] === byte);
  if (!matchesMagic(ZIP_MAGIC) && !matchesMagic(ZIP_EMPTY_MAGIC)) {
    throw errors.validation('Uploaded file is not a valid ZIP archive');
  }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/** Parse with a zod schema, converting failures into a typed API error. */
export function parseOrThrow<T extends z.ZodTypeAny>(schema: T, input: unknown): z.infer<T> {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw errors.validation(
      'Request validation failed',
      result.error.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      })),
    );
  }
  return result.data;
}

/** Human-readable label for a target, safe to render in the UI. */
export function describeTarget(target: ScanTarget): string {
  switch (target.type) {
    case 'github':
      return `${target.owner}/${target.repo}${target.ref ? `@${target.ref}` : ''}`;
    case 'local':
      return target.path.split('/').filter(Boolean).pop() ?? target.path;
    case 'archive':
      return target.originalName ?? 'uploaded archive';
  }
}
