import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { errors, isSafeArchiveEntry, safeResolve, type Logger } from '@sentinel/core';

/**
 * Minimal, hardened ZIP reader.
 *
 * Written in-house rather than pulled from npm because archive extraction is
 * the single most attacker-reachable code path in the product: a malicious
 * upload gets to choose every byte. Keeping it small means every branch is
 * auditable, and it lets us enforce zip-slip *and* zip-bomb limits directly
 * instead of hoping a dependency does.
 *
 * Supports stored (method 0) and deflate (method 8) entries, which covers every
 * archive produced by `git archive`, GitHub's "Download ZIP", and standard zip
 * tools.
 */

const END_OF_CENTRAL_DIRECTORY = 0x06054b50;
const ZIP64_END_LOCATOR = 0x07064b50;
const CENTRAL_FILE_HEADER = 0x02014b50;
const LOCAL_FILE_HEADER = 0x04034b50;

export interface ZipLimits {
  /** Reject the archive if the sum of uncompressed sizes exceeds this. */
  maxTotalUncompressedBytes: number;
  /** Reject a single entry larger than this. */
  maxEntryBytes: number;
  maxEntries: number;
  /**
   * Reject when uncompressed/compressed exceeds this ratio — the classic
   * zip-bomb signature (42.zip inflates ~4.5 billion to one).
   */
  maxCompressionRatio: number;
}

export const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxTotalUncompressedBytes: 2 * 1024 * 1024 * 1024,
  maxEntryBytes: 256 * 1024 * 1024,
  maxEntries: 200_000,
  maxCompressionRatio: 200,
};

export interface ZipEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  compressionMethod: number;
  localHeaderOffset: number;
  isDirectory: boolean;
}

function findEndOfCentralDirectory(buffer: Buffer): number {
  // The EOCD record is at the end but may be followed by up to 64KB of comment.
  const maxCommentLength = 0xffff;
  const start = Math.max(0, buffer.length - maxCommentLength - 22);
  for (let i = buffer.length - 22; i >= start; i -= 1) {
    if (buffer.readUInt32LE(i) === END_OF_CENTRAL_DIRECTORY) return i;
  }
  return -1;
}

export function readZipEntries(buffer: Buffer, limits: ZipLimits = DEFAULT_ZIP_LIMITS): ZipEntry[] {
  const eocd = findEndOfCentralDirectory(buffer);
  if (eocd < 0)
    throw errors.validation('Not a valid ZIP archive: end of central directory not found');

  // ZIP64 archives use different offset fields; rather than partially support
  // them and get it subtly wrong, we reject them explicitly.
  if (buffer.length > 64 && buffer.readUInt32LE(eocd - 20) === ZIP64_END_LOCATOR) {
    throw errors.validation('ZIP64 archives are not supported; please upload an archive under 4GB');
  }

  const entryCount = buffer.readUInt16LE(eocd + 10);
  if (entryCount > limits.maxEntries) {
    throw errors.tooLarge(
      `Archive contains ${entryCount} entries, exceeding the ${limits.maxEntries} limit`,
    );
  }

  const centralDirOffset = buffer.readUInt32LE(eocd + 16);
  const entries: ZipEntry[] = [];
  let offset = centralDirOffset;
  let totalUncompressed = 0;

  for (let i = 0; i < entryCount; i += 1) {
    if (offset + 46 > buffer.length) {
      throw errors.validation('Corrupt ZIP archive: central directory is truncated');
    }
    if (buffer.readUInt32LE(offset) !== CENTRAL_FILE_HEADER) {
      throw errors.validation('Corrupt ZIP archive: bad central directory signature');
    }

    const compressionMethod = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString('utf8', offset + 46, offset + 46 + nameLength);

    if (uncompressedSize > limits.maxEntryBytes) {
      throw errors.tooLarge(`Archive entry "${name}" exceeds the per-file size limit`);
    }

    // Ratio check per entry catches a bomb hidden among normal-looking files.
    if (compressedSize > 0 && uncompressedSize / compressedSize > limits.maxCompressionRatio) {
      throw errors.validation(
        `Archive entry "${name}" has a suspicious compression ratio and was rejected as a potential zip bomb`,
      );
    }

    totalUncompressed += uncompressedSize;
    if (totalUncompressed > limits.maxTotalUncompressedBytes) {
      throw errors.tooLarge('Archive exceeds the maximum total uncompressed size');
    }

    entries.push({
      name,
      compressedSize,
      uncompressedSize,
      compressionMethod,
      localHeaderOffset,
      isDirectory: name.endsWith('/'),
    });

    offset += 46 + nameLength + extraLength + commentLength;
  }

  return entries;
}

export function readZipEntryData(buffer: Buffer, entry: ZipEntry): Buffer {
  const header = entry.localHeaderOffset;
  if (header + 30 > buffer.length || buffer.readUInt32LE(header) !== LOCAL_FILE_HEADER) {
    throw errors.validation(`Corrupt ZIP archive: bad local header for "${entry.name}"`);
  }

  // The local header's name/extra lengths can differ from the central directory's.
  const nameLength = buffer.readUInt16LE(header + 26);
  const extraLength = buffer.readUInt16LE(header + 28);
  const dataStart = header + 30 + nameLength + extraLength;
  const dataEnd = dataStart + entry.compressedSize;

  if (dataEnd > buffer.length) {
    throw errors.validation(`Corrupt ZIP archive: data for "${entry.name}" is truncated`);
  }

  const raw = buffer.subarray(dataStart, dataEnd);

  if (entry.compressionMethod === 0) return Buffer.from(raw);
  if (entry.compressionMethod === 8) {
    const inflated = inflateRawSync(raw, { maxOutputLength: entry.uncompressedSize + 1024 });
    return Buffer.from(inflated);
  }

  throw errors.validation(
    `Archive entry "${entry.name}" uses unsupported compression method ${entry.compressionMethod}`,
  );
}

export interface ExtractResult {
  filesWritten: number;
  bytesWritten: number;
  skipped: { name: string; reason: string }[];
}

/**
 * Extract an archive into `destination`.
 *
 * Every entry is checked twice: once by name shape (`isSafeArchiveEntry`) and
 * once by resolved path (`safeResolve`). Defense in depth here is cheap and the
 * failure mode — arbitrary file write — is catastrophic.
 */
export async function extractZip(
  buffer: Buffer,
  destination: string,
  options: { limits?: ZipLimits; logger?: Logger } = {},
): Promise<ExtractResult> {
  const limits = options.limits ?? DEFAULT_ZIP_LIMITS;
  const entries = readZipEntries(buffer, limits);
  const skipped: ExtractResult['skipped'] = [];
  let filesWritten = 0;
  let bytesWritten = 0;

  await mkdir(destination, { recursive: true });

  for (const entry of entries) {
    if (entry.isDirectory) continue;

    if (!isSafeArchiveEntry(entry.name)) {
      skipped.push({ name: entry.name, reason: 'unsafe path' });
      options.logger?.warn('Skipped unsafe archive entry', { entry: entry.name });
      continue;
    }

    let targetPath: string;
    try {
      targetPath = safeResolve(destination, entry.name);
    } catch {
      skipped.push({ name: entry.name, reason: 'path escapes destination' });
      continue;
    }

    const data = readZipEntryData(buffer, entry);
    await mkdir(dirname(targetPath), { recursive: true });
    await writeFile(targetPath, data);
    filesWritten += 1;
    bytesWritten += data.length;
  }

  if (skipped.length) {
    options.logger?.warn('Archive contained unsafe entries that were skipped', {
      count: skipped.length,
    });
  }

  return { filesWritten, bytesWritten, skipped };
}

/**
 * Some archives (GitHub's "Download ZIP") wrap everything in a single top-level
 * directory. Detect that so the scan root is the project, not its wrapper.
 */
export function detectSingleRoot(entries: readonly ZipEntry[]): string | undefined {
  const tops = new Set<string>();
  for (const entry of entries) {
    const top = entry.name.split('/')[0];
    if (top) tops.add(top);
    if (tops.size > 1) return undefined;
  }
  const [only] = [...tops];
  return only;
}

export function hashBuffer(buffer: Buffer): string {
  return createHash('sha256').update(buffer).digest('hex').slice(0, 16);
}

export function joinRoot(root: string, sub: string | undefined): string {
  return sub ? join(root, sub) : root;
}
