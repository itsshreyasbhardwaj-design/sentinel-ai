#!/usr/bin/env node
import { run } from './index.js';

/**
 * CLI entry point.
 *
 * Everything that can fail is funnelled into an exit code, because in CI the
 * exit code is the only part of this that a pipeline reads.
 */
run(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`\nsentinel: ${message}\n`);
    if (process.env['SENTINEL_DEBUG'] && error instanceof Error) {
      process.stderr.write(`${error.stack}\n`);
    }
    process.exitCode = 2;
  });
