'use client';

import { useEffect } from 'react';
import { AlertOctagon } from 'lucide-react';
import { Button, Card, EmptyState } from '@/components/primitives';

/**
 * Route error boundary.
 *
 * Shows a generic message and the digest only. Rendering the raw error would
 * leak internal paths and query structure into the browser — the same class of
 * information disclosure Sentinel reports on.
 */
export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('Route error', error);
  }, [error]);

  return (
    <div className="mx-auto max-w-lg">
      <Card>
        <EmptyState
          icon={<AlertOctagon className="h-10 w-10 text-[var(--color-critical)]" />}
          title="Something went wrong"
          description={
            error.digest
              ? `An unexpected error occurred. Reference: ${error.digest}`
              : 'An unexpected error occurred while rendering this page.'
          }
          action={
            <Button variant="primary" onClick={reset}>
              Try again
            </Button>
          }
        />
      </Card>
    </div>
  );
}
