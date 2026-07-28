import Link from 'next/link';
import { FileQuestion } from 'lucide-react';
import { Card, EmptyState } from '@/components/primitives';

export default function NotFound() {
  return (
    <div className="mx-auto max-w-lg">
      <Card>
        <EmptyState
          icon={<FileQuestion className="h-10 w-10" />}
          title="Not found"
          description="That page, scan or project does not exist, or you do not have access to it."
          action={
            <Link
              href="/"
              className="inline-flex h-10 items-center rounded-lg bg-[var(--color-accent)] px-5 text-sm font-medium text-white transition-colors hover:bg-[var(--color-accent-hover)]"
            >
              Back to overview
            </Link>
          }
        />
      </Card>
    </div>
  );
}
