import { EmptyState } from '../components/EmptyState';
import { PageHeader } from '../components/PageHeader';
import './pages.css';

export function PlaceholderPage({ title, description }: { title: string; description: string }) {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Phase 1 shell" title={title}>
        {description}
      </PageHeader>
      <EmptyState title="Not implemented in React Phase 1">
        This route is intentionally present as a page shell. Source forms, scan submission, findings, comparisons, and charts are scheduled for later phases.
      </EmptyState>
    </div>
  );
}
