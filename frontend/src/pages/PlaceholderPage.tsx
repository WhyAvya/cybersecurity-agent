import { EmptyState } from '../components/EmptyState';
import { PageHeader } from '../components/PageHeader';
import './pages.css';

export function PlaceholderPage({ title, description }: { title: string; description: string }) {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Available route" title={title}>
        {description}
      </PageHeader>
      <EmptyState title="No content available">
        This route has no additional content to display.
      </EmptyState>
    </div>
  );
}
