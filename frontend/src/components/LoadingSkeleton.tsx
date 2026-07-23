import './components.css';

export function LoadingSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="skeleton" aria-label="Loading">
      {Array.from({ length: lines }, (_, index) => (
        <span key={index} className="skeleton__line" />
      ))}
    </div>
  );
}
