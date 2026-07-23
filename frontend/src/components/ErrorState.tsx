import { AlertCircle } from 'lucide-react';
import './components.css';

interface ErrorStateProps {
  title: string;
  message: string;
  onRetry?: () => void;
}

export function ErrorState({ title, message, onRetry }: ErrorStateProps) {
  return (
    <div className="error-state" role="alert">
      <AlertCircle size={22} aria-hidden="true" />
      <div>
        <h3>{title}</h3>
        <p>{message}</p>
        {onRetry ? <button onClick={onRetry}>Retry</button> : null}
      </div>
    </div>
  );
}
