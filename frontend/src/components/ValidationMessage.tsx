import './scan.css';

export function ValidationMessage({ tone = 'warning', children }: { tone?: 'warning' | 'danger' | 'success'; children: string }) {
  return <p className={`validation validation--${tone}`}>{children}</p>;
}
