import type { ReactNode } from 'react';
import './components.css';

interface GlassPanelProps {
  children: ReactNode;
  className?: string;
  as?: 'section' | 'article' | 'div';
}

export function GlassPanel({ children, className = '', as: Element = 'section' }: GlassPanelProps) {
  return <Element className={`glass-panel ${className}`}>{children}</Element>;
}
