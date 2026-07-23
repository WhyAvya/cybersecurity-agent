import { Menu, X } from 'lucide-react';
import { useEffect } from 'react';
import { Sidebar } from './Sidebar';
import './shell.css';

interface MobileNavProps {
  open: boolean;
  onOpen: () => void;
  onClose: () => void;
}

export function MobileNav({ open, onOpen, onClose }: MobileNavProps) {
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [onClose, open]);

  return (
    <>
      <button className="mobile-menu-button" type="button" aria-label="Open navigation" onClick={onOpen}>
        <Menu size={22} aria-hidden="true" />
      </button>
      {open ? (
        <div className="mobile-drawer" role="dialog" aria-modal="true" aria-label="Navigation drawer">
          <button className="mobile-drawer__close" type="button" aria-label="Close navigation" onClick={onClose}>
            <X size={22} aria-hidden="true" />
          </button>
          <Sidebar onNavigate={onClose} />
        </div>
      ) : null}
    </>
  );
}
