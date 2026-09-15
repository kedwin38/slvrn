/**
 * Who you are signed in as, and the way out.
 *
 * This lived at the bottom of the sidebar as four stacked lines of small grey text with a
 * ghost button under them — the least considered corner of the console, and the one a
 * finance director looks at first to check they are in the right account.
 *
 * It belongs beside the environment badge, because identity, authority and environment
 * answer one question together: what am I allowed to do here, and does it move real money.
 *
 * The authority level is shown in full rather than as "L3". Somebody being shown this
 * product for the first time has no idea what L3 means, and "Chief / Executive Payment
 * Authority" is the whole point of the hierarchy.
 */

import { useEffect, useRef, useState } from 'react';

export function AccountMenu({
  fullName,
  levelTitle,
  email,
  onSignOut,
}: {
  fullName: string;
  levelTitle: string;
  email: string;
  onSignOut: () => void;
}) {
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent) => {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  return (
    <div className="account" ref={container}>
      <button
        className="account-trigger"
        aria-expanded={open}
        aria-haspopup="menu"
        onClick={() => setOpen((value) => !value)}
      >
        <span className="avatar" aria-hidden="true">
          {initials(fullName)}
        </span>
        <span className="account-who">
          <span className="account-name">{fullName}</span>
          <span className="account-level">{levelTitle}</span>
        </span>
        <svg
          className="account-caret"
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div className="account-menu" role="menu">
          <div className="account-menu-head">
            <div className="strong">{fullName}</div>
            <div className="small muted">{email}</div>
            <div className="small muted">{levelTitle}</div>
          </div>
          <button className="account-menu-item" role="menuitem" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

/** Two letters at most: "Amina Njeri" reads as AN, a single name as its first letter. */
function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0]!.charAt(0).toUpperCase();
  return (parts[0]!.charAt(0) + parts[parts.length - 1]!.charAt(0)).toUpperCase();
}
