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
import { getTheme, setTheme, subscribeToTheme, type ThemePreference } from '../lib/theme.js';

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
          <ThemeChoice />
          <button className="account-menu-item" role="menuitem" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

/*
 * The colour theme, offered to everybody rather than buried in an administrator screen.
 *
 * A radio group, not a switch: the third state is the point. "System" follows the machine
 * and keeps following it, which is the right default and the one most people should stay
 * on; a two-state toggle would force every reader who touched it into a fixed theme for
 * good. The group is labelled and arrow-key navigable because that is what a radio group
 * is, and a menu is a poor place to discover that your keyboard does not work.
 */
const THEMES: { value: ThemePreference; label: string }[] = [
  { value: 'system', label: 'System' },
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
];

function ThemeChoice() {
  const [preference, setPreference] = useState<ThemePreference>(getTheme);

  // The preference lives outside React — public/theme.js sets it before the bundle loads,
  // and the OS can change it under 'system' — so the component follows the store.
  useEffect(() => subscribeToTheme(setPreference), []);

  return (
    <div className="account-menu-section">
      <div className="account-menu-label" id="theme-choice-label">
        Appearance
      </div>
      <div className="segmented" role="radiogroup" aria-labelledby="theme-choice-label">
        {THEMES.map((theme) => (
          <button
            key={theme.value}
            type="button"
            role="radio"
            aria-checked={preference === theme.value}
            className="segmented-option"
            onClick={() => setTheme(theme.value)}
          >
            {theme.label}
          </button>
        ))}
      </div>
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
