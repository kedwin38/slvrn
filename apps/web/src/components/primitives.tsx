/**
 * Interface primitives.
 *
 * Each component here exists because a plain HTML element would be wrong in a specific,
 * nameable way for a payment console — not for the sake of having a component library.
 */

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { formatCents, statusTone, type TxnState } from '@solvaren/core';

// ---------------------------------------------------------------------------
// Money
// ---------------------------------------------------------------------------

/**
 * Render an amount.
 *
 * `aria-label` spells the figure out because a screen reader pronouncing "45,000.00" as
 * "forty five thousand point zero zero" in a column of fifty is exhausting, and because
 * the currency belongs in the announcement.
 */
export function Amount({
  cents,
  size = 'normal',
  showCurrency = true,
}: {
  cents: number;
  size?: 'normal' | 'large';
  showCurrency?: boolean;
}) {
  const formatted = formatCents(cents);
  return (
    <span
      className={size === 'large' ? 'amount amount-lg' : 'amount'}
      aria-label={`${formatted} Kenyan shillings`}
    >
      {showCurrency && (
        <span className="amount-currency" aria-hidden="true">
          KES
        </span>
      )}
      <span aria-hidden="true">{formatted}</span>
    </span>
  );
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

const STATUS_LABELS: Record<TxnState, string> = {
  PENDING: 'Pending',
  SUBMITTED: 'Submitted',
  AWAITING_CALLBACK: 'Awaiting result',
  PROCESSING: 'Processing',
  RECONCILING: 'Reconciling',
  SUCCESS: 'Paid',
  FAILED: 'Failed',
  TIMEOUT: 'Timed out',
  CANCELLED: 'Cancelled',
};

/**
 * A status chip.
 *
 * The colour is reinforced by a glyph (in CSS) and by the text label, so status survives
 * greyscale printing, colour-vision deficiency and screen readers — WCAG 2.2 1.4.1 forbids
 * conveying information by colour alone, and an audit pack is frequently printed.
 */
export function StatusChip({ status }: { status: TxnState }) {
  return (
    <span className="chip" data-tone={statusTone(status)}>
      {STATUS_LABELS[status]}
    </span>
  );
}

export function BatchStateChip({ state }: { state: string }) {
  const tone =
    state === 'SUCCESS'
      ? 'success'
      : state === 'FAILED' || state === 'CANCELLED'
        ? 'danger'
        : state === 'PARTIAL_SUCCESS' || state === 'TIMEOUT' || state === 'HELD'
          ? 'warning'
          : state === 'DRAFT'
            ? 'neutral'
            : 'info';
  return (
    <span className="chip" data-tone={tone}>
      {state.replace(/_/g, ' ').toLowerCase()}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Feedback
// ---------------------------------------------------------------------------

/*
 * Each glyph carries U+FE0E, the text variation selector.
 *
 * Without it "\u26a0" and "\u2139" have emoji presentation by default on iOS and Windows,
 * so a status that is meant to read as a typographic mark turns into a full-colour emoji
 * beside sober financial copy — and, on a monochrome printout, into an ink blot. FE0E asks
 * for the text form; systems that only have the emoji font ignore it, and the adjacent
 * label still carries the meaning either way.
 */
const NOTICE_GLYPH = {
  info: 'ℹ\uFE0E',
  success: '✓',
  warning: '⚠\uFE0E',
  danger: '✕',
  neutral: '•',
} as const;

export function Notice({
  tone = 'info',
  title,
  children,
  /** Set for messages that must be announced when they appear, such as an error. */
  live,
}: {
  tone?: keyof typeof NOTICE_GLYPH;
  title?: string;
  children: ReactNode;
  live?: 'polite' | 'assertive';
}) {
  return (
    <div
      className="notice"
      data-tone={tone}
      role={live === 'assertive' ? 'alert' : undefined}
      aria-live={live}
    >
      <span className="notice-icon" aria-hidden="true">
        {NOTICE_GLYPH[tone]}
      </span>
      <div>
        {title && <div className="strong">{title}</div>}
        <div>{children}</div>
      </div>
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-title">{title}</div>
      {children && <div className="small">{children}</div>}
    </div>
  );
}

/**
 * Loading placeholder.
 *
 * Shaped like the content it replaces, so the layout does not jump when data arrives —
 * a jumping table is how an operator clicks the wrong row.
 */
export function TableSkeleton({ rows = 6, columns = 6 }: { rows?: number; columns?: number }) {
  return (
    <div aria-busy="true" aria-live="polite" style={{ padding: 'var(--s4)' }}>
      <span className="visually-hidden">Loading</span>
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div
          key={rowIndex}
          style={{ display: 'flex', gap: 'var(--s4)', marginBlockEnd: 'var(--s3)' }}
          aria-hidden="true"
        >
          {Array.from({ length: columns }).map((__, columnIndex) => (
            <div
              key={columnIndex}
              className="skeleton"
              style={{ height: 14, flex: columnIndex === 0 ? '2 1 0' : '1 1 0' }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

export function Stat({
  label,
  value,
  detail,
  tone,
  onClick,
}: {
  label: string;
  value: ReactNode;
  detail?: ReactNode;
  tone?: 'success' | 'warning' | 'danger';
  /** When present the tile becomes a button — the drill-down of spec §6.3. */
  onClick?: () => void;
}) {
  const content = (
    <>
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
      {detail && <span className="stat-detail">{detail}</span>}
    </>
  );

  if (onClick) {
    return (
      <button
        className="stat"
        data-tone={tone}
        onClick={onClick}
        style={{ textAlign: 'left', cursor: 'pointer' }}
      >
        {content}
      </button>
    );
  }
  return (
    <div className="stat" data-tone={tone}>
      {content}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Modal
// ---------------------------------------------------------------------------

/**
 * Modal dialog with a focus trap.
 *
 * The trap is not decoration: the authorization ceremony is rendered in one, and a
 * keyboard user who tabs out of it into the page behind can end up pressing a button they
 * cannot see. Escape closes, unless the dialog is mid-ceremony and the caller forbids it.
 */
export function Modal({
  open,
  onClose,
  labelledBy,
  children,
  dismissible = true,
  bleed = false,
}: {
  open: boolean;
  onClose: () => void;
  labelledBy: string;
  children: ReactNode;
  dismissible?: boolean;
  /**
   * Remove the dialog's own padding, for content that supplies its own edge-to-edge bands.
   *
   * The default is padding, because the opposite default was wrong everywhere it was used.
   * The dialog originally had none, on the reasoning that the release ceremony paints its
   * own full-width header, amount panel and footer — true for that one caller, and every
   * other dialog in the console inherited it. The credentials form, the batch detail and
   * the new-batch form all rendered their labels and inputs flush against the border, which
   * reads as an unstyled form on the screen an administrator uses to connect M-PESA.
   */
  bleed?: boolean;
}) {
  const container = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

  const focusable = useCallback(
    () =>
      Array.from(
        container.current?.querySelectorAll<HTMLElement>(
          'button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])',
        ) ?? [],
      ),
    [],
  );

  /*
   * The key handler reads its callbacks from a ref rather than closing over them.
   *
   * This is not a micro-optimisation. Every caller passes `onClose={() => setX(false)}`,
   * a new function identity on every render, so an effect that depended on `onClose` tore
   * down and re-ran after each keystroke — and its teardown restored focus to the element
   * that opened the dialog while its setup moved focus to the first field. The visible
   * result was a form you could only type one character at a time into, because the caret
   * jumped out of the field on every key.
   *
   * Fixing it at each call site would mean every future caller has to remember to memoise,
   * and a contract that must be remembered is one that will be forgotten. So the dialog
   * takes callers as they are.
   */
  const latest = useRef({ onClose, dismissible });
  useEffect(() => {
    latest.current = { onClose, dismissible };
  });

  // Focus and scroll locking, keyed on `open` alone: these must happen when the dialog
  // opens and closes, and at no other time.
  useEffect(() => {
    if (!open) return;

    previouslyFocused.current = document.activeElement as HTMLElement | null;
    focusable()[0]?.focus();

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.body.style.overflow = previousOverflow;
      // Return focus to whatever opened the dialog, so the keyboard user is not dumped at
      // the top of the document.
      previouslyFocused.current?.focus();
    };
  }, [open, focusable]);

  // The focus trap. Re-subscribing a listener is harmless; moving focus is not, which is
  // why this is a separate effect from the one above.
  useEffect(() => {
    if (!open) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && latest.current.dismissible) {
        event.preventDefault();
        latest.current.onClose();
        return;
      }
      if (event.key !== 'Tab') return;

      const elements = focusable();
      if (elements.length === 0) return;
      const first = elements[0]!;
      const last = elements[elements.length - 1]!;

      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [open, focusable]);

  if (!open) return null;

  return (
    <div
      className="ceremony-backdrop"
      onMouseDown={(event) => {
        if (dismissible && event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className={bleed ? 'ceremony ceremony-bleed' : 'ceremony'}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy}
        ref={container}
      >
        {children}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Copy to clipboard
// ---------------------------------------------------------------------------

/**
 * A provider reference with a copy affordance.
 *
 * Operators take these codes to Safaricom support verbatim; a transcription error wastes a
 * support call, so the code is selectable in one click and copyable in one press.
 */
export function Reference({ value, label }: { value: string | null; label: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="muted small">—</span>;

  return (
    <span className="row gap-2" style={{ gap: 'var(--s2)' }}>
      <code className="reference">{value}</code>
      <button
        className="button button-sm"
        data-variant="ghost"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1600);
          } catch {
            // Clipboard blocked (insecure context or denied permission). The value is
            // `user-select: all`, so a manual copy still works.
          }
        }}
        aria-label={`Copy ${label}`}
      >
        {copied ? 'Copied' : 'Copy'}
      </button>
    </span>
  );
}

// ---------------------------------------------------------------------------
// Form field
// ---------------------------------------------------------------------------

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string | null;
  children: (props: {
    id: string;
    'aria-describedby': string | undefined;
    'aria-invalid': boolean;
  }) => ReactNode;
}) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [hintId, errorId].filter(Boolean).join(' ') || undefined;

  return (
    <div className="field">
      <label className="label" htmlFor={id}>
        {label}
      </label>
      {children({ id, 'aria-describedby': describedBy, 'aria-invalid': Boolean(error) })}
      {hint && (
        <span className="hint" id={hintId}>
          {hint}
        </span>
      )}
      {error && (
        <span className="error-text" id={errorId} role="alert">
          {error}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Relative time
// ---------------------------------------------------------------------------

/**
 * "4 minutes ago", with the exact timestamp in the tooltip and in the accessible name.
 *
 * Relative time is what an operator watching a payroll run actually wants; the absolute
 * value is what an auditor needs. Both are present.
 */
export function RelativeTime({ value }: { value: string | null }) {
  if (!value) return <span className="muted">—</span>;

  const date = new Date(value);
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  const absolute = date.toLocaleString('en-KE', { dateStyle: 'medium', timeStyle: 'medium' });

  let relative: string;
  if (seconds < 45) relative = 'just now';
  else if (seconds < 3600) relative = `${Math.floor(seconds / 60)} min ago`;
  else if (seconds < 86_400) relative = `${Math.floor(seconds / 3600)} h ago`;
  else if (seconds < 2_592_000) relative = `${Math.floor(seconds / 86_400)} d ago`;
  else relative = date.toLocaleDateString('en-KE', { dateStyle: 'medium' });

  return (
    <time dateTime={value} title={absolute} aria-label={absolute} className="nowrap">
      {relative}
    </time>
  );
}
