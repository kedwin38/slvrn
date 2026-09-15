/**
 * The navigation icon set.
 *
 * These were Unicode glyphs — ◫ ▤ ⇄ ☰ ⚿ ⛃ ⛨ ◈ ⟳ ☷ ▦ ◎ — chosen because they cost nothing
 * to ship. The trouble is that a glyph is rendered by whatever font the operating system
 * decides to substitute, so the same nav rendered as neat line art on one machine, emoji on
 * another, and a dotted-box tofu on a third. On a product being shown to a finance team,
 * that reads as unfinished.
 *
 * Drawn here instead: one 24-unit grid, 1.6 stroke, round caps, `currentColor` throughout so
 * a single icon works on the sidebar, in a chip, and inverted, in both themes. Roughly 3 KB
 * for the set, which is less than one webfont request and has no flash of missing glyph.
 *
 * `aria-hidden` on every one: each sits beside its own text label, and a screen reader
 * announcing "chart, Dashboard" is worse than silence.
 */

export interface IconProps {
  /** Matches the cap height of the label beside it. */
  size?: number;
}

function Svg({ size = 18, children }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

/** Dashboard — panels of a summary view. */
export const IconDashboard = (p: IconProps) => (
  <Svg {...p}>
    <rect x="3" y="3" width="7.5" height="9" rx="1.5" />
    <rect x="13.5" y="3" width="7.5" height="5.5" rx="1.5" />
    <rect x="3" y="15" width="7.5" height="6" rx="1.5" />
    <rect x="13.5" y="11.5" width="7.5" height="9.5" rx="1.5" />
  </Svg>
);

/** Payment batches — a stack of instructions moving together. */
export const IconBatches = (p: IconProps) => (
  <Svg {...p}>
    <rect x="3" y="7" width="18" height="13" rx="2" />
    <path d="M6.5 4h11" />
    <path d="M8 12h8M8 16h5" />
  </Svg>
);

/** Transactions — value leaving and outcomes returning. */
export const IconTransactions = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4 8h13l-3-3" />
    <path d="M20 16H7l3 3" />
  </Svg>
);

/** Reconciliation — the loop back to the provider for an answer. */
export const IconReconciliation = (p: IconProps) => (
  <Svg {...p}>
    <path d="M20 11a8 8 0 1 0-2.3 5.6" />
    <path d="M20 5v6h-6" />
  </Svg>
);

/** Recipients — the people paid. */
export const IconRecipients = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="9" cy="8" r="3.2" />
    <path d="M3.5 20a5.5 5.5 0 0 1 11 0" />
    <path d="M16 5.2a3.2 3.2 0 0 1 0 5.9" />
    <path d="M17.5 14.4A5.5 5.5 0 0 1 20.5 20" />
  </Svg>
);

/** Intelligence — analysis, drawn as a considered spark rather than a magic wand. */
export const IconIntelligence = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 3.5 13.7 9l5.5 1.7-5.5 1.7L12 18l-1.7-5.6L4.8 10.7 10.3 9Z" />
    <path d="M18.5 17.5 19.2 19.7 21.4 20.4 19.2 21.1 18.5 23.3 17.8 21.1 15.6 20.4 17.8 19.7Z" />
  </Svg>
);

/** Reports — a produced document. */
export const IconReports = (p: IconProps) => (
  <Svg {...p}>
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z" />
    <path d="M14 3v5h5" />
    <path d="M9 13h6M9 17h4" />
  </Svg>
);

/** Members — the organisation's people and their authority. */
export const IconMembers = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="12" cy="7.5" r="3.5" />
    <path d="M5 20a7 7 0 0 1 14 0" />
  </Svg>
);

/** M-PESA credentials — a key, because that is exactly what is stored. */
export const IconCredentials = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="8" cy="12" r="4" />
    <path d="M12 12h9" />
    <path d="M17.5 12v3.5M20.5 12v2.5" />
  </Svg>
);

/** Policy — the balance struck between control and throughput. */
export const IconPolicy = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 4v16" />
    <path d="M6 8h12" />
    <path d="M6 8 3.5 14h5Z" />
    <path d="M18 8 15.5 14h5Z" />
    <path d="M8.5 20h7" />
  </Svg>
);

/** Security centre — watching. */
export const IconSecurityCentre = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 3.5 19.5 6v6c0 4.4-3 7.7-7.5 9.2C7.5 19.7 4.5 16.4 4.5 12V6Z" />
    <circle cx="12" cy="11.5" r="2.4" />
  </Svg>
);

/** Audit trail — links in a chain, which is literally how the log is built. */
export const IconAudit = (p: IconProps) => (
  <Svg {...p}>
    <path d="M9.5 14.5a3.5 3.5 0 0 1 0-5l2-2a3.5 3.5 0 0 1 5 5l-1 1" />
    <path d="M14.5 9.5a3.5 3.5 0 0 1 0 5l-2 2a3.5 3.5 0 0 1-5-5l1-1" />
  </Svg>
);

/** Backups — durable storage. */
export const IconBackups = (p: IconProps) => (
  <Svg {...p}>
    <ellipse cx="12" cy="6" rx="7.5" ry="3" />
    <path d="M4.5 6v12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V6" />
    <path d="M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3" />
  </Svg>
);

/** Account security — the individual's own credentials. */
export const IconAccountSecurity = (p: IconProps) => (
  <Svg {...p}>
    <rect x="4.5" y="10" width="15" height="10.5" rx="2" />
    <path d="M8 10V7.5a4 4 0 0 1 8 0V10" />
  </Svg>
);

export const NAV_ICONS = {
  dashboard: IconDashboard,
  batches: IconBatches,
  transactions: IconTransactions,
  reconciliation: IconReconciliation,
  recipients: IconRecipients,
  intelligence: IconIntelligence,
  reports: IconReports,
  members: IconMembers,
  daraja: IconCredentials,
  policy: IconPolicy,
  'security-centre': IconSecurityCentre,
  audit: IconAudit,
  backups: IconBackups,
  security: IconAccountSecurity,
} as const;
