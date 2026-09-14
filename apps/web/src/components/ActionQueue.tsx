/**
 * The action queue — "there is a batch waiting for you".
 *
 * Separation of duties has an operational failure mode nobody designs for: the batch sits in
 * L3_READY because the one person who can release it does not know it is there. Salaries are
 * late, somebody phones somebody, and the control takes the blame for the delay.
 *
 * There is no SMS and no email anywhere in this product, by requirement. So the signal lives
 * where the work is: at the top of every screen, on every page, until it is dealt with.
 *
 * What appears is computed server-side from the caller's own authority — an L1 is told their
 * batch was returned for correction, an L3 is told there is money waiting to be released.
 * Nothing here grants access; it reports what this person could already do, which is why it
 * is safe to render before knowing anything else about the page.
 */

import { useEffect, useState } from 'react';
import { api, type ActionQueueItem } from '../lib/api.js';

const TONE: Record<ActionQueueItem['severity'], 'danger' | 'warning' | 'info'> = {
  critical: 'danger',
  warning: 'warning',
  info: 'info',
};

export function ActionQueue({ onOpen }: { onOpen: (route: string) => void }) {
  const [items, setItems] = useState<ActionQueueItem[]>([]);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    let live = true;
    const load = () => {
      api.analytics
        .actionQueue()
        .then((result) => {
          if (live) setItems(result.items);
        })
        // A failure here must never block the page. The queue is a prompt, not a gate, and
        // the underlying screens report their own errors properly.
        .catch(() => undefined);
    };
    load();
    // Long enough not to be chatty, short enough that an approver who leaves the console
    // open sees a batch arrive without reloading.
    const timer = window.setInterval(load, 60_000);
    return () => {
      live = false;
      window.clearInterval(timer);
    };
  }, []);

  const visible = items.filter((item) => !dismissed.has(item.kind));
  if (visible.length === 0) return null;

  const shown = expanded ? visible : visible.slice(0, 2);

  return (
    <div className="stack" style={{ marginBlockEnd: 'var(--s4)' }}>
      {shown.map((item) => (
        <div
          key={item.kind}
          className="notice"
          data-tone={TONE[item.severity]}
          role="status"
          aria-live="polite"
        >
          <div style={{ display: 'flex', gap: 'var(--s3)', alignItems: 'start', flexWrap: 'wrap' }}>
            <div style={{ flex: '1 1 240px' }}>
              <strong>{item.title}</strong>
              <div className="small">{item.detail}</div>
            </div>
            <div style={{ display: 'flex', gap: 'var(--s2)' }}>
              <button
                className="button button-sm"
                data-variant="primary"
                onClick={() => onOpen(item.route)}
              >
                Open
              </button>
              <button
                className="button button-sm"
                data-variant="ghost"
                /* Dismissal lives in component state only: it hides the prompt for this
                   visit and it is back on the next sign-in, because the work is still
                   waiting. A notice that could be permanently silenced would be. */
                onClick={() => setDismissed(new Set(dismissed).add(item.kind))}
              >
                Not now
              </button>
            </div>
          </div>
        </div>
      ))}

      {visible.length > shown.length && (
        <button className="button button-sm" data-variant="ghost" onClick={() => setExpanded(true)}>
          Show {visible.length - shown.length} more waiting on you
        </button>
      )}
    </div>
  );
}
