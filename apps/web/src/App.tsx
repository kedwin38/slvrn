/**
 * Application shell.
 *
 * Routing is hash-based and hand-rolled. A router library would add 15 KB to carry six
 * routes, and a payment console opened on a phone over a mobile network during a payroll
 * run is exactly the case where that matters.
 *
 * The navigation renders from the capability payload the server issued at sign-in, so an
 * L1 officer never sees a Daraja settings link. That is a courtesy, not a control: every
 * endpoint re-checks authority server-side (spec §4, HARD CONTROL).
 */

import { useCallback, useEffect, useState } from 'react';
import { LEVEL_TITLES, type TxnState } from '@solvaren/core';
import { api, ApiError, setSessionToken, type SessionResponse } from './lib/api.js';
import { Login } from './pages/Login.js';
import { Dashboard } from './pages/Dashboard.js';
import { TransactionsExplorer } from './pages/TransactionsExplorer.js';
import { BatchesPage } from './pages/Batches.js';
import { BackupsPage } from './pages/Backups.js';
import { UsersPage } from './pages/Users.js';
import { DarajaCredentialsPage } from './pages/DarajaCredentials.js';
import { AuditLogPage } from './pages/AuditLog.js';
import { PolicySettingsPage } from './pages/PolicySettings.js';
import { SecuritySettingsPage } from './pages/SecuritySettings.js';
import { ReconciliationPage } from './pages/Reconciliation.js';
import { RecipientsPage } from './pages/Recipients.js';
import { SecurityCentrePage } from './pages/SecurityCentre.js';
import { ReportsPage } from './pages/Reports.js';
import { IntelligencePage } from './pages/Intelligence.js';
import { ActionQueue } from './components/ActionQueue.js';
import { StepUpGate } from './components/StepUp.js';
import { Notice } from './components/primitives.js';

type Route =
  | 'dashboard'
  | 'transactions'
  | 'batches'
  | 'reconciliation'
  | 'recipients'
  | 'reports'
  | 'intelligence'
  | 'backups'
  | 'members'
  | 'daraja'
  | 'policy'
  | 'audit'
  | 'security-centre'
  | 'security';

interface NavEntry {
  route: Route;
  label: string;
  icon: string;
  /** Rendered only when the actor holds this capability. */
  requires?: string;
  group: 'Operations' | 'Administration' | 'Account';
}

const NAVIGATION: NavEntry[] = [
  { route: 'dashboard', label: 'Dashboard', icon: '◫', group: 'Operations' },
  {
    route: 'batches',
    label: 'Payment batches',
    icon: '▤',
    requires: 'batch:read',
    group: 'Operations',
  },
  {
    route: 'transactions',
    label: 'Transactions',
    icon: '⇄',
    requires: 'transactions:read',
    group: 'Operations',
  },
  {
    route: 'reconciliation',
    label: 'Reconciliation',
    icon: '⟳',
    requires: 'reconciliation:read',
    group: 'Operations',
  },
  {
    route: 'recipients',
    label: 'Recipients',
    icon: '☷',
    requires: 'recipients:read',
    group: 'Operations',
  },
  {
    route: 'intelligence',
    label: 'Intelligence',
    icon: '◈',
    requires: 'ai:batch_analysis',
    group: 'Operations',
  },
  {
    route: 'reports',
    label: 'Reports',
    icon: '▦',
    requires: 'reports:operational',
    group: 'Operations',
  },
  {
    route: 'members',
    label: 'Members',
    icon: '☰',
    requires: 'admin:users',
    group: 'Administration',
  },
  {
    route: 'daraja',
    label: 'M-PESA credentials',
    icon: '⚿',
    requires: 'admin:daraja',
    group: 'Administration',
  },
  {
    route: 'policy',
    label: 'Policy',
    icon: '⚖',
    requires: 'admin:policies',
    group: 'Administration',
  },
  {
    route: 'security-centre',
    label: 'Security centre',
    icon: '◎',
    requires: 'admin:security',
    group: 'Administration',
  },
  {
    route: 'audit',
    label: 'Audit trail',
    icon: '✇',
    requires: 'audit:read_org',
    group: 'Administration',
  },
  {
    route: 'backups',
    label: 'Backups',
    icon: '⛃',
    requires: 'admin:backups',
    group: 'Administration',
  },
  // Everyone has their own credentials to manage, so this carries no capability gate.
  { route: 'security', label: 'Security', icon: '⛨', group: 'Account' },
];

export function App() {
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [route, setRoute] = useState<Route>(readRoute());
  const [explorerFilter, setExplorerFilter] = useState<{ statuses?: TxnState[]; batchId?: string }>(
    {},
  );
  const [banner, setBanner] = useState<{ tone: 'success' | 'danger'; message: string } | null>(
    null,
  );

  useEffect(() => {
    const onHashChange = () => setRoute(readRoute());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const navigate = useCallback((next: Route) => {
    window.location.hash = `#/${next}`;
    setRoute(next);
    // Move focus to the main region so a keyboard user is not left at the nav item they
    // just activated, hunting for where the page went.
    document.getElementById('main-content')?.focus();
  }, []);

  const drillDown = useCallback(
    (statuses: TxnState[]) => {
      setExplorerFilter({ statuses });
      navigate('transactions');
    },
    [navigate],
  );

  async function signOut() {
    try {
      await api.auth.logout();
    } catch {
      // Even if the call fails, the local token must go.
    }
    setSessionToken(null);
    setSession(null);
  }

  if (!session) {
    return <Login onAuthenticated={setSession} />;
  }

  const { user, capabilities } = session;
  const visible = NAVIGATION.filter(
    (entry) => !entry.requires || capabilities[entry.requires as never],
  );
  const groups = ['Operations', 'Administration', 'Account'] as const;

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Main">
        <div className="brand">
          <BrandMark />
          <div>
            <div className="brand-name">SOLVAREN</div>
            <div className="brand-tagline">Move money with certainty</div>
          </div>
        </div>

        <div className="nav">
          {groups.map((group) => {
            const entries = visible.filter((entry) => entry.group === group);
            if (entries.length === 0) return null;
            return (
              <div key={group}>
                <div className="nav-group-label">{group}</div>
                {entries.map((entry) => (
                  <button
                    key={entry.route}
                    className="nav-item"
                    aria-current={route === entry.route ? 'page' : undefined}
                    onClick={() => {
                      if (entry.route === 'transactions') setExplorerFilter({});
                      navigate(entry.route);
                    }}
                  >
                    <span className="nav-item-icon" aria-hidden="true">
                      {entry.icon}
                    </span>
                    {entry.label}
                  </button>
                ))}
              </div>
            );
          })}
        </div>

        <div style={{ marginBlockStart: 'auto', paddingInline: 'var(--s2)' }}>
          <div className="small strong">{user.fullName}</div>
          <div className="small muted">{LEVEL_TITLES[user.level]}</div>
          <div className="small muted">{user.organizationSlug}</div>
          <button
            className="button button-sm"
            data-variant="ghost"
            onClick={signOut}
            style={{ marginBlockStart: 'var(--s3)' }}
          >
            Sign out
          </button>
        </div>
      </nav>

      {/* Rendered once, above every route: any protected action can raise it. */}
      <StepUpGate />

      <main className="main" id="main-content" tabIndex={-1}>
        {banner && (
          <div style={{ marginBlockEnd: 'var(--s4)' }}>
            <Notice tone={banner.tone} live="polite">
              {banner.message}
            </Notice>
          </div>
        )}

        <ActionQueue onOpen={(next) => navigate(next as Route)} />

        {route === 'dashboard' && (
          <Dashboard
            capabilities={capabilities}
            level={user.level}
            fullName={user.fullName}
            onDrillDown={drillDown}
          />
        )}

        {route === 'transactions' && (
          <TransactionsExplorer
            capabilities={capabilities}
            initialStatuses={explorerFilter.statuses}
            initialBatchId={explorerFilter.batchId}
          />
        )}

        {route === 'batches' && (
          <BatchesPage
            capabilities={capabilities}
            onReleased={(summary) =>
              setBanner({
                tone: 'success',
                message: `${summary.batchReference} released. ${summary.message}`,
              })
            }
            onViewTransactions={(batchId) => {
              setExplorerFilter({ batchId });
              navigate('transactions');
            }}
          />
        )}

        {route === 'reconciliation' && <ReconciliationPage capabilities={capabilities} />}
        {route === 'recipients' && <RecipientsPage capabilities={capabilities} />}
        {route === 'reports' && <ReportsPage />}
        {route === 'intelligence' && <IntelligencePage capabilities={capabilities} />}
        {route === 'security-centre' && <SecurityCentrePage />}
        {route === 'backups' && <BackupsPage />}
        {route === 'members' && <UsersPage />}
        {route === 'daraja' && <DarajaCredentialsPage />}
        {route === 'policy' && <PolicySettingsPage />}
        {route === 'audit' && <AuditLogPage />}
        {route === 'security' && <SecuritySettingsPage session={session} />}
      </main>
    </div>
  );
}

function readRoute(): Route {
  /*
   * Derived from NAVIGATION rather than listed again.
   *
   * This was a second, hand-maintained copy of the route list, and it silently fell out of
   * step the moment routes were added: the nav entry rendered, the hash changed, and this
   * function did not recognise the value, so every new screen quietly showed the dashboard
   * instead. A allowlist that has to be remembered is one that will eventually be forgotten.
   */
  const hash = window.location.hash.replace(/^#\//, '');
  const routes = NAVIGATION.map((entry) => entry.route);
  return routes.includes(hash as Route) ? (hash as Route) : 'dashboard';
}

/**
 * The SOLVAREN mark: two offset chevrons forming an upward path through a boundary.
 * Drawn inline so it costs no request and inherits the theme's accent colour.
 */
function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 32 32" role="img" aria-label="SOLVAREN">
      <rect x="1" y="1" width="30" height="30" rx="8" fill="var(--accent)" />
      <path
        d="M10 20.5 L16 12.5 L22 20.5"
        fill="none"
        stroke="var(--ink-inverse)"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M10 25 L22 25"
        stroke="var(--ink-inverse)"
        strokeWidth="2.4"
        strokeLinecap="round"
        opacity="0.55"
      />
    </svg>
  );
}

export { ApiError };
