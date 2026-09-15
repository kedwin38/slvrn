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
import { NAV_ICONS, type IconProps } from './components/icons.js';
import { EnvironmentBadge } from './components/EnvironmentBadge.js';
import { AccountMenu } from './components/AccountMenu.js';
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
  /** Rendered only when the actor holds this capability. */
  requires?: string;
  group: 'Operations' | 'Administration' | 'Account';
}

const NAVIGATION: NavEntry[] = [
  { route: 'dashboard', label: 'Dashboard', group: 'Operations' },
  {
    route: 'batches',
    label: 'Payment batches',
    requires: 'batch:read',
    group: 'Operations',
  },
  {
    route: 'transactions',
    label: 'Transactions',
    requires: 'transactions:read',
    group: 'Operations',
  },
  {
    route: 'reconciliation',
    label: 'Reconciliation',
    requires: 'reconciliation:read',
    group: 'Operations',
  },
  {
    route: 'recipients',
    label: 'Recipients',
    requires: 'recipients:read',
    group: 'Operations',
  },
  {
    route: 'intelligence',
    label: 'Intelligence',
    requires: 'ai:batch_analysis',
    group: 'Operations',
  },
  {
    route: 'reports',
    label: 'Reports',
    requires: 'reports:operational',
    group: 'Operations',
  },
  {
    route: 'members',
    label: 'Members',
    requires: 'admin:users',
    group: 'Administration',
  },
  {
    route: 'daraja',
    label: 'M-PESA credentials',
    requires: 'admin:daraja',
    group: 'Administration',
  },
  {
    route: 'policy',
    label: 'Policy',
    requires: 'admin:policies',
    group: 'Administration',
  },
  {
    route: 'security-centre',
    label: 'Security centre',
    requires: 'admin:security',
    group: 'Administration',
  },
  {
    route: 'audit',
    label: 'Audit trail',
    requires: 'audit:read_org',
    group: 'Administration',
  },
  {
    route: 'backups',
    label: 'Backups',
    requires: 'admin:backups',
    group: 'Administration',
  },
  // Everyone has their own credentials to manage, so this carries no capability gate.
  { route: 'security', label: 'Security', group: 'Account' },
];

/*
 * Icons live in their own module, which cannot import Route from here without a cycle. This
 * annotation closes the loop from this side: adding a Route without drawing its icon fails
 * to type-check, so a route can never ship with a missing glyph.
 */
const ROUTE_ICONS: Record<Route, (props: IconProps) => JSX.Element> = NAV_ICONS;

function NavIcon({ route }: { route: Route }) {
  const Icon = ROUTE_ICONS[route];
  return <Icon />;
}

export function App() {
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [route, setRoute] = useState<Route>(readRoute());
  /*
   * The navigation drawer, on narrow viewports only.
   *
   * Below 900px the sidebar used to stack above the content, so opening the console on a
   * phone showed a full screen of menu and the operator scrolled past every route to reach
   * the dashboard. It is a drawer now: content first, navigation a tap away.
   */
  const [navOpen, setNavOpen] = useState(false);
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
    // Navigating is the drawer's whole purpose, so it closes itself on the way out.
    setNavOpen(false);
    // Move focus to the main region so a keyboard user is not left at the nav item they
    // just activated, hunting for where the page went.
    document.getElementById('main-content')?.focus();
  }, []);

  useEffect(() => {
    if (!navOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setNavOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navOpen]);

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
    <div className="shell" data-nav-open={navOpen ? 'true' : undefined}>
      {/* Catches the tap that means "not the menu, then". Inert on wide viewports. */}
      <button
        className="nav-scrim"
        type="button"
        tabIndex={-1}
        aria-hidden="true"
        onClick={() => setNavOpen(false)}
      />

      <nav className="sidebar" id="main-nav" aria-label="Main">
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
                    <NavIcon route={entry.route} />
                    {entry.label}
                  </button>
                ))}
              </div>
            );
          })}
        </div>

        {/*
          The organisation, at the foot of the nav. Who you are signed in AS now lives in
          the top bar with the sign-out, because identity and authority belong beside the
          environment badge — those three answer one question together: what can I do here,
          and does it move real money.
        */}
        <div className="sidebar-foot">
          <div className="org-name">{user.organizationSlug}</div>
          <div className="org-note">Payment control plane</div>
        </div>
      </nav>

      {/* Rendered once, above every route: any protected action can raise it. */}
      <StepUpGate />

      <div className="content">
        <header className="topbar">
          <button
            className="nav-toggle"
            type="button"
            aria-label={navOpen ? 'Close navigation' : 'Open navigation'}
            aria-expanded={navOpen}
            aria-controls="main-nav"
            onClick={() => setNavOpen((open) => !open)}
          >
            <MenuIcon open={navOpen} />
          </button>

          <div className="topbar-context">
            <span className="topbar-crumb">
              {visible.find((entry) => entry.route === route)?.group ?? 'Operations'}
            </span>
            <span className="topbar-sep" aria-hidden="true">
              /
            </span>
            <span className="topbar-page">
              {visible.find((entry) => entry.route === route)?.label ?? 'Dashboard'}
            </span>
          </div>

          <div className="topbar-actions">
            <EnvironmentBadge deployment={session.deployment} />
            <AccountMenu
              fullName={user.fullName}
              levelTitle={LEVEL_TITLES[user.level]}
              email={user.email}
              onSignOut={signOut}
            />
          </div>
        </header>

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
          {route === 'reports' && <ReportsPage user={session.user} />}
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

/** Three rules, or a cross when the drawer is open — the state, not just the affordance. */
function MenuIcon({ open }: { open: boolean }) {
  return (
    <svg className="icon" width={20} height={20} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      {open ? (
        <path
          d="M6 6 L18 18 M18 6 L6 18"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
        />
      ) : (
        <path
          d="M4 7h16M4 12h16M4 17h16"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
        />
      )}
    </svg>
  );
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
