/**
 * The reader's colour theme.
 *
 * Three states, not two. "Dark" and "light" are explicit choices that follow the account
 * across sessions; "system" defers to the operating system and keeps deferring, so a
 * console left on system switches with the machine at dusk without anybody touching it.
 * A two-state toggle cannot express that, and defaulting everyone to an explicit choice
 * would freeze the theme for the majority who never open the menu and are best served by
 * following their machine.
 *
 * The stylesheet already understood all three: `prefers-color-scheme` under a
 * `:root:not([data-theme='light'])` guard, plus explicit `[data-theme]` blocks in both
 * directions. All that was missing was a way to say which one you wanted. This module is
 * that, and the attribute it sets is the same one the stylesheet has always read.
 *
 * public/theme.js applies the stored value before the first paint. This module owns every
 * change after that.
 */

export type ThemePreference = 'system' | 'light' | 'dark';

/** Duplicated in public/theme.js, which runs before the bundle and cannot import from here. */
const STORAGE_KEY = 'solvaren.theme';

/** The ground colour of each theme, for the browser chrome on a phone. */
const THEME_COLOR: Record<'light' | 'dark', string> = {
  light: '#f7f8fa',
  dark: '#141a24',
};

const listeners = new Set<(preference: ThemePreference) => void>();
let current: ThemePreference = readStored();

function readStored(): ThemePreference {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === 'dark' || stored === 'light' ? stored : 'system';
  } catch {
    // Private browsing with site data blocked throws rather than returning null. The
    // reader still gets a working console on their system theme; they just cannot persist
    // a change, which is the browser's decision to make and not ours to work around.
    return 'system';
  }
}

export function getTheme(): ThemePreference {
  return current;
}

/** Which theme is actually on screen right now, resolving 'system' against the OS. */
export function resolvedTheme(): 'light' | 'dark' {
  if (current !== 'system') return current;
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function setTheme(preference: ThemePreference): void {
  current = preference;
  apply(preference);
  try {
    if (preference === 'system') localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, preference);
  } catch {
    // As above: the choice still applies to this tab, it simply will not outlive it.
  }
  for (const listener of listeners) listener(preference);
}

export function subscribeToTheme(listener: (preference: ThemePreference) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function apply(preference: ThemePreference): void {
  const root = document.documentElement;
  if (preference === 'system') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', preference);
  applyThemeColor(preference);
}

/*
 * Keep the phone's browser chrome in step with the console.
 *
 * index.html carries two media-scoped theme-color tags so the chrome is right before any
 * script runs. Those keep following the OS, so on an explicit choice the address bar ends
 * up the opposite colour to the page — which is very visible on a phone and looks like a
 * rendering fault rather than a preference.
 *
 * A non-media theme-color matches unconditionally, and the browser takes the FIRST tag
 * whose media matches, so this one is inserted at the top of <head> to win over both. On a
 * return to system it is removed and the originals take over again.
 */
function applyThemeColor(preference: ThemePreference): void {
  const existing = document.head.querySelector<HTMLMetaElement>('meta[data-theme-managed]');
  if (preference === 'system') {
    existing?.remove();
    return;
  }
  const meta = existing ?? document.createElement('meta');
  meta.setAttribute('name', 'theme-color');
  meta.setAttribute('data-theme-managed', '');
  meta.setAttribute('content', THEME_COLOR[preference]);
  if (!existing) document.head.prepend(meta);
}

/**
 * Start the theme and keep it current.
 *
 * Called once from the entry point. The stored value is already on the element courtesy of
 * public/theme.js; this re-applies it so the theme-color tag is set too, and then listens
 * for the OS changing underneath a reader who chose 'system'.
 */
export function initTheme(): void {
  apply(current);

  const query = window.matchMedia?.('(prefers-color-scheme: dark)');
  if (!query) return;
  // The stylesheet reacts to the media query on its own; this notifies subscribers so the
  // menu's own "System" row reports what is actually on screen.
  query.addEventListener('change', () => {
    if (current !== 'system') return;
    for (const listener of listeners) listener(current);
  });
}
