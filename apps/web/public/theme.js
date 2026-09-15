/*
 * Apply the stored colour theme before the first paint.
 *
 * This is a separate file loaded synchronously from <head>, rather than an inline script,
 * because the console ships `script-src 'self'` with no 'unsafe-inline'. The usual
 * anti-flash trick is an inline <script>, and taking it would mean adding 'unsafe-inline'
 * to the script policy of a payment authorization console to save a frame of white. A file
 * the same origin already serves costs one cached request and weakens nothing.
 *
 * It must stay synchronous and stay in <head>: deferred, or moved after the body, the
 * document paints in the system theme first and then flips, which is precisely the flash
 * this exists to prevent.
 *
 * Kept deliberately small and dependency-free — it runs before the bundle, so nothing it
 * needs exists yet. The matching TypeScript lives in src/lib/theme.ts; STORAGE_KEY is
 * duplicated there because these two cannot import from each other.
 */
(function () {
  try {
    var stored = localStorage.getItem('solvaren.theme');
    if (stored === 'dark' || stored === 'light') {
      document.documentElement.setAttribute('data-theme', stored);
    }
  } catch {
    /*
     * localStorage throws outright in a private window with site data blocked, not merely
     * returning null. Swallowing it means the reader gets their system theme, which is the
     * correct fallback; letting it throw would abort the script and, being synchronous in
     * <head>, is not worth risking for a preference.
     */
  }
})();
