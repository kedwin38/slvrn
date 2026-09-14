import { defineConfig, loadEnv, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

/**
 * Resolve the API base URL and reconcile the Content-Security-Policy with it.
 *
 * Two failures made this necessary, and both shipped a console that looked fine and could
 * not sign anybody in:
 *
 *  1. `VITE_API_BASE_URL` is inlined by Vite at build time. When it was absent the client
 *     quietly fell back to the console's own origin, so every API call was answered by the
 *     static file server with `index.html` or a 405. Nothing failed until a person tried to
 *     log in, and the error they got named neither cause.
 *
 *  2. `index.html` pinned `connect-src` to `'self'`. Under Cloudflare Pages the console and
 *     the API shared an origin, so that was correct. On Railway they are two services on two
 *     domains, and `'self'` blocks every request before it reaches the network — `fetch`
 *     rejects, and the console can only report a generic "could not reach" message because
 *     from its side that is all that is observable.
 *
 * So the build now refuses to produce a bundle it cannot configure, and derives the one
 * cross-origin connection the policy needs from the address it was given. The CSP stays
 * closed by default: exactly one origin is added, and only because it was configured.
 */
function apiOriginPlugin(apiBaseUrl: string): Plugin {
  return {
    name: 'solvaren-api-origin-csp',
    transformIndexHtml(html) {
      // A relative base (for example "/api" behind a shared domain) is already covered by
      // 'self'; widening the policy for it would be strictly worse than leaving it alone.
      if (!/^https?:\/\//i.test(apiBaseUrl)) return html;

      const origin = new URL(apiBaseUrl).origin;

      /*
       * Match the policy inside the <meta> element itself, never a bare `connect-src 'self'`
       * anywhere in the file. The prose above the element quotes the directive, and a plain
       * string replace rewrites that comment instead — producing a build that looks correct,
       * documents itself wrongly, and still cannot call the API.
       */
      // The attribute delimiter is a double quote; the policy itself is full of single
      // quotes ('self', 'none'), so a delimiter class of ["'] terminates on the first
      // keyword rather than the end of the attribute.
      const policy = /(<meta\b[^>]*http-equiv="Content-Security-Policy"[^>]*content=")([^"]*)(")/i;

      const match = html.match(policy);
      if (!match) {
        throw new Error(
          'apps/web/index.html has no <meta http-equiv="Content-Security-Policy"> element, so ' +
            'the API origin cannot be added to connect-src. Refusing to build a console that ' +
            'would be blocked from reaching the API.',
        );
      }
      if (!match[2].includes("connect-src 'self'")) {
        throw new Error(
          `The Content-Security-Policy in apps/web/index.html no longer contains "connect-src ` +
            `'self'" (found: ${match[2]}). apps/web/vite.config.ts must be updated to match it, ` +
            'or the console will build and then be unable to reach the API.',
        );
      }

      return html.replace(
        policy,
        (_full, open: string, content: string, close: string) =>
          open + content.replace("connect-src 'self'", `connect-src 'self' ${origin}`) + close,
      );
    },
  };
}

export default defineConfig(({ command, mode }) => {
  const root = fileURLToPath(new URL('.', import.meta.url));
  const apiBaseUrl = loadEnv(mode, root, 'VITE_').VITE_API_BASE_URL?.trim() ?? '';

  // `vite dev` serves the console and proxies or shares an origin, so it is allowed to run
  // unconfigured. A production bundle is not: it is the artefact that gets deployed, and an
  // unconfigured one is broken in a way that only shows up in front of a user.
  if (command === 'build' && !apiBaseUrl) {
    throw new Error(
      [
        '',
        'VITE_API_BASE_URL is not set, so this build would produce a console that cannot',
        'reach the API.',
        '',
        'Vite inlines this value at BUILD time, so it must be present now — setting it on',
        'the running container has no effect, and neither does restarting the service. It',
        'must be a build variable, and changing it requires a rebuild.',
        '',
        '  Railway:  VITE_API_BASE_URL = https://${{solvaren-api.RAILWAY_PUBLIC_DOMAIN}}',
        '  Docker:   --build-arg VITE_API_BASE_URL=https://api.example.com',
        '  Local:    VITE_API_BASE_URL=http://localhost:8787 pnpm --filter @solvaren/web build',
        '',
      ].join('\n'),
    );
  }

  return {
    plugins: [react(), apiOriginPlugin(apiBaseUrl)],
    resolve: {
      alias: {
        '@solvaren/core': fileURLToPath(
          new URL('../../packages/core/src/index.ts', import.meta.url),
        ),
      },
    },
    build: {
      target: 'es2022',
      // A payment console is used on office machines and phones on the move; a large bundle
      // is a real cost on the latter, so the budget is enforced rather than aspirational.
      chunkSizeWarningLimit: 400,
      rollupOptions: {
        output: {
          manualChunks: {
            react: ['react', 'react-dom'],
          },
        },
      },
    },
    server: { port: 5173 },
  };
});
