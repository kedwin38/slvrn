# SOLVAREN API — production image.
#
# Multi-stage, so the runtime image carries no compiler, no test suite and no dev
# dependencies. The build stage needs the whole workspace because the API depends on
# @solvaren/core and @solvaren/daraja by workspace reference; both are built to their own
# dist and resolved through node_modules at runtime.

# ---- Build ------------------------------------------------------------------
FROM node:22-bookworm-slim AS build
WORKDIR /repo

RUN corepack enable

# Manifests first, so editing source does not invalidate the dependency layer.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY packages/core/package.json packages/core/
COPY packages/daraja/package.json packages/daraja/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/

RUN pnpm install --frozen-lockfile --ignore-scripts

COPY tsconfig.base.json ./
COPY packages packages
COPY apps/api apps/api

# Order matters: the API compiles against the packages' declared types, and at runtime
# resolves their dist.
RUN pnpm --filter @solvaren/core build \
 && pnpm --filter @solvaren/daraja build \
 && pnpm --filter @solvaren/api build

# Prune to production dependencies. The build tree carries TypeScript and vitest; none of
# it belongs in a running payment service.
RUN pnpm install --frozen-lockfile --prod --ignore-scripts

# ---- Runtime ----------------------------------------------------------------
FROM node:22-bookworm-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production

# Run as a non-root user: a process that cannot write to its own image cannot be made to
# persist anything by an attacker who reaches code execution.
RUN useradd --system --uid 10001 --home /app solvaren

# The workspace layout is preserved so the node_modules symlinks to @solvaren/* resolve.
COPY --from=build /repo/node_modules ./node_modules
COPY --from=build /repo/package.json ./package.json
COPY --from=build /repo/pnpm-workspace.yaml ./pnpm-workspace.yaml

COPY --from=build /repo/packages/core/package.json ./packages/core/package.json
COPY --from=build /repo/packages/core/dist ./packages/core/dist
COPY --from=build /repo/packages/core/node_modules ./packages/core/node_modules

COPY --from=build /repo/packages/daraja/package.json ./packages/daraja/package.json
COPY --from=build /repo/packages/daraja/dist ./packages/daraja/dist
COPY --from=build /repo/packages/daraja/node_modules ./packages/daraja/node_modules

COPY --from=build /repo/apps/api/package.json ./apps/api/package.json
COPY --from=build /repo/apps/api/dist ./apps/api/dist
COPY --from=build /repo/apps/api/node_modules ./apps/api/node_modules

# Migrations travel with the image so the pre-deploy command can apply them.
COPY db/migrations ./db/migrations
COPY scripts/migrate.mjs ./scripts/migrate.mjs

USER solvaren

EXPOSE 8080

CMD ["node", "--enable-source-maps", "apps/api/dist/server.js"]
