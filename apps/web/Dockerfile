# SOLVAREN console — static image.
#
# The API base URL is baked in at build time (Vite inlines import.meta.env), so
# VITE_API_BASE_URL must be supplied as a build argument, not a runtime variable. Railway
# passes it through from the service's build-time variables.

# ---- Build ------------------------------------------------------------------
FROM node:22-bookworm-slim AS build
WORKDIR /repo

RUN corepack enable

# pnpm refuses to remove a modules directory without a TTY, which makes the production
# prune below fail inside a container with:
#   ERR_PNPM_ABORTED_REMOVE_MODULES_DIR_NO_TTY
# CI=true is pnpm's documented non-interactive switch. Set once, before any install.
ENV CI=true

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY packages/core/package.json packages/core/
COPY packages/daraja/package.json packages/daraja/
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/

RUN pnpm install --frozen-lockfile --ignore-scripts

COPY tsconfig.base.json ./
COPY packages packages
COPY apps/web apps/web

ARG VITE_API_BASE_URL
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

RUN pnpm --filter @solvaren/web build

# ---- Runtime ----------------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

COPY --from=build /repo/apps/web/dist /usr/share/nginx/html
COPY apps/web/nginx.conf /etc/nginx/templates/default.conf.template

# nginx:alpine substitutes ${PORT} from the environment into the template at startup.
ENV PORT=8080
EXPOSE 8080
