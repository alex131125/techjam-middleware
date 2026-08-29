ARG NODE_IMAGE=node:22-bookworm-slim
FROM ${NODE_IMAGE} AS build
WORKDIR /app

COPY package.json package-lock.json tsconfig.base.json ./
COPY apps/server/package.json apps/server/package.json
COPY apps/web/package.json apps/web/package.json
RUN npm ci

COPY apps ./apps
RUN npm run build
RUN npm prune --omit=dev

FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production
WORKDIR /app

ARG DEBIAN_MIRROR=""
ARG DEBIAN_SECURITY_MIRROR=""
# Client only. Needed solely by RUNTIME_PROVIDER=container, where the control plane asks
# the host engine to launch a sibling Runtime container over the mounted socket.
ARG DOCKER_CLI_VERSION=27.5.1
ARG INSTALL_DOCKER_CLI=true

RUN if [ -n "$DEBIAN_SECURITY_MIRROR" ]; then \
      find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) \
        -exec sed -i "s|http://deb.debian.org/debian-security|$DEBIAN_SECURITY_MIRROR|g" {} +; \
    fi \
    && if [ -n "$DEBIAN_MIRROR" ]; then \
      find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) \
        -exec sed -i "s|http://deb.debian.org/debian|$DEBIAN_MIRROR|g" {} +; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git ripgrep \
    && apt-get install -y --no-install-recommends curl \
    && npm install --global @openai/codex@0.111.0 \
    && codex --version \
    && if [ "$INSTALL_DOCKER_CLI" = "true" ]; then \
         arch="$(uname -m)"; \
         case "$arch" in x86_64) dl=x86_64 ;; aarch64|arm64) dl=aarch64 ;; *) dl="" ;; esac; \
         if [ -n "$dl" ]; then \
           curl -fsSL "https://download.docker.com/linux/static/stable/${dl}/docker-${DOCKER_CLI_VERSION}.tgz" \
             -o /tmp/docker.tgz \
           && tar -xzf /tmp/docker.tgz -C /tmp docker/docker \
           && install -m 0755 /tmp/docker/docker /usr/local/bin/docker \
           && rm -rf /tmp/docker /tmp/docker.tgz \
           && docker --version; \
         fi; \
       fi \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/apps/server/package.json ./apps/server/package.json
COPY --from=build /app/apps/server/dist ./apps/server/dist
COPY --from=build /app/apps/web/dist ./apps/web/dist

RUN mkdir -p /app/data /app/workspaces /app/codex-home \
    && chown -R node:node /app

USER node
EXPOSE 3000
HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "apps/server/dist/index.js"]
