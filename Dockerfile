# Hunter: one Node service. Each hunt runs in its own sandboxed child process
# (empty environment, Node permission model, no spawn, no writes), so this image
# is the whole deploy. The container is the outer boundary; the child is the inner.

FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
# git is required to clone the target repository a hunt analyses. The docker CLI
# is required by the `bash` tool (src/sandbox-exec.ts) when SANDBOX_RUNTIME=docker:
# it execs `docker` to run each command in its own disposable, locked-down
# container. The binary alone grants nothing — it still needs a daemon to talk to.
# That daemon is normally the host's, reached by mounting /var/run/docker.sock into
# this container at `docker run` time, which is a deliberate operator decision: it
# hands this container the ability to ask the host's Docker daemon to do anything,
# including starting a container that mounts the host's own filesystem. Do that
# only on infrastructure where this image's own compromise is an acceptable risk
# to the host, and never set SANDBOX_RUNTIME=docker without it (the runner falls
# back to "bash is unavailable" when the daemon can't be reached).
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY migrations ./migrations
EXPOSE 8080
USER node
CMD ["node", "dist/index.js"]
