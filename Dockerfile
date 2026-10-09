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
# git is required to clone the target repository a hunt analyses.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY migrations ./migrations
EXPOSE 8080
USER node
CMD ["node", "dist/index.js"]
