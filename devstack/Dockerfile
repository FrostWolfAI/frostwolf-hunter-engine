# The dev control-plane: a local stand-in for the Cloudflare worker.
# node:sqlite is still behind a flag on Node 22, so the image pins 22 and runs with
# --experimental-sqlite. It needs no dependencies beyond the Node standard library.
FROM node:22-slim
WORKDIR /app
COPY devstack/dev-worker.mjs ./devstack/dev-worker.mjs
COPY migrations ./migrations
ENV MIGRATIONS_DIR=/app/migrations
EXPOSE 8787
CMD ["node", "--experimental-sqlite", "devstack/dev-worker.mjs"]
