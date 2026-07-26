# Pin to an immutable patch tag rather than the moving node:24-alpine tag, so the
# internet-facing policy boundary is reproducible between rehearsal and delivery.
# For a security-teaching repo the stronger form is a digest pin
# (FROM node:24.4.1-alpine@sha256:<digest>); let Dependabot maintain the digest.
FROM node:24.4.1-alpine3.21

WORKDIR /app

ENV NODE_ENV=production

# Copy the manifest first so a lockfile-only change does not bust earlier layers.
COPY package.json package-lock.json ./
# The gateway has no runtime dependencies, so `npm ci` only verifies the lockfile
# is in sync. It is here so adding a dependency later cannot silently skip it.
RUN npm ci --omit=dev

COPY remove-netdefaultdb.mjs server.mjs ./

# The policy boundary and the root-privileged remove-netdefaultdb cleaner both run
# from this image. Neither needs root, and running the internet-facing process as
# UID 0 is the posture this gateway exists to avoid. node:*-alpine ships this user.
USER node

EXPOSE 8081

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=6 \
  CMD node -e "fetch('http://127.0.0.1:8081/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Compose sets `init: true` so a real init reaps zombies and forwards SIGTERM;
# without it node as PID 1 ignores SIGTERM and every `docker compose down` stalls
# 10s before SIGKILL.
CMD ["node", "server.mjs"]
