# DMARC Report Analyzer
# Small Express app; no build step, so a single stage keeps it simple.
FROM node:24-alpine

# tini: correct signal handling so `docker stop` exits promptly rather than
#       waiting out the 10s kill timeout.
# openssl: used to generate a self-signed certificate when TLS_ENABLED=true.
RUN apk add --no-cache tini openssl

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/data

WORKDIR /app

# Copy manifests first so `npm ci` is cached until dependencies actually change.
# better-sqlite3 13+ ships its N-API binaries inside the npm package, including
# Alpine (musl) for amd64 and arm64, so nothing needs compiling. The package still
# carries a binding.gyp, and `npm ci` (unlike `npm install`) ignores its
# "gypfile": false and tries node-gyp anyway; --ignore-scripts stops that. No
# dependency of this app has an install script, so nothing else is lost.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# Baked in by the workflow so the footer can say which build is running. Placed after
# the dependency layer: an ENV changes the cache key of every later step, and these
# change on every commit.
ARG GIT_SHA=""
ARG BUILD_DATE=""
ENV APP_COMMIT=$GIT_SHA \
    APP_BUILD_DATE=$BUILD_DATE

# Every top-level module, so a new file cannot be left out of the image by mistake
# (test/ is a directory and does not match the glob).
COPY *.js ./
COPY public ./public
COPY examples ./examples

# Fail the build, not the first container start, if a module is missing:
# server.js only listens when it is the main module, so requiring it just
# resolves the whole dependency graph. A throwaway DATA_DIR keeps the check from
# leaving a database or key material in the image.
RUN DATA_DIR=/tmp/smoke node -e "require('./server.js')" && rm -rf /tmp/smoke

# The image ships no data; /data is a volume that outlives the container. The app
# only reads /app, so it stays root-owned (a chown of node_modules would copy every
# file into one more layer).
# node:alpine already provides an unprivileged `node` user (uid 1000).
RUN mkdir -p /data && chown node:node /data

USER node
EXPOSE 3000
VOLUME ["/data"]

# Probes /api/auth/me: it is the one endpoint that answers 200 whether or not
# anyone is signed in, so the check reflects "Express is serving", not "logged in".
# Follows the app's own scheme, and skips verification because a self-signed
# certificate is expected here.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "const tls=(process.env.TLS_ENABLED||'').toLowerCase()==='true'||!!process.env.TLS_CERT;require(tls?'https':'http').get({host:'127.0.0.1',port:process.env.PORT||3000,path:'/api/auth/me',timeout:4000,rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on('timeout',()=>process.exit(1)).on('error',()=>process.exit(1))"

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]
