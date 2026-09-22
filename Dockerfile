# DMARC Report Analyzer
# Small Express app; no build step, so a single stage keeps it simple.
FROM node:22-alpine

# tini: correct signal handling so `docker stop` exits promptly rather than
#       waiting out the 10s kill timeout.
# openssl: used to generate a self-signed certificate when TLS_ENABLED=true.
RUN apk add --no-cache tini openssl

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/data

WORKDIR /app

# Copy manifests first so `npm ci` is cached until dependencies actually change.
# better-sqlite3 ships prebuilt binaries for Alpine (musl); if a future version
# ever has to compile from source, add `apk add --no-cache python3 make g++`
# before this step (and remove it afterwards to keep the image small).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY server.js auth.js auth-routes.js tls-setup.js db.js graph.js dmarc-parser.js sync.js ./
COPY public ./public
COPY examples ./examples

# The image ships no data; /data is a volume that outlives the container.
# node:alpine already provides an unprivileged `node` user (uid 1000).
RUN mkdir -p /data && chown -R node:node /data /app

USER node
EXPOSE 3000
VOLUME ["/data"]

# Probes /api/auth/me: it is the one endpoint that answers 200 whether or not
# anyone is signed in, so the check reflects "Express is serving", not "logged in".
# Follows the app's own scheme, and skips verification because a self-signed
# certificate is expected here.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "const tls=(process.env.TLS_ENABLED||'').toLowerCase()==='true'||!!process.env.TLS_CERT;require(tls?'https':'http').get({host:'127.0.0.1',port:process.env.PORT||3000,path:'/api/auth/me',timeout:4000,rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]
