FROM node:22-alpine

# better-sqlite3 needs build tools on alpine
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Install dependencies first (layer caching)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy application source
COPY src/ ./src/
COPY public/ ./public/

# Create data directory for SQLite
RUN mkdir -p /app/data

# Default environment
ENV NODE_ENV=production \
    CVG_PORT=3010 \
    CVG_DB_PATH=/app/data/cvg.db \
    CVG_ADMIN_USERNAME=admin \
    CVG_ADMIN_PASSWORD=admin

EXPOSE 3010

# Run as non-root
RUN addgroup -S cvg && adduser -S cvg -G cvg && chown -R cvg:cvg /app
USER cvg

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3010/api/v1/health || exit 1

CMD ["node", "src/server.js"]
