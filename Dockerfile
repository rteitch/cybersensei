# ============================================================
# Stage 1 — Builder
# Install dependencies & build core, web (Vite), and bot
# ============================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests first (layer cache optimization)
COPY package.json package-lock.json ./
COPY core/package.json ./core/
COPY apps/web/package.json ./apps/web/
COPY apps/bot/package.json ./apps/bot/

# Install ALL dependencies (including devDeps needed for Vite & TS builds)
RUN npm ci

# Copy full source code
COPY . .

# Pass GEMINI_API_KEY at build time via --build-arg for Vite frontend
ARG GEMINI_API_KEY=""
ENV GEMINI_API_KEY=${GEMINI_API_KEY}

# Build all workspaces (core -> web -> bot)
RUN npm run build

# ============================================================
# Stage 2 — Production Server (Cloud Run compatible)
# Runs the Node.js Express server which serves API, Bot, and Web
# ============================================================
FROM node:20-alpine AS production

WORKDIR /app

ENV NODE_ENV=production

# Copy root configs
COPY package.json package-lock.json ./

# Copy workspace configs
COPY core/package.json ./core/
COPY apps/web/package.json ./apps/web/
COPY apps/bot/package.json ./apps/bot/

# Install ONLY production dependencies across the monorepo
RUN npm ci --omit=dev

# Copy compiled core
COPY --from=builder /app/core/dist ./core/dist

# Copy compiled bot
COPY --from=builder /app/apps/bot/dist ./apps/bot/dist

# Copy compiled web frontend into bot's expected public directory
# (bot's server.ts uses path.join(__dirname, '..', 'public'))
COPY --from=builder /app/apps/web/dist ./apps/bot/public

# Expose port (Cloud Run sets PORT env var, defaults to 8080)
EXPOSE 8080

# Start the Node.js app directly
CMD ["node", "apps/bot/dist/server.js"]
