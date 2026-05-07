# ============================================================
# Stage 1 — Builder
# Install dependencies & build the Vite/React app
# ============================================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests first (layer cache optimization)
COPY package.json package-lock.json ./

# Install ALL dependencies (including devDeps needed for Vite build)
RUN npm ci --frozen-lockfile

# Copy full source code
COPY . .

# Pass GEMINI_API_KEY at build time via --build-arg
# (Vite bakes env vars into the bundle at build time)
ARG GEMINI_API_KEY=""
ENV GEMINI_API_KEY=${GEMINI_API_KEY}

RUN npm run build

# ============================================================
# Stage 2 — Production Server (Cloud Run compatible)
# Serve /dist with Nginx, listening on $PORT from Cloud Run
# ============================================================
FROM nginx:1.27-alpine AS production

# Install envsubst (included in gettext) for PORT substitution
RUN apk add --no-cache gettext

# Remove default Nginx placeholder page & config
RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/default.conf

# Copy built static files from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy Nginx config TEMPLATE — uses ${PORT} placeholder
# envsubst will replace it at container startup
COPY nginx.conf /etc/nginx/conf.d/default.conf.template

# Cloud Run injects PORT at runtime (default: 8080).
# We document 8080 here, but the actual value comes from $PORT.
EXPOSE 8080

# At startup: substitute ${PORT} in the template, then launch Nginx
CMD ["/bin/sh", "-c", \
  "envsubst '${PORT}' < /etc/nginx/conf.d/default.conf.template > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'"]
