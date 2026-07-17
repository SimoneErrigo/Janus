# syntax=docker/dockerfile:1.7

# The Vite bundle is architecture-independent. Build it on the native runner
# even when BuildKit is producing an arm64 final image, avoiding QEMU for Node.
FROM --platform=$BUILDPLATFORM node:22-alpine AS builder

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /build/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENV API_BACKEND=127.0.0.1
ENV API_BACKEND_PORT=9090
ENV FRONTEND_BIND=0.0.0.0
ENV FRONTEND_PORT=3000
ENV FRONTEND_ROOT=/usr/share/nginx/html

EXPOSE 3000
ENTRYPOINT ["/docker-entrypoint.sh"]
