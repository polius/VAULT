# syntax=docker/dockerfile:1
# docker buildx build -t vault:latest --load .

# Unprivileged nginx: runs as uid 101 and listens on 8080. Pinned by digest;
# Dependabot bumps the tag and digest together.
FROM nginxinc/nginx-unprivileged:1.29.8-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY src /vault

# Readable by the nginx user whatever the host umask was. Nothing is writable:
# the container can also run with --read-only (nginx then needs a tmpfs on /tmp).
USER root
RUN chmod -R a+rX,go-w /vault /etc/nginx/conf.d/default.conf
USER 101

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD wget -qO /dev/null http://127.0.0.1:8080/ || exit 1
