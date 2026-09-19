# docker buildx build -t vault:latest --compress --load .

# Use a lightweight Nginx base image
FROM nginx:alpine

# Set working directory
WORKDIR /vault

# Copy application files into the container, normalizing permissions so the
# non-root nginx worker can always read them regardless of the host's umask.
COPY src /vault
RUN chmod -R a+rX /vault

# Copy custom Nginx configuration to override the default
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80 for HTTP traffic
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1/ >/dev/null 2>&1 || exit 1

# Start Nginx in the foreground (required for Docker)
CMD ["nginx", "-g", "daemon off;"]
