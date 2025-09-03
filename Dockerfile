# docker buildx build -t vault:latest --compress --load .

# Use a lightweight Nginx base image
FROM nginx:alpine

# Set working directory
WORKDIR /vault

# Copy application files into the container
COPY src /vault

# Copy custom Nginx configuration to override the default
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80 for HTTP traffic
EXPOSE 80

# Start Nginx in the foreground (required for Docker)
CMD ["nginx", "-g", "daemon off;"]
