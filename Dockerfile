FROM node:20-alpine

# Install basic networking tools if needed for any diagnostics (optional)
RUN apk update && apk add --no-cache openssh-client

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy application files
COPY server.js ./
COPY import-existing.js ./
COPY public/ ./public/
COPY ssh-export/ ./ssh-export/

# Expose server port
EXPOSE 3000

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000

# Start server
CMD ["node", "server.js"]
