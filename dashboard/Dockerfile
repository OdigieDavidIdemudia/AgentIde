FROM node:22-alpine

WORKDIR /app

# Install deps first (layer caching)
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Build the React UI
RUN npm run build

EXPOSE 8443

# Generate dev TLS certs, migrate the DB, then start the server.
# PGHOST etc. come from the environment (docker-compose env_file).
CMD ["sh", "-c", "npm run cert:generate && npm run db:migrate && npm start"]
