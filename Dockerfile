FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN sh scripts/fetch-circuits.sh
ENV PORT=8080 DATA_DIR=/data
EXPOSE 8080
CMD ["node","src/server.js"]
