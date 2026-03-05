FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY build/ ./build/

ENTRYPOINT ["node", "build/index.js"]
