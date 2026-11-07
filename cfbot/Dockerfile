FROM node:22.13-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY server.mjs ./
# The key volume mounts here; the image owns it so the node user can write its key.
RUN mkdir /data && chown node /data
USER node
CMD ["node", "server.mjs"]
