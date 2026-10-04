FROM node:22-alpine
WORKDIR /app
COPY package.json server.mjs ./
RUN mkdir /app/data && chown node:node /app/data
USER node
EXPOSE 8080
CMD ["node", "server.mjs"]
