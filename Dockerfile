FROM node:22-alpine
WORKDIR /app
COPY package.json server.mjs start.mjs admin.mjs pw-auth.mjs ./
COPY public ./public
RUN mkdir /app/data && chown node:node /app/data
USER node
EXPOSE 8080
CMD ["node", "start.mjs"]
