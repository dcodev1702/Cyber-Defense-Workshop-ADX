FROM node:24-alpine

WORKDIR /app
COPY package.json remove-netdefaultdb.mjs server.mjs ./

EXPOSE 8081
CMD ["node", "server.mjs"]