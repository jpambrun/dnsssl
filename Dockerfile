FROM node:16
ENV NODE_ENV=production
WORKDIR /app
COPY ["package.json", "package-lock.json*", "./"]
RUN npm install
COPY ["index.mjs", "./"]
CMD [ "node", "index.mjs" ]
