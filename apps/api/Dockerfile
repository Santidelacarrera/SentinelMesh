FROM node:22-alpine AS build
WORKDIR /repo
COPY package.json package-lock.json ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
RUN npm ci -w apps/api --include-workspace-root
COPY apps/api apps/api
RUN npm run build -w apps/api
FROM node:22-alpine
WORKDIR /repo
ENV NODE_ENV=production
COPY package.json package-lock.json ./
COPY apps/api/package.json apps/api/
RUN npm ci -w apps/api --include-workspace-root --omit=dev
COPY --from=build /repo/apps/api/dist apps/api/dist
USER node
CMD ["node", "apps/api/dist/main.js"]
