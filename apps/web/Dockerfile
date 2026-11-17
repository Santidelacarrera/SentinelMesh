FROM node:22-alpine AS build
WORKDIR /repo
COPY package.json package-lock.json ./
COPY apps/web/package.json apps/web/
COPY apps/api/package.json apps/api/
RUN npm ci -w apps/web --include-workspace-root
COPY apps/web apps/web
RUN npm run build -w apps/web

FROM nginxinc/nginx-unprivileged:1.29-alpine
# the base image ships OS packages with known fixes: upgrade them, then drop back to the unprivileged user
USER root
RUN apk upgrade --no-cache
USER 101
COPY apps/web/nginx.conf /etc/nginx/templates/default.conf.template
ENV API_UPSTREAM=http://api:3000 NGINX_ENVSUBST_FILTER=API_
COPY --from=build /repo/apps/web/dist /usr/share/nginx/html
EXPOSE 8080
