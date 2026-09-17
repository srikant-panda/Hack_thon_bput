# Build stage: compile the Vite SPA with VITE_* vars baked in at build time.
FROM node:20-alpine AS build
WORKDIR /app

# VITE_API_BASE_URL stays relative ("/api/v1"): the browser calls the same
# origin it loaded the page from, and nginx proxies /api/* to the backend.
ARG VITE_API_BASE_URL=/api/v1
ARG VITE_SUPABASE_URL=https://YOUR-PROJECT.supabase.co
ARG VITE_SUPABASE_ANON_KEY=your-anon-key
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL \
    VITE_SUPABASE_URL=$VITE_SUPABASE_URL \
    VITE_SUPABASE_ANON_KEY=$VITE_SUPABASE_ANON_KEY

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Serve stage: Nginx — serves the SPA at / and reverse-proxies /api/*.
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
