FROM node:24-alpine AS frontend
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.24-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/internal/webui/dist ./internal/webui/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dnstrike ./cmd/server

FROM alpine:3.22
RUN addgroup -S dnstrike && adduser -S -G dnstrike dnstrike
WORKDIR /app
COPY --from=backend /out/dnstrike /usr/local/bin/dnstrike
RUN mkdir -p /app/data /app/reports && chown -R dnstrike:dnstrike /app
USER dnstrike
ENV DNSTRIKE_ADDR=0.0.0.0:8080 DNSTRIKE_DATA_DIR=/app/data
EXPOSE 8080
VOLUME ["/app/data", "/app/reports"]
ENTRYPOINT ["dnstrike"]
