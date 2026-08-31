.PHONY: dev backend frontend test build

dev:
	go run ./cmd/server

backend:
	go build -buildvcs=false ./cmd/server

frontend:
	cd web && npm run build

test:
	go test ./...
	cd web && npm run build

build: frontend backend
