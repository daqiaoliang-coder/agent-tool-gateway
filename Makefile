.PHONY: build run demo-backend fmt

build:
	go build -o bin/agent-tool-gateway ./cmd/gateway

run:
	go run ./cmd/gateway -config configs/gateway.example.json

demo-backend:
	go run ./cmd/demo-backend

fmt:
	gofmt -w cmd internal
