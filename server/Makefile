GO ?= go

.PHONY: all build vet test test-integration run fmt clean

all: vet test build

build:
	$(GO) build -o bin/yanshu-server ./cmd/yanshu-server

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

# 需要 TEST_DATABASE_URL；没有时集成测试自动 skip。
test-integration:
	$(GO) test ./... -count=1

run:
	$(GO) run ./cmd/yanshu-server

fmt:
	gofmt -w ./cmd ./internal

clean:
	rm -rf bin
