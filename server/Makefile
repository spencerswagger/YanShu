GO ?= go

# 常用参数（可覆盖）：make deliver YSPK=/tmp/a.yspk BASE=http://127.0.0.1:8080
BASE ?= http://127.0.0.1:8080
YSPK ?=
EXTRA ?=

.PHONY: all build vet test run deliver fmt clean

all: vet test build

build:
	$(GO) build -o bin/yanshu-server ./cmd/yanshu-server
	$(GO) build -o bin/deliver ./cmd/deliver

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

# 需要 TEST_DATABASE_URL；没有时集成测试自动 skip。
test-integration:
	$(GO) test ./... -count=1

run:
	$(GO) run ./cmd/yanshu-server

# 一次完整投递（包必须由端侧工具产出）：
#   make deliver YSPK=/tmp/a.yspk BASE=http://127.0.0.1:18080 \
#     EXTRA="--no-ack --blob-dir /tmp/blobs --dsn $YANSHU_DATABASE_URL"
deliver:
	$(GO) run ./cmd/deliver --base-url $(BASE) --yspk $(YSPK) $(EXTRA)

fmt:
	gofmt -w ./cmd ./internal

clean:
	rm -rf bin
