APP := promptzero
PKG := github.com/xunholy/promptzero
BIN := bin/$(APP)

GOFLAGS := -trimpath
LDFLAGS := -s -w

.PHONY: build run clean tidy lint

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/promptzero

run: build
	./$(BIN)

clean:
	rm -rf bin/

tidy:
	go mod tidy

lint:
	golangci-lint run ./...
