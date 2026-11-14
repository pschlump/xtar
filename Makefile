GO ?= go

LINK_NAMES = tar gtar cpio zip unzip 7z 7za 7zr zipinfo

all: build

build:
	$(GO) build -o bin/xtar .

links: build
	cd bin && for n in $(LINK_NAMES); do ln -sf xtar $$n; done

test:
	$(GO) test ./... -count=1

race:
	$(GO) test -race -count=1 ./...

lint:
	golangci-lint run ./...

vet:
	$(GO) vet ./...

cover:
	$(GO) test ./... -coverprofile=cover.out -count=1

fmt:
	gofmt -l -w .

clean:
	rm -rf bin cover.out

.PHONY: all build links test race lint vet cover fmt clean
