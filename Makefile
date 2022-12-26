APPNAME:=nginx-mail-auth-delegator
IMAGE_NAME:=nginx-mail-auth-delegator
RELEASE?=0
CGO_ENABLED?=0

DOCKER_CMD := $(shell command -v podman 2> /dev/null || echo docker)

ifeq ($(RELEASE), 1)
	# Strip debug information from the binary
	GO_LDFLAGS+=-s -w
endif
GO_LDFLAGS:=-ldflags="$(GO_LDFLAGS)"


.PHONY: default
default: coverage

.PHONY: build
build:
	CGO_ENABLED=$(CGO_ENABLED) go build $(GO_LDFLAGS) -o ./build/$(APPNAME) -v cmd/main.go

.PHONY: docker
docker:
	$(DOCKER_CMD) build -t $(IMAGE_NAME) .

.PHONY: test
test: build
	CGO_ENABLED=$(CGO_ENABLED) go test -v ./...

.PHONY: coverage
coverage: build
	CGO_ENABLED=$(CGO_ENABLED) go test -v ./... -coverprofile=build/coverage.out
	gcov2lcov -infile=build/coverage.out -outfile=build/coverage.lcov

.PHONY: clean
clean:
	rm -rf ./build