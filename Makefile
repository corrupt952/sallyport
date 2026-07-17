VERSION ?= 0.1.0
LDFLAGS ?= -ldflags "-s -w -X 'github.com/corrupt952/sallyport/command.Version=$(VERSION)'"

# HACK: make [target] [ARGS...]
ARGS = $(filter-out $@,$(MAKECMDGOALS))

# HACK: nothing undefined target
%:
	@:

all: run

run:
	go run $(LDFLAGS) . $(ARGS)

build:
	go build $(LDFLAGS) -o sallyport .

fmt:
	@go fmt ./...

test:
	@go test -race -count=1 ./...

lint:
	@golangci-lint run

clean:
	@rm -f sallyport

install: build
	@mv sallyport $(GOPATH)/bin/ || mv sallyport /usr/local/bin/

.PHONY: all run build fmt test lint clean install
