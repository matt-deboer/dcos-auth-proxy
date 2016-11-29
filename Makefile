VERSION  := $$(git describe --tags --always)
TARGET   := $$(basename `git rev-parse --show-toplevel`)
TEST     ?= ./...

default: test build

test:
	go test -v -run=$(RUN) $(TEST)

build: clean
	go build -v -o bin/$(TARGET)

release: clean
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build \
		-a -tags netgo \
    -ldflags "-X main.Version=$(VERSION) -X main.Name=$(TARGET)" \
		-o bin/$(TARGET) .
	docker build -t gettyimages/$(TARGET):$(VERSION) .

clean:
	rm -rf bin/