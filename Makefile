.PHONY: build test clean run

# Go parameters
BINARY_NAME=govir
MAIN_FILE=main.go

# Build the application
build:
	go build -v ./...

# Run the application
run:
	go run main.go $(ARGS)

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	go clean
	rm -f $(BINARY_NAME)

# Install dependencies
deps:
	go mod download

# Run linter
lint:
	go vet ./...

# All (build, test, and lint)
all: deps lint test build

# Build docker image
docker-build:
	docker build -t govir .