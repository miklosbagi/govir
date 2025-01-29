.PHONY: build run test dockerize clean

# Go parameters
BINARY_NAME=govir
MAIN_FILE=main.go

# Build the application
build:
	go build -o $(BINARY_NAME) $(MAIN_FILE)

# Run the application
run: build
	./$(BINARY_NAME)

# Run tests
test:
	go test -v -race -cover ./...

# Build docker image
dockerize:
	docker-compose build

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