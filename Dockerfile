FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN go build -o govir

FROM alpine:latest

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/govir .

# Create config directory
RUN mkdir -p /app/config

ENTRYPOINT ["./govir"]