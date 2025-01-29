FROM golang:1.22.0-alpine3.19 AS builder

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
RUN CGO_ENABLED=0 GOOS=linux go build -o govir

FROM alpine:3.19

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/govir .

# Create config directory
RUN mkdir -p /app/config

ENTRYPOINT ["/app/govir"]