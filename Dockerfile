FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o govir ./cmd/govir

FROM alpine:latest

WORKDIR /app

# Add labels
LABEL Name="govir" \
      Version="1.0.0" \
      Description="VirusTotal CLI Scanner"

# Copy binary from builder
COPY --from=builder /app/govir .

ENTRYPOINT ["/app/govir"]