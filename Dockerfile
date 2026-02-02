# ===============================
# Stage 1: Build the Go binary
# ===============================
FROM golang:1.25-alpine AS builder

# Install git (needed for go modules), ca-certificates & tzdata
RUN apk add --no-cache git ca-certificates tzdata && update-ca-certificates

# Set working directory inside container
WORKDIR /app

# Copy go.mod and go.sum first (for dependency caching)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the entire project
COPY . .

# Build the binary for Linux
RUN CGO_ENABLED=0 GOOS=linux go build -o secureapi ./cmd/api/main.go

# ===============================
# Stage 2: Create minimal image
# ===============================
FROM alpine:latest

# Set timezone & install ca-certificates
RUN apk add --no-cache ca-certificates tzdata && update-ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/secureapi .

# Copy .env (optional, if you want env in container)
COPY .env .

# Expose port used by Gin
EXPOSE 8080

# Run the binary
CMD ["./secureapi"]
