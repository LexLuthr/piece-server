# 1st Stage: Build the Binary
FROM golang:1.22 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy only dependency files first to optimize caching
COPY go.mod go.sum ./
RUN go mod download

# Copy everything at once
COPY . .

# Build the Go binary
RUN go build -o piece-server ./main.go

# 2nd Stage: Create the Final Image
FROM ubuntu:latest

# Set the label for the source repository
LABEL org.opencontainers.image.source="https://github.com/lexluthr/piece-server"

# Install minimal packages
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/piece-server /usr/local/bin/piece-server

# Ensure the binary is executable
RUN chmod +x /usr/local/bin/piece-server


# Expose ports commonly used for HTTP (8080) and HTTPS (443)
EXPOSE 8080
EXPOSE 443

# By default, the container just runs `piece-server`—you can pass subcommands & flags at `docker run` time
ENTRYPOINT ["/usr/local/bin/piece-server"]
