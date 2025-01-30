# Dockerfile
FROM ubuntu:latest

# Install minimal packages
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /app

# Copy the prebuilt piece-server binary (GoReleaser will place it in the container build context)
COPY piece-server /usr/local/bin/piece-server

# Expose ports commonly used for HTTP (8080) and HTTPS (443)
EXPOSE 8080
EXPOSE 443

# By default, the container just runs `piece-server`—you can pass subcommands & flags at `docker run` time
ENTRYPOINT ["/usr/local/bin/piece-server"]
