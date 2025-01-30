# Documentation for "piece-server" 

## Overview
The `piece-server` program is designed to run as an HTTP or HTTPS server to serve file information. This server allows scanning directories and can share information about the available files.

The program processes the directories independently for scanning and protects shared data using mutex locks to prevent race conditions. The program also supports user validation through an `htpasswd` file and basic authentication when the secure mode is enabled.

You can interact with the server remotely using commands to add and remove directories that should be scanned. The file information and actual file contents can then be accessed using specific routes.

## Installation

### 1. Pre-built Binaries (Recommended)
Pre-built binaries for Linux and macOS are available on the [GitHub Releases](https://github.com/LexLuthr/piece-server/releases) page.

1. Download the latest binary for your OS.
2. Extract the `.tar.gz` file:
   ```sh
   tar -xvzf piece-server_<version>_<os>_<arch>.tar.gz
   ```
3. Move the binary to a directory in your `PATH`, e.g., `/usr/local/bin/`:
   ```sh
   mv piece-server /usr/local/bin/
   chmod +x /usr/local/bin/piece-server
   ```
4. Verify installation:
   ```sh
   piece-server --help
   ```

### 2. Docker (Containerized Deployment)
If you prefer running `piece-server` in a container, use the official Docker image:

```sh
docker pull ghcr.io/LexLuthr/piece-server:latest
```

To run the server on port 8080, mounting a directory for file access:

```sh
docker run -p 8080:8080 \
  -v /path/to/data:/data \
  ghcr.io/LexLuthr/piece-server:latest run --dir /data --port 8080
```

For secure mode (HTTPS), mount TLS certificates:

```sh
docker run -p 443:443 \
  -v /path/to/data:/data \
  -v /path/to/cert.pem:/cert.pem \
  -v /path/to/key.pem:/key.pem \
  ghcr.io/LexLuthr/piece-server:latest run --dir /data --port 443 --secure --cert /cert.pem --key /key.pem
```

### 3. Install via Go (Manual Build)
Ensure Go is installed on your machine:

```sh
go version
```

Install directly using Go:

```sh
go install github.com/LexLuthr/piece-server@latest
```

Alternatively, build manually from source:

```sh
git clone https://github.com/LexLuthr/piece-server.git
cd piece-server
go build -o piece-server main.go
./piece-server --help
```

## Usage
Run the piece-server program using the following syntax:

- To start the server in HTTP mode:

    ```shell
    ./piece-server run --dir="/path/to/dir"
    ```

- To start the server in HTTPS mode:

    ```shell
    ./piece-server run --dir="/path/to/dir" --cert="path/to/cert.pem" --key="path/to/key.pem" --secure --htpasswd="path/to/htpasswd"
    ```


- The flags used are:

    ```text
    --dir: specify the directory to scan initially.
    --port: (optional) specify port for the server (default is 8080).
    --bind: (optional) specify bind address for the server (default is 0.0.0.0).
    --cert: path to the TLS certificate file (required for secure mode).
    --key: path to the TLS key file (required for secure mode).
    --htpasswd: path to the htpasswd file for user authentication (required for secure mode).
    --secure: enable secure mode (HTTPS and Basic Auth)
    ```

- You can manage directories remotely using the following syntax:
  - To add a directory:
    ```shell
    ./main manage add --url="http://localhost:8080" --dir="/path/to/dir" --username="username" --password="password"
    ```

  - To remove a directory:
    ```shell
    ./main manage remove --url="http://localhost:8080" --dir="/path/to/dir" --username="username" --password="password"
    ```

    
## Basic Authentication in Secure Mode
If the server runs in secure mode (--secure), you need to use Basic Authentication for each request. Basic Authentication requires sending a header that includes base64 encoded username and password.
Here is a simple way to generate it in Bash:
```shell
echo -n 'username:password' | base64
```

