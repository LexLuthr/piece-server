# Documentation for "piece-server" 

## Overview
The `piece-server` program is designed to run as an HTTP or HTTPS server to serve file information. This server allows scanning directories and can share information about the available files.

The program processes the directories independently for scanning and protects shared data using mutex locks to prevent race conditions. The program also supports user validation through an `htpasswd` file and basic authentication when the secure mode is enabled.

You can interact with the server remotely using commands to add and remove directories that should be scanned. The file information and actual file contents can then be accessed using specific routes.

## Installation

### 🏰 Using Prebuilt Binaries (Recommended)

For Linux/macOS (x86_64 & ARM64):

```sh
curl -L -o piece-server.tar.gz "https://github.com/LexLuthr/piece-server/releases/latest/download/piece-server_$(uname -s)_$(uname -m).tar.gz"
tar -xzf piece-server.tar.gz
chmod +x piece-server
./piece-server --help
```

### ⚙️ Using Go Install (Alternative)

Ensure Go is installed:

```sh
go version
```

Then install via Go:

```sh
go install github.com/LexLuthr/piece-server@latest
```

### 🔧 Manual Build (Only if Needed)

Clone and build manually:

```sh
git clone https://github.com/LexLuthr/piece-server.git
cd piece-server
go build -o piece-server main.go
```

---

## 📦 Running with Docker

Prebuilt Docker images are available at [GitHub Container Registry](https://github.com/LexLuthr/piece-server/pkgs/container/piece-server).

### **🌆 Pull & Run**
```sh
docker pull ghcr.io/lexluthr/piece-server:latest
docker run -d --name piece-server -p 8080:8080 ghcr.io/lexluthr/piece-server:latest
```

### **🛠 Running with Custom Data Directory**
Since `piece-server` reads directories, you need to **mount a volume**:

```sh
docker run -d --name piece-server -p 8080:8080 -v /your/data:/data ghcr.io/lexluthr/piece-server:latest --dir /data
```

### **🔒 Running Secure (HTTPS + Auth)**
```sh
docker run -d --name piece-server \
  -p 443:443 \
  -v /path/to/certs:/certs \
  ghcr.io/lexluthr/piece-server:latest \
  --secure --cert /certs/cert.pem --key /certs/key.pem --htpasswd /certs/.htpasswd
```

---

## ✅ Verify Download (Optional, Recommended)

```sh
curl -L -o piece-server.tar.gz "https://github.com/LexLuthr/piece-server/releases/latest/download/piece-server_$(uname -s)_$(uname -m).tar.gz"
curl -L -o checksums.txt "https://github.com/LexLuthr/piece-server/releases/latest/download/checksums.txt"
shasum -a 256 -c checksums.txt 2>&1 | grep piece-server
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

