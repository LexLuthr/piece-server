# Documentation for "piece-server" 

## Overview
The `piece-server` program is designed to run as an HTTP or HTTPS server to serve file information. This server allows scanning directories and can share information about the available files.

The program processes the directories independently for scanning and protects shared data using mutex locks to prevent race conditions. The program also supports user validation through an `htpasswd` file and basic authentication when the secure mode is enabled.

You can interact with the server remotely using commands to add and remove directories that should be scanned. The file information and actual file contents can then be accessed using specific routes.

## Installation
As this is a Go program, make sure Go is installed on your machine. You can check the installed version using:
Clone the program repository, navigate to the program's directory and build the binary:
go build main.go

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