package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"
)

type FileInfo struct {
	Name string
	Size int64
}

var (
	fileMap    = make(map[string]FileInfo)
	mapMutex   = sync.RWMutex{}
	scanTicker *time.Ticker
	dirs       []string
	dirMutex   = sync.RWMutex{}
	users      = map[string]string{} // map of username to hashed password for authentication
)

func main() {
	app := &cli.App{
		Name:  "piece-server",
		Usage: "Start an HTTP/HTTPS server to serve file information",
		Commands: []*cli.Command{
			runCmd,
			manageCmd,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

var runCmd = &cli.Command{
	Name:  "run",
	Usage: "Run the HTTP/HTTPS server",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:     "dir",
			Usage:    "Directory paths to scan",
			Required: true,
		},
		&cli.IntFlag{
			Name:  "port",
			Value: 8080,
			Usage: "Port for the server",
		},
		&cli.StringFlag{
			Name:  "bind",
			Value: "0.0.0.0",
			Usage: "Bind address for the server",
		},
		&cli.StringFlag{
			Name:  "cert",
			Usage: "Path to the TLS certificate file (for secure mode)",
		},
		&cli.StringFlag{
			Name:  "key",
			Usage: "Path to the TLS key file (for secure mode)",
		},
		&cli.StringFlag{
			Name:  "htpasswd",
			Usage: "Path to the htpasswd file for user authentication",
		},
		&cli.BoolFlag{
			Name:  "secure",
			Usage: "Enable secure mode (HTTPS and Basic Auth)",
		},
	},
	Action: func(c *cli.Context) error {
		dirs = c.StringSlice("dir")
		port := c.Int("port")
		bindAddress := c.String("bind")
		certFile := c.String("cert")
		keyFile := c.String("key")
		htpasswdFile := c.String("htpasswd")
		secureMode := c.Bool("secure")

		if secureMode {
			if err := loadHtpasswdFile(htpasswdFile); err != nil {
				return err
			}
		}

		// Start the directory scanner in a separate goroutine
		scanTicker = time.NewTicker(30 * time.Second)
		go scanDirectories()

		// Start the server
		mux := http.NewServeMux()
		mux.HandleFunc("/pieces", authenticated(handlePiecesRequest, secureMode))
		mux.HandleFunc("/add-dir", authenticated(handleAddDirRequest, secureMode))
		mux.HandleFunc("/remove-dir", authenticated(handleRemoveDirRequest, secureMode))
		mux.HandleFunc("/data", authenticated(handleDataRequest, secureMode))

		address := fmt.Sprintf("%s:%d", bindAddress, port)
		log.Printf("Starting server on %s...\n", address)

		if secureMode {
			if certFile == "" || keyFile == "" {
				return fmt.Errorf("secure mode requires cert and key files")
			}
			server := &http.Server{
				Addr:    address,
				Handler: mux,
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS12, // Enforce strong TLS version
				},
			}
			return server.ListenAndServeTLS(certFile, keyFile)
		}

		return http.ListenAndServe(address, mux)
	},
}

var manageCmd = &cli.Command{
	Name:  "manage",
	Usage: "Manage directories remotely",
	Subcommands: []*cli.Command{
		addDirCmd,
		rmDirCmd,
	},
}

var addDirCmd = &cli.Command{
	Name:  "add",
	Usage: "Add a directory to the server",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "url",
			Usage:    "Server URL",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "dir",
			Usage:    "Directory to add",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "username",
			Usage: "Username for basic authentication (if secure)",
		},
		&cli.StringFlag{
			Name:  "password",
			Usage: "Password for basic authentication (if secure)",
		},
	},
	Action: func(c *cli.Context) error {
		url := c.String("url")
		dir := c.String("dir")
		username := c.String("username")
		password := c.String("password")
		return sendDirRequest(url+"/add-dir", dir, username, password)
	},
}

var rmDirCmd = &cli.Command{
	Name:  "remove",
	Usage: "Remove a directory from the server",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:     "url",
			Usage:    "Server URL",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "dir",
			Usage:    "Directory to remove",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "username",
			Usage: "Username for basic authentication (if secure)",
		},
		&cli.StringFlag{
			Name:  "password",
			Usage: "Password for basic authentication (if secure)",
		},
	},
	Action: func(c *cli.Context) error {
		url := c.String("url")
		dir := c.String("dir")
		username := c.String("username")
		password := c.String("password")
		return sendDirRequest(url+"/remove-dir", dir, username, password)
	},
}

func sendDirRequest(url, dir, username, password string) error {
	body, err := json.Marshal(map[string]string{"dir": dir})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update directory: %s", resp.Status)
	}

	log.Printf("Directory %s successfully updated", dir)
	return nil
}

func scanDirectories() {
	for range scanTicker.C {
		log.Println("Scanning directories...")

		// Read directory paths safely
		dirMutex.RLock()
		currentDirs := make([]string, len(dirs))
		copy(currentDirs, dirs)
		dirMutex.RUnlock()

		tempMap := make(map[string]FileInfo)

		for _, dir := range currentDirs {
			err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					tempMap[info.Name()] = FileInfo{
						Name: info.Name(),
						Size: info.Size(),
					}
				}
				return nil
			})
			if err != nil {
				log.Printf("Error scanning directory %s: %v\n", dir, err)
			}
		}

		// Safely update the shared map with new data
		mapMutex.Lock()
		fileMap = tempMap
		mapMutex.Unlock()

		log.Printf("Updated file map with %d entries\n", len(fileMap))
	}
}

func handlePiecesRequest(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	mapMutex.RLock()
	defer mapMutex.RUnlock()

	if fileInfo, found := fileMap[id]; found {
		w.Header().Set("Filecoin-Piece-RawSize", fmt.Sprintf("%d", fileInfo.Size))
		w.WriteHeader(http.StatusOK)
		_, err := fmt.Fprintf(w, "File Name: %s, Size: %d bytes\n", fileInfo.Name, fileInfo.Size)
		if err != nil {
			log.Printf("ERROR: Failed to write to the HTTP reponsewriter: %s", err)
		}
	} else {
		http.NotFound(w, r)
	}
}

func handleDataRequest(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	// Lock the map for reading
	mapMutex.RLock()
	defer mapMutex.RUnlock()

	// Find the file path based on the filename
	var filePath string
	for _, dir := range dirs {
		path := filepath.Join(dir, id)
		if _, err := os.Stat(path); err == nil {
			filePath = path
			break
		}
	}

	if filePath == "" {
		http.NotFound(w, r)
		return
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "Failed to open file", http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = file.Close()
	}()

	// Set the correct headers
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", id))

	// Stream the file content
	if _, err := io.Copy(w, file); err != nil {
		http.Error(w, "Failed to send file", http.StatusInternalServerError)
	}
}

func handleAddDirRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var requestData map[string]string
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	dir := requestData["dir"]
	if dir == "" {
		http.Error(w, "Missing 'dir' parameter", http.StatusBadRequest)
		return
	}

	dirMutex.Lock()
	dirs = append(dirs, dir)
	dirMutex.Unlock()

	log.Printf("Added directory to scan: %s\n", dir)
	w.WriteHeader(http.StatusOK)
	_, err := fmt.Fprintln(w, "Directory added successfully")
	if err != nil {
		log.Printf("ERROR: Failed to write to the HTTP reponsewriter: %s", err)
	}
}

func handleRemoveDirRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var requestData map[string]string
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	dir := requestData["dir"]
	if dir == "" {
		http.Error(w, "Missing 'dir' parameter", http.StatusBadRequest)
		return
	}

	dirMutex.Lock()
	for i, d := range dirs {
		if d == dir {
			dirs = append(dirs[:i], dirs[i+1:]...)
			break
		}
	}
	dirMutex.Unlock()

	log.Printf("Removed directory from scan: %s\n", dir)
	w.WriteHeader(http.StatusOK)
	_, err := fmt.Fprintln(w, "Directory removed successfully")
	if err != nil {
		log.Printf("ERROR: Failed to write to the HTTP reponsewriter: %s", err)
	}
}

func loadHtpasswdFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open htpasswd file: %v", err)
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid htpasswd entry: %s", line)
		}
		users[parts[0]] = parts[1]
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading htpasswd file: %v", err)
	}
	return nil
}

func authenticated(handler http.HandlerFunc, secure bool) http.HandlerFunc {
	if !secure {
		return handler
	}
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !validateUser(u, p) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func validateUser(username, password string) bool {
	hashedPassword, ok := users[username]
	if !ok {
		return false
	}

	// Compare the provided password with the hashed password
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}
