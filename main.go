package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"
)

type FileInfo struct {
	Name string
	Size int64
	Path string
}

var (
	fileMap  = make(map[string]FileInfo)
	mapMutex = sync.Mutex{}
	dirs     []string
	dirMutex = sync.Mutex{}
	users    = map[string]string{} // map of username to hashed password for authentication
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
		go scanDirectories(c.Context)

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
		cerr := resp.Body.Close()
		if cerr != nil {
			log.Printf("ERROR: Failed to close response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update directory: %s", resp.Status)
	}

	log.Printf("Directory %s successfully updated", dir)
	return nil
}

func scanDirectories(ctx context.Context) {
	scanTicker := time.NewTicker(30 * time.Second)
	defer scanTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Stopping directory scanner...")
			return
		case <-scanTicker.C:
			log.Println("Scanning directories...")

			// Read directory paths safely
			tempMap := make(map[string]FileInfo)
			dirMutex.Lock()
			currentDirs := make([]string, len(dirs))
			copy(currentDirs, dirs)
			dirMutex.Unlock()
			for _, dir := range currentDirs {
				select {
				case <-ctx.Done():
					// Stop scanning if the context is canceled
					log.Println("INFO: Directory scanning interrupted due to context cancellation...")
					return
				default:
					err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
						if err != nil {
							return err
						}
						if !info.IsDir() {
							// Strip out any .car or .* suffix
							id := strings.Split(info.Name(), ".")[0]
							_, ok := tempMap[id]
							if !ok {
								tempMap[id] = FileInfo{
									Name: info.Name(),
									Size: info.Size(),
									Path: path,
								}
							} else {
								log.Printf("WARNING - Duplicate file ID found: %s\n", id)
							}
						}
						return nil
					})
					if err != nil {
						log.Printf("Error scanning directory %s: %v\n", dir, err)
					}
				}
			}

			// Safely update the shared map with new data
			mapMutex.Lock()
			fileMap = tempMap
			mapMutex.Unlock()

			log.Printf("Updated file map with %d entries\n", len(fileMap))
		}
	}
}

func handlePiecesRequest(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		log.Printf("WARNING: Missing 'id' query parameter in query %s\n", r.URL.Query())
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}
	log.Printf("Received request for piece info for %s\n", id)

	mapMutex.Lock()
	defer mapMutex.Unlock()

	if fileInfo, found := fileMap[id]; found {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size))
		w.WriteHeader(http.StatusOK)
		_, err := fmt.Fprintf(w, "File Name: %s, Size: %d bytes\n", fileInfo.Name, fileInfo.Size)
		if err != nil {
			log.Printf("ERROR: Failed to write to the HTTP reponsewriter: %s", err)
		}
		log.Printf("INFO: Responded successfully to piece info request %s (%d bytes)\n", id, fileInfo.Size)
	} else {
		http.NotFound(w, r)
	}
}

// Custom errors when range parsing overlaps
var (
	ErrNoOverlap          = errors.New("invalid range: no overlap with file size")
	ErrInvalidRangeFormat = errors.New("invalid range format, expected X-Y")
	ErrInvalidRange       = errors.New("invalid range, cannot parse bounds")
)

// Parse the Range header into individual byte ranges
func parseRange(rangeHeader string, fileSize int64) ([][2]int64, error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return nil, ErrInvalidRangeFormat
	}
	rangeHeader = strings.TrimPrefix(rangeHeader, "bytes=")
	rangeParts := strings.Split(rangeHeader, ",")
	ranges := make([][2]int64, 0, len(rangeParts))

	for _, part := range rangeParts {
		bounds := strings.Split(part, "-")
		if len(bounds) != 2 {
			return nil, ErrInvalidRangeFormat
		}

		var start, end int64
		var err error

		if bounds[0] == "" {
			// Case: bytes=-X (last X bytes)
			parsedEnd, err := strconv.ParseInt(bounds[1], 10, 64)
			if err != nil {
				return nil, ErrInvalidRange
			}
			start = fileSize - parsedEnd
			end = fileSize - 1
		} else if bounds[1] == "" {
			// Case: bytes=X- (all bytes from X onwards)
			start, err = strconv.ParseInt(bounds[0], 10, 64)
			if err != nil {
				return nil, ErrInvalidRange
			}
			end = fileSize - 1
		} else {
			// Case: bytes=X-Y
			start, err = strconv.ParseInt(bounds[0], 10, 64)
			if err != nil {
				return nil, ErrInvalidRange
			}
			end, err = strconv.ParseInt(bounds[1], 10, 64)
			if err != nil {
				return nil, ErrInvalidRange
			}
		}

		if start > end || start >= fileSize || end < 0 {
			return nil, ErrNoOverlap
		}

		// Clamp the range to the valid file boundaries
		if start < 0 {
			start = 0
		}
		if end >= fileSize {
			end = fileSize - 1
		}

		ranges = append(ranges, [2]int64{start, end})
	}

	return ranges, nil
}

func handleDataRequest(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	// Lock the map for reading
	mapMutex.Lock()
	defer mapMutex.Unlock()

	v, ok := fileMap[id]
	if !ok {
		log.Printf("WARNING: File %s not found for query: %s\n", id, r.URL.Query())
		http.NotFound(w, r)
		return
	}

	log.Printf("Received request for file %s\n", id)

	// Open the file
	file, err := os.Open(v.Path)
	if err != nil {
		log.Printf("ERROR: Failed to open file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer func(file *os.File) {
		cerr := file.Close()
		if cerr != nil {
			log.Printf("ERROR: Failed to close file: %v", cerr)
		}
	}(file)

	fileStat, err := file.Stat()
	if err != nil {
		log.Printf("ERROR: Failed to retrieve file info: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	fileSize := fileStat.Size()
	if fileSize <= 0 {
		http.Error(w, "File is empty", http.StatusInternalServerError)
		return
	}

	// Handle Head request
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, id))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fileSize))
		w.WriteHeader(http.StatusOK)
		log.Printf("INFO: Responded successfully to HEAD request for %s (%d bytes)\n", id, fileSize)
		return
	}

	// Check for range requests
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		ranges, err := parseRange(rangeHeader, fileSize)
		if err != nil {
			if errors.Is(err, ErrNoOverlap) {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", fileSize))
				http.Error(w, "Requested Range Not Satisfiable", http.StatusRequestedRangeNotSatisfiable)
			} else {
				http.Error(w, "Invalid Range Header", http.StatusBadRequest)
			}
			return
		}

		if len(ranges) > 1 {
			// Multipart response
			boundary := fmt.Sprintf("MULTIPART_BYTERANGES-%d", time.Now().UnixNano())
			w.Header().Set("Content-Type", `multipart/byteranges; boundary=`+boundary)
			w.WriteHeader(http.StatusPartialContent)

			for _, rng := range ranges {
				start, end := rng[0], rng[1]
				n, err := w.Write([]byte(fmt.Sprintf("\r\n--%s\r\n", boundary)))
				if err != nil {
					log.Printf("ERROR: Failed to write multipart header: %v", err)
					return
				}
				if n != len(fmt.Sprintf("\r\n--%s\r\n", boundary)) {
					log.Printf("ERROR: Failed to write entire multipart header: %d != %d", n, len(fmt.Sprintf("\r\n--%s\r\n", boundary)))
				}
				n, err = w.Write([]byte("Content-Type: application/octet-stream\r\n"))
				if err != nil {
					log.Printf("ERROR: Failed to write multipart header: %v", err)
					return
				}
				if n != len(fmt.Sprintf("\r\n--%s\r\n", boundary)) {
					log.Printf("ERROR: Failed to write entire multipart header: %d != %d", n, len(fmt.Sprintf("\r\n--%s\r\n", boundary)))
				}
				n, err = w.Write([]byte(fmt.Sprintf("Content-Range: bytes %d-%d/%d\r\n", start, end, fileSize)))
				if err != nil {
					log.Printf("ERROR: Failed to write multipart header: %v", err)
					return
				}
				if n != len(fmt.Sprintf("\r\n--%s\r\n", boundary)) {
					log.Printf("ERROR: Failed to write entire multipart header: %d != %d", n, len(fmt.Sprintf("\r\n--%s\r\n", boundary)))
				}
				n, err = w.Write([]byte(fmt.Sprintf("Content-Length: %d\r\n\r\n", end-start+1)))
				if err != nil {
					log.Printf("ERROR: Failed to write multipart header: %v", err)
					return
				}
				if n != len(fmt.Sprintf("\r\n--%s\r\n", boundary)) {
					log.Printf("ERROR: Failed to write entire multipart header: %d != %d", n, len(fmt.Sprintf("\r\n--%s\r\n", boundary)))
				}

				// Write range data
				if _, err := file.Seek(start, io.SeekStart); err != nil {
					log.Printf("ERROR: Failed to seek file: %v", err)
					return
				}
				if _, err := io.CopyN(w, file, end-start+1); err != nil {
					log.Printf("ERROR: Failed to write range data: %v", err)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}
			}
			write, err := w.Write([]byte(fmt.Sprintf("\r\n--%s--\r\n", boundary)))
			if err != nil {
				log.Printf("ERROR: Failed to write multipart footer: %v", err)
				return
			}
			if write != len(fmt.Sprintf("\r\n--%s--\r\n", boundary)) {
				log.Printf("ERROR: Failed to write entire multipart footer: %d != %d", write, len(fmt.Sprintf("\r\n--%s--\r\n", boundary)))
			}
			log.Printf("INFO: Responded successfully to multipart response for %s (%d bytes)\n", id, fileSize)
			return
		}

		// Single range
		start, end := ranges[0][0], ranges[0][1]
		if _, err := file.Seek(start, io.SeekStart); err != nil {
			http.Error(w, "Failed to seek file", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, id))
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", end-start+1))
		w.WriteHeader(http.StatusPartialContent)
		n, err := io.CopyN(w, file, end-start+1)
		if err != nil {
			log.Printf("ERROR: Failed to write range data: %v", err)
			return
		}
		if n != end-start+1 {
			log.Printf("ERROR: Failed to write entire range: %d != %d", n, end-start+1)
		}
		log.Printf("INFO: Responded successfully to range request for %s (%d bytes)\n", id, fileSize)
		return
	}

	// Serve the entire file
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, id))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileSize))
	if _, err := io.Copy(w, file); err != nil {
		log.Printf("ERROR: Failed to send file: %v", err)
	}
	log.Printf("INFO: Responded successfully to file request for %s (%d bytes)\n", id, fileSize)
}

func handleAddDirRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("WARNING: Invalid request method for adding directory: %s\n", r.Method)
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var requestData map[string]string
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Printf("WARNING: Invalid JSON payload for adding directory: %v\n", err)
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	dir := requestData["dir"]
	if dir == "" {
		log.Printf("WARNING: Missing 'dir' parameter for adding directory\n")
		http.Error(w, "Missing 'dir' parameter", http.StatusBadRequest)
		return
	}

	dirMutex.Lock()
	for _, d := range dirs {
		if d == dir {
			dirMutex.Unlock() // Unlock here
			log.Printf("WARNING: Directory %s already exists\n", dir)
			http.Error(w, "Directory already exists", http.StatusBadRequest)
			return
		}
	}

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
		log.Printf("WARNING: Invalid request method for removing directory: %s\n", r.Method)
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var requestData map[string]string
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Printf("WARNING: Invalid JSON payload for removing directory: %v\n", err)
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	dir := requestData["dir"]
	if dir == "" {
		log.Printf("WARNING: Missing 'dir' parameter for removing directory\n")
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
		cerr := file.Close()
		if cerr != nil {
			log.Printf("ERROR: Failed to close htpasswd file: %v", cerr)
		}
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
			log.Printf("WARNING: Failed authentication attempt for user: %s", u)
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
