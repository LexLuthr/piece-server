package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Mock global variables for testing
var testFileMap = make(map[string]FileInfo)
var testMapMutex = sync.Mutex{}
var testDirs []string
var testDirMutex = sync.Mutex{}

func TestHandlePiecesRequest(t *testing.T) {
	// Setup mock data
	testFileMap["testfile"] = FileInfo{Name: "testfile.txt", Size: 1024, Path: "/tmp/testfile.txt"}

	req, err := http.NewRequest("GET", "/pieces?id=testfile", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePiecesRequest)

	testMapMutex.Lock()
	fileMap = testFileMap
	testMapMutex.Unlock()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", rr.Code)
	}
}

func TestHandleAddDirRequest(t *testing.T) {
	payload := map[string]string{"dir": "/tmp/testdir"}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", "/add-dir", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleAddDirRequest)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", rr.Code)
	}
}

func TestHandleRemoveDirRequest(t *testing.T) {
	// Add a directory first
	testDirMutex.Lock()
	testDirs = append(testDirs, "/tmp/testdir")
	testDirMutex.Unlock() // Unlock after modifying testDirs

	payload := map[string]string{"dir": "/tmp/testdir"}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", "/remove-dir", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleRemoveDirRequest)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", rr.Code)
	}
}

func TestLoadHtpasswdFile(t *testing.T) {
	// Create a temporary htpasswd file
	tempFile, err := os.CreateTemp("", "htpasswd")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	_, err = tempFile.WriteString("testuser:$2a$10$KIXt9KVR6y6D9wJOPLOex.OI7QjXeSk/F1V7g4/uO2Tlv3X.qXQiK\n") // bcrypt hashed password for "password"
	if err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close()

	err = loadHtpasswdFile(tempFile.Name())
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if _, exists := users["testuser"]; !exists {
		t.Errorf("Expected user 'testuser' to exist")
	}
}

func TestValidateUser(t *testing.T) {
	// Hash the password before storing it in users map
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to generate bcrypt hash: %v", err)
	}
	users["testuser"] = string(hashedPassword) // Store hashed password

	// Test correct password
	if !validateUser("testuser", "password") {
		t.Errorf("Expected user validation to succeed")
	}

	// Test incorrect password
	if validateUser("testuser", "wrongpassword") {
		t.Errorf("Expected user validation to fail for incorrect password")
	}
}
