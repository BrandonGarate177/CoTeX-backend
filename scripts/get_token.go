package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

// SignInRequest represents the request body for Supabase sign in
type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse represents the response from Supabase auth
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	User         User   `json:"user"`
}

// User represents user information from Supabase
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func main() {
	// Command line flags
	var (
		envFile = flag.String("env", ".env", "Path to .env file")
		verbose = flag.Bool("v", false, "Verbose output")
	)
	flag.Parse()

	// Load environment variables
	if err := loadEnvFile(*envFile); err != nil {
		if *verbose {
			fmt.Printf("Note: Could not load %s: %v\n", *envFile, err)
		}
	}

	// Get Supabase configuration
	supabaseURL := os.Getenv("SUPABASE_URL")
	if supabaseURL == "" {
		fmt.Fprintf(os.Stderr, "Error: SUPABASE_URL environment variable is required\n")
		os.Exit(1)
	}

	supabaseKey := os.Getenv("SUPABASE_KEY")
	if supabaseKey == "" {
		fmt.Fprintf(os.Stderr, "Error: SUPABASE_KEY environment variable is required\n")
		os.Exit(1)
	}

	// Hardcoded credentials
	email := "testuser@example.com"
	password := "pasword"

	if *verbose {
		fmt.Printf("Using Supabase URL: %s\n", supabaseURL)
		fmt.Printf("Authenticating user: %s\n", email)
	}

	// Get token
	token, err := getSupabaseToken(supabaseURL, supabaseKey, email, password, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting token: %v\n", err)
		os.Exit(1)
	}

	// Output the token
	fmt.Println(token)

	if *verbose {
		fmt.Printf("\nFor Postman, use this Authorization header:\n")
		fmt.Printf("Authorization: Bearer %s\n", token)
	}
}

// getSupabaseToken authenticates with Supabase and returns an access token
func getSupabaseToken(supabaseURL, supabaseKey, email, password string, verbose bool) (string, error) {
	// Prepare the sign-in request
	signInReq := SignInRequest{
		Email:    email,
		Password: password,
	}

	reqBody, err := json.Marshal(signInReq)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create the HTTP request
	url := fmt.Sprintf("%s/auth/v1/token?grant_type=password", supabaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", supabaseKey)

	if verbose {
		fmt.Printf("Making request to: %s\n", url)
	}

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if verbose {
		fmt.Printf("Response status: %s\n", resp.Status)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if verbose {
		fmt.Printf("Authentication successful!\n")
		fmt.Printf("User ID: %s\n", authResp.User.ID)
		fmt.Printf("User Email: %s\n", authResp.User.Email)
		fmt.Printf("Token expires in: %d seconds\n", authResp.ExpiresIn)
	}

	return authResp.AccessToken, nil
}

// loadEnvFile loads environment variables from a .env file
func loadEnvFile(envFile string) error {
	// If the path is not absolute, make it relative to the project root
	if !filepath.IsAbs(envFile) {
		// Look for the file in the current directory and parent directories
		currentDir, err := os.Getwd()
		if err != nil {
			return err
		}

		// Try current directory first
		if _, err := os.Stat(filepath.Join(currentDir, envFile)); err == nil {
			envFile = filepath.Join(currentDir, envFile)
		} else {
			// Try parent directory (useful when running from scripts/ directory)
			parentDir := filepath.Dir(currentDir)
			if _, err := os.Stat(filepath.Join(parentDir, envFile)); err == nil {
				envFile = filepath.Join(parentDir, envFile)
			}
		}
	}

	return godotenv.Load(envFile)
}
