package oauth

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	ClientId      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	IssuerUrl     string `json:"issuer_url"`
	RedirectUrl   string `json:"redirect_url"`
	CookieSecret  string `json:"cookie_secret"`
	EmailDomains  []string `json:"email_domains"`
	AllowedGroups []string `json:"allowed_groups"`
}

func GetOauthConfig(workspaceName string) (*Config, error) {
	var config Config
	fmt.Println("Getting OAuth config for workspace:", workspaceName)
	workspacePath := os.Getenv("HOME") + "/.config/bitswan/workspaces/" + workspaceName 
	configPath := workspacePath + "/secrets/oauth-config.yaml"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {	
		fmt.Println("No OAuth config found, skipping...")
		return nil, fmt.Errorf("no OAuth config found")
	}

	fmt.Println("Config path:", configPath)

	fileContent, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Println("Error reading OAuth config file:", err)
		return nil, fmt.Errorf("error reading OAuth config file: %w", err)
	}

	if err := yaml.Unmarshal(fileContent, &config); err != nil {
		fmt.Println("Error unmarshalling OAuth config file:", err)
		return nil, fmt.Errorf("error unmarshalling OAuth config file: %w", err)
	}

	if config.ClientId == "" || config.ClientSecret == "" || config.IssuerUrl == "" || config.CookieSecret == "" {
		fmt.Println("Error: all required fields are not set")
		return nil, fmt.Errorf("all required fields are not set")
	}

	return &config, nil
}

func GetInitOauthConfig(oauthConfigFile string) (*Config, error) {
	var config Config

	// Read the JSON file
	jsonFile, err := os.Open(oauthConfigFile)
	if err != nil {
		return nil, fmt.Errorf("error opening OAuth config file: %w", err)
	}
	defer jsonFile.Close()

	// Parse the JSON file
	if err := json.NewDecoder(jsonFile).Decode(&config); err != nil {
		return nil, fmt.Errorf("invalid JSON file: %w", err)
	}

	// Check if all required fields are set
	if config.ClientId == "" || config.ClientSecret == "" || config.IssuerUrl == "" || config.CookieSecret == "" {
		return nil, fmt.Errorf("all required fields are not set")
	}

	return &config, nil
}
