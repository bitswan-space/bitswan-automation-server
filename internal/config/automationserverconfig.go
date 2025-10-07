package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// AutomationServerConfig handles reading and writing of Bitswan automation server configuration
type AutomationServerConfig struct {
	configDir string
}

// Config represents the combined TOML configuration
type Config struct {
	ActiveWorkspace    string                    `toml:"active_workspace"`
	AutomationOperationsCenter   AutomationOperationsCenterSettings  `toml:"aoc"`

}

// AutomationOperationsCenterSettings represents the automation operations center connection settings in TOML
type AutomationOperationsCenterSettings struct {
	AOCUrl             string `toml:"aoc_url"`
	AutomationServerId string `toml:"automation_server_id"`
	AccessToken        string `toml:"access_token"`
	ExpiresAt          string `toml:"expires_at,omitempty"`
}

// NewAutomationServerConfig creates a new automation server configuration manager
func NewAutomationServerConfig() *AutomationServerConfig {
	return &AutomationServerConfig{
		configDir: filepath.Join(os.Getenv("HOME"), ".config", "bitswan"),
	}
}

// LoadConfig loads the configuration from the TOML file
func (m *AutomationServerConfig) LoadConfig() (*Config, error) {
	tomlConfigPath := filepath.Join(m.configDir, "automation_server_config.toml")
	if _, err := os.Stat(tomlConfigPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", tomlConfigPath)
	}
	return m.loadTOMLConfig(tomlConfigPath)
}

// loadTOMLConfig loads configuration from the TOML file
func (m *AutomationServerConfig) loadTOMLConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var config Config
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file %s: %w", path, err)
	}

	return &config, nil
}


// SaveConfig saves the configuration to the TOML file
func (m *AutomationServerConfig) SaveConfig(config *Config) error {
	// Ensure config directory exists
	if err := os.MkdirAll(m.configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Save to TOML config
	if err := m.saveTOMLConfig(config); err != nil {
		return fmt.Errorf("failed to save TOML config: %w", err)
	}

	return nil
}

// saveTOMLConfig saves configuration to the TOML file
func (m *AutomationServerConfig) saveTOMLConfig(config *Config) error {
	tomlConfigPath := filepath.Join(m.configDir, "automation_server_config.toml")
	
	file, err := os.Create(tomlConfigPath)
	if err != nil {
		return fmt.Errorf("failed to create TOML config file: %w", err)
	}
	defer file.Close()

	if err := toml.NewEncoder(file).Encode(config); err != nil {
		return fmt.Errorf("failed to encode TOML config: %w", err)
	}

	return nil
}

// UpdateAutomationServer updates only the automation server settings
func (m *AutomationServerConfig) UpdateAutomationServer(settings AutomationOperationsCenterSettings) error {
	config, err := m.LoadConfig()
	if err != nil {
		// If no config exists, create a new one
		config = &Config{}
	}

	config.AutomationOperationsCenter = settings
	return m.SaveConfig(config)
}

// GetAutomationOperationsCenterSettings returns the current automation operations center connection settings
func (m *AutomationServerConfig) GetAutomationOperationsCenterSettings() (*AutomationOperationsCenterSettings, error) {
	config, err := m.LoadConfig()
	if err != nil {
		return nil, err
	}

	return &config.AutomationOperationsCenter, nil
}

// GetActiveWorkspace returns the current active workspace
func (m *AutomationServerConfig) GetActiveWorkspace() (string, error) {
	config, err := m.LoadConfig()
	if err != nil {
		return "", err
	}

	return config.ActiveWorkspace, nil
}

// SetActiveWorkspace updates the active workspace setting
func (m *AutomationServerConfig) SetActiveWorkspace(workspace string) error {
	config, err := m.LoadConfig()
	if err != nil {
		// If no config exists, create a new one
		config = &Config{}
	}

	config.ActiveWorkspace = workspace
	return m.SaveConfig(config)
}

// ConfigExists checks if any configuration file exists
func (m *AutomationServerConfig) ConfigExists() bool {
	tomlConfigPath := filepath.Join(m.configDir, "automation_server_config.toml")
	
	_, tomlExists := os.Stat(tomlConfigPath)
	
	return tomlExists == nil
}

// GetConfigPath returns the path to the primary TOML config file
func (m *AutomationServerConfig) GetConfigPath() string {
	return filepath.Join(m.configDir, "automation_server_config.toml")
}

// GetWorkspaceName returns the active workspace name
func GetWorkspaceName() (string, error) {
	config := NewAutomationServerConfig()
	return config.GetActiveWorkspace()
}
