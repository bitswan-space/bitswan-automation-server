package daemonapi

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

// TokenType represents the type of token
type TokenType string

const (
	TokenTypeGlobal    TokenType = "global"
	TokenTypeWorkspace TokenType = "workspace"
)

// Token represents a token with its metadata
type Token struct {
	Value       string    `yaml:"value"`
	Type        TokenType `yaml:"type"`
	Workspace   string    `yaml:"workspace,omitempty"` // Only set for workspace tokens
	Description string    `yaml:"description,omitempty"`
	CreatedAt   string    `yaml:"created_at"`
}

// TokenManager manages tokens for the daemon API
type TokenManager struct {
	tokensPath string
	tokens     map[string]*Token
	mu         sync.RWMutex
}

// NewTokenManager creates a new token manager
func NewTokenManager(configDir string) (*TokenManager, error) {
	tokensPath := filepath.Join(configDir, "daemon_tokens.yaml")

	tm := &TokenManager{
		tokensPath: tokensPath,
		tokens:     make(map[string]*Token),
	}

	// Load existing tokens
	if err := tm.loadTokens(); err != nil {
		// If file doesn't exist, that's okay - we'll create it when needed
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load tokens: %w", err)
		}
	}

	return tm, nil
}

// loadTokens loads tokens from the YAML file
func (tm *TokenManager) loadTokens() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	data, err := os.ReadFile(tm.tokensPath)
	if err != nil {
		return err
	}

	var tokensData struct {
		Tokens map[string]*Token `yaml:"tokens"`
	}

	if err := yaml.Unmarshal(data, &tokensData); err != nil {
		return fmt.Errorf("failed to unmarshal tokens: %w", err)
	}

	tm.tokens = tokensData.Tokens
	if tm.tokens == nil {
		tm.tokens = make(map[string]*Token)
	}

	return nil
}

// saveTokens saves tokens to the YAML file
// NOTE: This method assumes the caller already holds tm.mu.Lock()
func (tm *TokenManager) saveTokens() error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(tm.tokensPath), 0755); err != nil {
		return fmt.Errorf("failed to create tokens directory: %w", err)
	}

	tokensData := struct {
		Tokens map[string]*Token `yaml:"tokens"`
	}{
		Tokens: tm.tokens,
	}

	data, err := yaml.Marshal(tokensData)
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	if err := os.WriteFile(tm.tokensPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write tokens file: %w", err)
	}

	return nil
}

// generateToken generates a new secure random token
func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// CreateGlobalToken creates a new global token
func (tm *TokenManager) CreateGlobalToken(description string) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tokenValue, err := generateToken()
	if err != nil {
		return "", err
	}

	token := &Token{
		Value:       tokenValue,
		Type:        TokenTypeGlobal,
		Description: description,
		CreatedAt:   time.Now().Format(time.RFC3339),
	}

	tm.tokens[tokenValue] = token

	if err := tm.saveTokens(); err != nil {
		delete(tm.tokens, tokenValue)
		return "", err
	}

	return tokenValue, nil
}

// CreateWorkspaceToken creates a new workspace-specific token
func (tm *TokenManager) CreateWorkspaceToken(workspace string, description string) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tokenValue, err := generateToken()
	if err != nil {
		return "", err
	}

	token := &Token{
		Value:       tokenValue,
		Type:        TokenTypeWorkspace,
		Workspace:   workspace,
		Description: description,
		CreatedAt:   time.Now().Format(time.RFC3339),
	}

	tm.tokens[tokenValue] = token

	if err := tm.saveTokens(); err != nil {
		delete(tm.tokens, tokenValue)
		return "", err
	}

	return tokenValue, nil
}

// ValidateToken validates a token and returns its type and workspace (if applicable)
func (tm *TokenManager) ValidateToken(tokenValue string) (TokenType, string, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	token, exists := tm.tokens[tokenValue]
	if !exists {
		return "", "", fmt.Errorf("invalid token")
	}

	workspace := ""
	if token.Type == TokenTypeWorkspace {
		workspace = token.Workspace
	}

	return token.Type, workspace, nil
}

// DeleteToken deletes a token
func (tm *TokenManager) DeleteToken(tokenValue string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if _, exists := tm.tokens[tokenValue]; !exists {
		return fmt.Errorf("token not found")
	}

	delete(tm.tokens, tokenValue)
	return tm.saveTokens()
}

// ListTokens returns all tokens (for management purposes)
func (tm *TokenManager) ListTokens() map[string]*Token {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	result := make(map[string]*Token)
	for k, v := range tm.tokens {
		result[k] = v
	}
	return result
}
