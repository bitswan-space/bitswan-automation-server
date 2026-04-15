package vpn

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	magicLinkFile    = "magic-links.json"
	magicLinkExpiry  = 1 * time.Hour
	magicLinkTokenLen = 32 // 32 bytes = 64 hex chars
)

// MagicLink represents a one-time-use VPN credential download token.
type MagicLink struct {
	Token     string    `json:"token"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Claimed   bool      `json:"claimed"`
	ClaimedBy string    `json:"claimed_by,omitempty"`
}

// MagicLinkStore manages magic link tokens on disk.
type MagicLinkStore struct {
	baseDir string
	mu      sync.Mutex
}

// NewMagicLinkStore creates a store rooted at the VPN config directory.
func NewMagicLinkStore(bitswanConfigDir string) *MagicLinkStore {
	return &MagicLinkStore{
		baseDir: filepath.Join(bitswanConfigDir, vpnDirName),
	}
}

// Create generates a new magic link token.
func (s *MagicLinkStore) Create(createdBy string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokenBytes := make([]byte, magicLinkTokenLen)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	now := time.Now().UTC()
	link := MagicLink{
		Token:     token,
		CreatedBy: createdBy,
		CreatedAt: now,
		ExpiresAt: now.Add(magicLinkExpiry),
		Claimed:   false,
	}

	links, _ := s.readLinks()
	links = append(links, link)
	if err := s.writeLinks(links); err != nil {
		return "", err
	}

	return token, nil
}

// Validate checks if a token is valid (exists, not expired, not claimed).
func (s *MagicLinkStore) Validate(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	links, err := s.readLinks()
	if err != nil {
		return fmt.Errorf("failed to read magic links: %w", err)
	}

	for _, link := range links {
		if link.Token == token {
			if link.Claimed {
				return fmt.Errorf("token already claimed")
			}
			if time.Now().UTC().After(link.ExpiresAt) {
				return fmt.Errorf("token expired")
			}
			return nil
		}
	}
	return fmt.Errorf("token not found")
}

// Claim marks a token as claimed and returns the creator info.
func (s *MagicLinkStore) Claim(token, claimedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	links, err := s.readLinks()
	if err != nil {
		return fmt.Errorf("failed to read magic links: %w", err)
	}

	for i, link := range links {
		if link.Token == token {
			if link.Claimed {
				return fmt.Errorf("token already claimed")
			}
			if time.Now().UTC().After(link.ExpiresAt) {
				return fmt.Errorf("token expired")
			}
			links[i].Claimed = true
			links[i].ClaimedBy = claimedBy
			return s.writeLinks(links)
		}
	}
	return fmt.Errorf("token not found")
}

// CleanupExpired removes expired and claimed tokens.
func (s *MagicLinkStore) CleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	links, err := s.readLinks()
	if err != nil {
		return
	}

	now := time.Now().UTC()
	var active []MagicLink
	for _, link := range links {
		if !link.Claimed && now.Before(link.ExpiresAt) {
			active = append(active, link)
		}
	}
	s.writeLinks(active)
}

// List returns all active (unclaimed, unexpired) magic links.
func (s *MagicLinkStore) List() ([]MagicLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	links, err := s.readLinks()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	var active []MagicLink
	for _, link := range links {
		if !link.Claimed && now.Before(link.ExpiresAt) {
			active = append(active, link)
		}
	}
	return active, nil
}

func (s *MagicLinkStore) readLinks() ([]MagicLink, error) {
	filePath := filepath.Join(s.baseDir, magicLinkFile)
	data, err := os.ReadFile(filePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var links []MagicLink
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, err
	}
	return links, nil
}

func (s *MagicLinkStore) writeLinks(links []MagicLink) error {
	filePath := filepath.Join(s.baseDir, magicLinkFile)
	os.MkdirAll(s.baseDir, 0700)
	data, err := json.MarshalIndent(links, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0600)
}
