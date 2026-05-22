package daemon

import (
	"fmt"

	"github.com/bitswan-space/bitswan-workspaces/internal/aoc"
)

// registerProtectedRedirectURI tells AOC to add a redirect URI to the
// shared bitswan-protected-client. Every internal endpoint protected
// by bitswan-protected-proxy needs its callback URL on that client's
// allowlist; Keycloak otherwise refuses the OAuth callback.
//
// service_name="bitswan-protected" matches the existing client whose
// client_id is automation-server-<server>-bitswan-protected-client.
// GetOrCreateOAuthClient is idempotent: it adds the URI if missing
// and returns the existing client credentials.
func registerProtectedRedirectURI(hostname string) error {
	aocClient, err := aoc.NewAOCClient()
	if err != nil {
		return fmt.Errorf("AOC not configured: %w", err)
	}
	redirectURI := fmt.Sprintf("https://%s/oauth2/callback", hostname)
	if _, err := aocClient.GetOrCreateOAuthClient("bitswan-protected", redirectURI); err != nil {
		return err
	}
	return nil
}
