package oauth

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type Config struct {
	ClientId      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	IssuerUrl     string   `json:"issuer_url"`
	RedirectUrl   string   `json:"redirect_url"`
	CookieSecret  string   `json:"cookie_secret"`
	EmailDomains  []string `json:"email_domains"`
	AllowedGroups []string `json:"allowed_groups"`

	// Advanced OAuth2 Proxy settings (optional)
	Provider               *string `json:"provider,omitempty"`                 // e.g., "oidc", "keycloak-oidc"
	HttpAddress            *string `json:"http_address,omitempty"`             // e.g., "0.0.0.0:9999"
	LoginUrl               *string `json:"login_url,omitempty"`                // Custom login URL
	RedeemUrl              *string `json:"redeem_url,omitempty"`               // Custom token endpoint URL
	JwksUrl                *string `json:"jwks_url,omitempty"`                 // Custom JWKS URL
	ValidateUrl            *string `json:"validate_url,omitempty"`             // Custom userinfo endpoint URL
	Scope                  *string `json:"scope,omitempty"`                    // e.g., "openid email profile"
	SetAuthorizationHeader *bool   `json:"set_authorization_header,omitempty"` // Pass authorization header
	PassAccessToken        *bool   `json:"pass_access_token,omitempty"`        // Pass access token
	GroupsClaim            *string `json:"groups_claim,omitempty"`             // Groups claim name
}

func GetOauthConfig(workspaceName string) (*Config, error) {
	var config Config
	workspacePath := os.Getenv("HOME") + "/.config/bitswan/workspaces/" + workspaceName
	configPath := workspacePath + "/oauth-config.yaml"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, err
	}

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

// SaveOauthConfig saves the OAuth config to the workspace directory
func SaveOauthConfig(workspaceName string, config *Config) error {
	workspacePath := os.Getenv("HOME") + "/.config/bitswan/workspaces/" + workspaceName
	configPath := workspacePath + "/oauth-config.yaml"

	// Marshal config to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal OAuth config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write OAuth config file: %w", err)
	}

	fmt.Printf("OAuth config saved to: %s\n", configPath)
	return nil
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

// CreateOAuthEnvVars creates OAuth2 Proxy environment variables from an OAuth config
// serviceName is used to construct the redirect URL (e.g., "editor" or "gitops")
func CreateOAuthEnvVars(config *Config, serviceName, workspaceName, domain string) []string {
	if config == nil {
		return []string{}
	}

	// Use provider from config or default to keycloak-oidc
	provider := "keycloak-oidc"
	if config.Provider != nil {
		provider = *config.Provider
	}

	// Use http address from config or default
	httpAddress := "0.0.0.0:9999"
	if config.HttpAddress != nil {
		httpAddress = *config.HttpAddress
	}

	// Use scope from config or default
	scope := "openid email profile"
	if config.Scope != nil {
		scope = *config.Scope
	}

	// Use groups claim from config or default
	groupsClaim := "group_membership"
	if config.GroupsClaim != nil {
		groupsClaim = *config.GroupsClaim
	}

	oauthEnvVars := []string{
		"OAUTH_ENABLED=true", // This is the trigger entrypoint script
		"OAUTH2_PROXY_PROVIDER=" + provider,
		"OAUTH2_PROXY_HTTP_ADDRESS=" + httpAddress,
		"OAUTH2_PROXY_CLIENT_ID=" + config.ClientId,
		"OAUTH2_PROXY_CLIENT_SECRET=" + config.ClientSecret,
		"OAUTH2_PROXY_COOKIE_SECRET=" + config.CookieSecret,
		"OAUTH2_PROXY_OIDC_ISSUER_URL=" + config.IssuerUrl,
		"OAUTH2_PROXY_REDIRECT_URL=https://" + fmt.Sprintf("%s-%s", workspaceName, serviceName) + "." + domain + "/oauth2/callback",
		"OAUTH2_PROXY_EMAIL_DOMAINS=" + strings.Join(config.EmailDomains, ","),
		"OAUTH2_PROXY_OIDC_GROUPS_CLAIM=" + groupsClaim,
		"OAUTH2_PROXY_SCOPE=" + scope,
		"OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256",
		"OAUTH2_PROXY_SKIP_PROVIDER_BUTTON=true",
	}

	// Add custom endpoint URLs if provided, otherwise construct from issuer URL
	if config.LoginUrl != nil || config.RedeemUrl != nil || config.JwksUrl != nil || config.ValidateUrl != nil {
		// If any custom endpoint is provided, enable manual discovery mode
		oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_SKIP_OIDC_DISCOVERY=true")

		if config.LoginUrl != nil {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_LOGIN_URL="+*config.LoginUrl)
		} else {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_LOGIN_URL="+config.IssuerUrl+"/protocol/openid-connect/auth")
		}

		if config.RedeemUrl != nil {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_REDEEM_URL="+*config.RedeemUrl)
		} else {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_REDEEM_URL="+config.IssuerUrl+"/protocol/openid-connect/token")
		}

		if config.JwksUrl != nil {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_OIDC_JWKS_URL="+*config.JwksUrl)
		} else {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_OIDC_JWKS_URL="+config.IssuerUrl+"/protocol/openid-connect/certs")
		}

		if config.ValidateUrl != nil {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_VALIDATE_URL="+*config.ValidateUrl)
		} else {
			oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_VALIDATE_URL="+config.IssuerUrl+"/protocol/openid-connect/userinfo")
		}
	} else if strings.Contains(config.IssuerUrl, "localhost") {
		oauthEnvVars = append(oauthEnvVars,
			"OAUTH2_PROXY_SKIP_OIDC_DISCOVERY=true",
			"OAUTH2_PROXY_OIDC_JWKS_URL="+config.IssuerUrl+"/protocol/openid-connect/certs",
			"OAUTH2_PROXY_LOGIN_URL="+config.IssuerUrl+"/protocol/openid-connect/auth",
			"OAUTH2_PROXY_REDEEM_URL="+config.IssuerUrl+"/protocol/openid-connect/token",
			"OAUTH2_PROXY_VALIDATE_URL="+config.IssuerUrl+"/protocol/openid-connect/userinfo")
	}

	// Add optional flags
	if config.SetAuthorizationHeader != nil && *config.SetAuthorizationHeader {
		oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_SET_AUTHORIZATION_HEADER=true")
	}
	if config.PassAccessToken != nil && *config.PassAccessToken {
		oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_PASS_ACCESS_TOKEN=true")
	}

	// Add localhost-specific SSL settings if needed
	if strings.Contains(config.IssuerUrl, "localhost") {
		oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_SSL_INSECURE_SKIP_VERIFY=true")
	}

	if len(config.AllowedGroups) > 0 {
		oauthEnvVars = append(oauthEnvVars, "OAUTH2_PROXY_ALLOWED_GROUPS="+strings.Join(config.AllowedGroups, ","))
	}

	return oauthEnvVars
}

