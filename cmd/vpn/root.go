package vpn

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/bitswan-space/bitswan-workspaces/internal/config"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func NewVPNCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vpn",
		Short: "Manage WireGuard VPN for the platform",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newDestroyCmd())
	cmd.AddCommand(newBootstrapCmd())
	cmd.AddCommand(newInviteCmd())
	cmd.AddCommand(newStatusCmd())
	cmd.AddCommand(newListDevicesCmd())
	cmd.AddCommand(newSessionsCmd())
	cmd.AddCommand(newRevokeCmd())

	return cmd
}

func getDaemonClient() *daemon.Client {
	client, err := daemon.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
		os.Exit(1)
	}
	return client
}

func newInitCmd() *cobra.Command {
	var endpoint string
	var domain string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize WireGuard VPN for the platform",
		Long: `Sets up the WireGuard server, VPN DNS, and VPN Traefik.
All workspaces will use this VPN.

Internal services use a fake TLD: <workspace>.<server-slug>.bswn.internal
The server name is set during 'bitswan automation-server-daemon init'
(random Docker-style name) or when registering with the AOC.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if endpoint == "" {
				// Auto-detect public IP
				detected, err := detectPublicIP()
				if err != nil {
					return fmt.Errorf("could not detect public IP (use --endpoint to set manually): %w", err)
				}
				endpoint = detected
				fmt.Printf("Detected public IP: %s\n", endpoint)
			}

			// Load existing config to get the server slug
			cfg := config.NewAutomationServerConfig()
			serverConfig, err := cfg.LoadConfig()
			if err != nil {
				return fmt.Errorf("automation server not initialized — run 'bitswan automation-server-daemon init' first")
			}
			if serverConfig.Slug == "" {
				randomName := config.GenerateRandomName()
				if err := cfg.SetNameAndSlug(randomName); err != nil {
					return fmt.Errorf("failed to generate server name: %w", err)
				}
				serverConfig, _ = cfg.LoadConfig()
				fmt.Printf("Generated server name: %s\n", randomName)
			}

			// Resolve platform domain
			if domain != "" {
				// Flag provided — save to config
				if err := cfg.SetDomain(domain); err != nil {
					return fmt.Errorf("failed to save domain: %w", err)
				}
				serverConfig, _ = cfg.LoadConfig()
			} else if serverConfig.Domain == "" {
				// Try to find domain from an existing workspace
				foundDomain := findDomainFromWorkspaces()
				if foundDomain != "" {
					fmt.Printf("Detected domain from existing workspace: %s\n", foundDomain)
					if err := cfg.SetDomain(foundDomain); err != nil {
						return fmt.Errorf("failed to save domain: %w", err)
					}
					serverConfig, _ = cfg.LoadConfig()
				} else {
					return fmt.Errorf("no domain configured. Use --domain or register with AOC first")
				}
			}

			internalDomain := serverConfig.InternalDomain()

			client := getDaemonClient()
			body := fmt.Sprintf(`{"endpoint": %q, "internal_domain": %q}`, endpoint, internalDomain)
			req, err := http.NewRequest("POST", "http://daemon/vpn/init", strings.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.DoRequest(req)
			if err != nil {
				return fmt.Errorf("failed to initialize VPN: %w", err)
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("VPN init failed (HTTP %d): %s", resp.StatusCode, string(respBody))
			}

			var result map[string]string
			json.Unmarshal(respBody, &result)
			fmt.Println(result["message"])
			fmt.Println()
			fmt.Printf("Automation server: %s (slug: %s)\n", serverConfig.Name, serverConfig.Slug)
			fmt.Printf("Internal domain:   *.%s\n", internalDomain)
			fmt.Printf("Workspace URLs:    <workspace>.%s\n", internalDomain)
			fmt.Println()
			fmt.Println("Next step: run 'bitswan vpn bootstrap' to generate your admin VPN config.")
			return nil
		},
	}

	cmd.Flags().StringVar(&endpoint, "endpoint", "", "Public hostname or IP for VPN connections (auto-detected if omitted)")
	cmd.Flags().StringVar(&domain, "domain", "", "Platform domain (e.g., sandbox.bitswan.ai) — auto-detected from workspaces if omitted")

	return cmd
}

func newDestroyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "destroy",
		Short: "Tear down VPN infrastructure",
		Long:  "Stop and remove all VPN containers (WireGuard, VPN Traefik, CoreDNS) and delete VPN config.",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := getDaemonClient()
			req, err := http.NewRequest("POST", "http://daemon/vpn/destroy", nil)
			if err != nil {
				return err
			}
			resp, err := client.DoRequest(req)
			if err != nil {
				return fmt.Errorf("failed to destroy VPN: %w", err)
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			fmt.Println(result["message"])
			if errs, ok := result["errors"].([]interface{}); ok {
				for _, e := range errs {
					fmt.Printf("  Warning: %v\n", e)
				}
			}
			return nil
		},
	}
}

func newBootstrapCmd() *cobra.Command {
	var deviceName string

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Generate your VPN config (first admin)",
		Long: `Generate a WireGuard VPN configuration for yourself as the first administrator.

Use --device to name this device (e.g., "laptop", "desktop").
You can run bootstrap multiple times with different device names.

To give VPN access to other users, use 'bitswan vpn invite' instead.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := user.Current()
			if err != nil {
				return fmt.Errorf("failed to get current user: %w", err)
			}
			userID := u.Username
			if deviceName == "" {
				hostname, _ := os.Hostname()
				if hostname != "" {
					deviceName = hostname
				} else {
					deviceName = "default"
				}
			}

			cfg := config.NewAutomationServerConfig()
			serverConfig, _ := cfg.LoadConfig()
			slug := "wireguard"
			if serverConfig != nil && serverConfig.Slug != "" {
				slug = serverConfig.Slug
			}

			client := getDaemonClient()
			body := fmt.Sprintf(`{"user_id": %q, "device_name": %q}`, userID, deviceName)
			req, err := http.NewRequest("POST", "http://daemon/vpn/credentials", strings.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.DoRequest(req)
			if err != nil {
				return fmt.Errorf("failed to generate credentials: %w", err)
			}
			defer resp.Body.Close()

			outPath := slug + ".conf"
			f, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create %s: %w", outPath, err)
			}
			defer f.Close()
			io.Copy(f, resp.Body)

			fmt.Printf("VPN config written to %s (device: %s/%s)\n\n", outPath, userID, deviceName)
			printConnectionGuide(outPath, slug)
			return nil
		},
	}

	cmd.Flags().StringVar(&deviceName, "device", "", "Device name (e.g., 'laptop', 'phone') — defaults to hostname")

	return cmd
}

func newInviteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "invite",
		Short: "Generate a magic link to invite a user to the VPN",
		Long: `Generate a one-time magic link (valid 1 hour) that you can send to
a colleague. They open the link, authenticate via OAuth, and their
VPN config is generated automatically using their email as the user ID.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			u, _ := user.Current()
			createdBy := u.Username

			client := getDaemonClient()
			body := fmt.Sprintf(`{"created_by": %q}`, createdBy)
			req, err := http.NewRequest("POST", "http://daemon/vpn/magic-link", strings.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.DoRequest(req)
			if err != nil {
				return fmt.Errorf("failed to create magic link: %w", err)
			}
			defer resp.Body.Close()

			var result map[string]string
			json.NewDecoder(resp.Body).Decode(&result)

			fmt.Println("Magic link created!")
			fmt.Println()
			fmt.Printf("  Link:    %s\n", result["claim_url"])
			fmt.Printf("  Expires: %s\n", result["expires"])
			fmt.Println()
			fmt.Println("Send this link to the user. They will:")
			fmt.Println("  1. Open the link in their browser")
			fmt.Println("  2. Authenticate with their organization credentials (OAuth)")
			fmt.Println("  3. Download their personal WireGuard config")
			fmt.Println()
			fmt.Println("The link can only be used once and expires in 1 hour.")
			return nil
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show VPN status",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := getDaemonClient()
			req, _ := http.NewRequest("GET", "http://daemon/vpn/status", nil)
			resp, err := client.DoRequest(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var status map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&status)

			initialized, _ := status["initialized"].(bool)
			if !initialized {
				fmt.Println("VPN: not initialized")
				fmt.Println("Run 'bitswan vpn init --endpoint <hostname>' to set up")
				return nil
			}

			enabled, _ := status["enabled"].(bool)
			if enabled {
				fmt.Println("VPN: enabled")
			} else {
				fmt.Println("VPN: disabled")
			}
			if pub, ok := status["server_public_key"].(string); ok {
				fmt.Printf("Server public key: %s\n", pub)
			}
			if count, ok := status["user_count"].(float64); ok {
				fmt.Printf("Users: %d\n", int(count))
			}
			return nil
		},
	}
}

func newListDevicesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-devices",
		Short: "List all VPN devices",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := getDaemonClient()
			req, _ := http.NewRequest("GET", "http://daemon/vpn/users", nil)
			resp, err := client.DoRequest(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var devices []map[string]string
			json.NewDecoder(resp.Body).Decode(&devices)

			if len(devices) == 0 {
				fmt.Println("No VPN devices.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "DEVICE ID\tUSER\tDEVICE\tIP\tISSUED")
			for _, d := range devices {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					d["device_id"], d["user_id"], d["device_name"], d["ip"], d["issued_at"])
			}
			w.Flush()
			return nil
		},
	}
}

func newSessionsCmd() *cobra.Command {
	var active bool

	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "Show VPN session history and active connections",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := getDaemonClient()
			url := "http://daemon/vpn/sessions"
			if active {
				url += "?active=true"
			}
			req, _ := http.NewRequest("GET", url, nil)
			resp, err := client.DoRequest(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var events []map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&events)

			if len(events) == 0 {
				if active {
					fmt.Println("No active VPN sessions.")
				} else {
					fmt.Println("No VPN session history.")
				}
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			if active {
				fmt.Fprintln(w, "DEVICE\tUSER\tIP\tRX\tTX\tLAST SEEN")
				for _, e := range events {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
						str(e, "device_name"), str(e, "user_id"), str(e, "ip"),
						humanBytes(num(e, "transfer_rx")), humanBytes(num(e, "transfer_tx")),
						str(e, "timestamp"))
				}
			} else {
				fmt.Fprintln(w, "TIME\tEVENT\tDEVICE\tUSER\tSOURCE IP")
				for _, e := range events {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
						str(e, "timestamp"), str(e, "event"),
						str(e, "device_name"), str(e, "user_id"),
						str(e, "source_ip"))
				}
			}
			w.Flush()
			return nil
		},
	}

	cmd.Flags().BoolVar(&active, "active", false, "Show only currently active sessions")
	return cmd
}

func str(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func num(m map[string]interface{}, key string) int64 {
	if v, ok := m[key].(float64); ok {
		return int64(v)
	}
	return 0
}

func humanBytes(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1f KiB", float64(b)/1024)
	}
	if b < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MiB", float64(b)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GiB", float64(b)/(1024*1024*1024))
}

func newRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <user/device>",
		Short: "Revoke a VPN device",
		Long:  "Revoke a specific device's VPN access. Use 'bitswan vpn list-devices' to see device IDs.\nFormat: user/device (e.g., admin/laptop)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			client := getDaemonClient()
			body := fmt.Sprintf(`{"device_id": %q}`, deviceID)
			req, err := http.NewRequest("POST", "http://daemon/vpn/revoke", strings.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.DoRequest(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			fmt.Printf("Revoked VPN device %s\n", deviceID)
			return nil
		},
	}
}

func printConnectionGuide(confPath, slug string) {
	fmt.Println("=== WireGuard Connection Guide ===")
	fmt.Println()
	fmt.Println("--- Linux ---")
	fmt.Println()
	fmt.Println("  Install WireGuard:")
	fmt.Println("    Ubuntu/Debian:  sudo apt install wireguard")
	fmt.Println("    Fedora:         sudo dnf install wireguard-tools")
	fmt.Println("    Arch:           sudo pacman -S wireguard-tools")
	fmt.Println()
	fmt.Printf("  Copy the config and start the tunnel:\n")
	fmt.Printf("    sudo cp %s /etc/wireguard/%s.conf\n", confPath, slug)
	fmt.Printf("    sudo wg-quick up %s\n", slug)
	fmt.Println()
	fmt.Println("  To connect automatically on boot:")
	fmt.Printf("    sudo systemctl enable --now wg-quick@%s\n", slug)
	fmt.Println()
	fmt.Println("  To disconnect:")
	fmt.Printf("    sudo wg-quick down %s\n", slug)
	fmt.Println()
	fmt.Println("  Check connection status:")
	fmt.Println("    sudo wg show")
	fmt.Println()
	fmt.Println("--- macOS ---")
	fmt.Println()
	fmt.Println("  Option 1: WireGuard App (recommended)")
	fmt.Println("    1. Install WireGuard from the Mac App Store")
	fmt.Printf("    2. Open the app → \"Import Tunnel(s) from File\" → select %s\n", confPath)
	fmt.Println("    3. Click \"Activate\" to connect")
	fmt.Println()
	fmt.Println("  Option 2: Command line (Homebrew)")
	fmt.Println("    brew install wireguard-tools")
	fmt.Printf("    sudo cp %s /etc/wireguard/%s.conf\n", confPath, slug)
	fmt.Printf("    sudo wg-quick up %s\n", slug)
	fmt.Println()
	fmt.Println("--- Windows ---")
	fmt.Println()
	fmt.Println("  1. Download WireGuard from https://www.wireguard.com/install/")
	fmt.Printf("  2. Open the app → \"Import tunnel(s) from file\" → select %s\n", confPath)
	fmt.Println("  3. Click \"Activate\" to connect")
	fmt.Println()
	fmt.Println("--- Verify Connection ---")
	fmt.Println()
	fmt.Println("  After connecting, verify you can reach the internal services:")
	fmt.Println("    ping 10.8.0.1    (VPN gateway)")
	fmt.Println()
	fmt.Println("  If you can ping the gateway, your VPN is working and you can")
	fmt.Println("  access the editor, gitops, and dev automations through the VPN.")
}

// findDomainFromWorkspaces scans existing workspace metadata for a domain.
func findDomainFromWorkspaces() string {
	homeDir, _ := os.UserHomeDir()
	workspacesDir := filepath.Join(homeDir, ".config", "bitswan", "workspaces")
	entries, err := os.ReadDir(workspacesDir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		meta, err := config.GetWorkspaceMetadata(entry.Name())
		if err != nil {
			continue
		}
		if meta.Domain != "" {
			return meta.Domain
		}
	}
	return ""
}

func detectPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if ip == "" {
		return "", fmt.Errorf("empty response from IP detection service")
	}
	return ip, nil
}
