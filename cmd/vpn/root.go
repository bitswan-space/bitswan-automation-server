package vpn

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
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
	cmd.AddCommand(newBootstrapCmd())
	cmd.AddCommand(newInviteCmd())
	cmd.AddCommand(newStatusCmd())
	cmd.AddCommand(newListUsersCmd())
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
				return fmt.Errorf("--endpoint is required (e.g., vpn.example.com or 203.0.113.1)")
			}

			// Load existing config to get the server slug
			cfg := config.NewAutomationServerConfig()
			serverConfig, err := cfg.LoadConfig()
			if err != nil {
				return fmt.Errorf("automation server not initialized — run 'bitswan automation-server-daemon init' first")
			}
			if serverConfig.Slug == "" {
				return fmt.Errorf("automation server has no name — this should have been set during init")
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

			var result map[string]string
			json.NewDecoder(resp.Body).Decode(&result)
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

	cmd.Flags().StringVar(&endpoint, "endpoint", "", "Public hostname or IP for VPN connections (required)")

	return cmd
}

func newBootstrapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "bootstrap",
		Short: "Generate your VPN config (first admin)",
		Long: `Generate a WireGuard VPN configuration for yourself as the first administrator.

This is only for initial setup. To give VPN access to other users,
use 'bitswan vpn invite' to generate a magic link instead.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Use system username as the user ID
			u, err := user.Current()
			if err != nil {
				return fmt.Errorf("failed to get current user: %w", err)
			}
			userID := u.Username

			client := getDaemonClient()
			body := fmt.Sprintf(`{"user_id": %q}`, userID)
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

			outPath := "wireguard.conf"
			f, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create %s: %w", outPath, err)
			}
			defer f.Close()
			io.Copy(f, resp.Body)

			fmt.Printf("VPN config written to %s\n\n", outPath)
			printConnectionGuide(outPath)
			return nil
		},
	}
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

func newListUsersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-users",
		Short: "List VPN users",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := getDaemonClient()
			req, _ := http.NewRequest("GET", "http://daemon/vpn/users", nil)
			resp, err := client.DoRequest(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			var users []map[string]string
			json.NewDecoder(resp.Body).Decode(&users)

			if len(users) == 0 {
				fmt.Println("No VPN users.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "USER\tIP\tPUBLIC KEY")
			for _, u := range users {
				fmt.Fprintf(w, "%s\t%s\t%s\n", u["id"], u["ip"], u["public_key"])
			}
			w.Flush()
			return nil
		},
	}
}

func newRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <user>",
		Short: "Revoke VPN access for a user",
		Long:  "Revoke a user's VPN access. Use 'bitswan vpn list-users' to see user IDs.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			userID := args[0]
			client := getDaemonClient()
			body := fmt.Sprintf(`{"user_id": %q}`, userID)
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

			fmt.Printf("Revoked VPN access for %s\n", userID)
			return nil
		},
	}
}

func printConnectionGuide(confPath string) {
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
	fmt.Printf("    sudo cp %s /etc/wireguard/wg0.conf\n", confPath)
	fmt.Println("    sudo wg-quick up wg0")
	fmt.Println()
	fmt.Println("  To connect automatically on boot:")
	fmt.Println("    sudo systemctl enable --now wg-quick@wg0")
	fmt.Println()
	fmt.Println("  To disconnect:")
	fmt.Println("    sudo wg-quick down wg0")
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
	fmt.Printf("    sudo cp %s /etc/wireguard/wg0.conf\n", confPath)
	fmt.Println("    sudo wg-quick up wg0")
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
