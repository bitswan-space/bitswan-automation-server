package vpn

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

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
	cmd.AddCommand(newStatusCmd())
	cmd.AddCommand(newListUsersCmd())
	cmd.AddCommand(newGenerateCredsCmd())
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
		Long:  "Sets up the WireGuard server, VPN network, and VPN Traefik. All workspaces will use this VPN.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if endpoint == "" {
				return fmt.Errorf("--endpoint is required (e.g., vpn.example.com or 203.0.113.1)")
			}

			client := getDaemonClient()
			body := fmt.Sprintf(`{"endpoint": %q}`, endpoint)
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
			return nil
		},
	}

	cmd.Flags().StringVar(&endpoint, "endpoint", "", "Public hostname or IP for VPN connections (required)")

	return cmd
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
			fmt.Fprintln(w, "USER ID\tIP\tPUBLIC KEY")
			for _, u := range users {
				fmt.Fprintf(w, "%s\t%s\t%s\n", u["id"], u["ip"], u["public_key"])
			}
			w.Flush()
			return nil
		},
	}
}

func newGenerateCredsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "generate-credentials <user-id>",
		Short: "Generate VPN credentials for a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			userID := args[0]
			client := getDaemonClient()
			body := fmt.Sprintf(`{"user_id": %q}`, userID)
			req, err := http.NewRequest("POST", "http://daemon/vpn/credentials", strings.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.DoRequest(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			outPath := userID + ".conf"
			f, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create %s: %w", outPath, err)
			}
			defer f.Close()
			io.Copy(f, resp.Body)

			fmt.Printf("VPN config written to %s\n", outPath)
			return nil
		},
	}
}

func newRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <user-id>",
		Short: "Revoke VPN access for a user",
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
