package automationserverdaemon

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

func newSyncWorkspacesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync-workspaces",
		Short: "Manually trigger workspace list publication to AOC",
		Long:  "Manually trigger publication of the current workspace list to AOC via MQTT. This ensures the AOC is synchronized with the actual workspaces on this automation server.",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			req, err := http.NewRequest("POST", "http://unix/workspace/sync", nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: Failed to create request: %v\n", err)
				os.Exit(1)
			}

			resp, err := client.DoRequest(req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: Failed to connect to daemon: %v\n", err)
				os.Exit(1)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				fmt.Fprintf(os.Stderr, "Error: Failed to publish workspace list: %s\n", string(body))
				os.Exit(1)
			}

			fmt.Println("✓ Workspace list published successfully")
			return nil
		},
	}

	return cmd
}
