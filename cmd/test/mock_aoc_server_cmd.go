package test

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

func newMockAOCServerCmd() *cobra.Command {
	var port int
	var emqxSecret string
	var serverID string
	var orgID string
	var emqxURL string
	var emqxPort int

	cmd := &cobra.Command{
		Use:   "mock-aoc-server",
		Short: "Start a mock AOC server for testing",
		Long:  "Starts a simple HTTP server that mocks AOC API endpoints for MQTT testing",
		RunE: func(cmd *cobra.Command, args []string) error {
			server := NewMockAOCServer(port, emqxSecret, serverID, orgID, emqxURL, emqxPort)

			// Handle graceful shutdown
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

			go func() {
				<-sigChan
				fmt.Println("\nShutting down mock AOC server...")
				server.Stop()
				os.Exit(0)
			}()

			fmt.Printf("Starting mock AOC server on port %d...\n", port)
			fmt.Printf("  EMQX URL: %s:%d\n", emqxURL, emqxPort)
			fmt.Printf("  Server ID: %s\n", serverID)
			fmt.Printf("  Org ID: %s\n", orgID)

			if err := server.Start(); err != nil {
				return fmt.Errorf("failed to start mock AOC server: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&port, "port", 8080, "Port to listen on")
	cmd.Flags().StringVar(&emqxSecret, "emqx-secret", "", "EMQX JWT secret (required)")
	cmd.Flags().StringVar(&serverID, "server-id", "", "Automation server ID (required)")
	cmd.Flags().StringVar(&orgID, "org-id", "", "Organization ID (required)")
	cmd.Flags().StringVar(&emqxURL, "emqx-url", "aoc-emqx", "EMQX broker URL")
	cmd.Flags().IntVar(&emqxPort, "emqx-port", 1883, "EMQX broker port")

	cmd.MarkFlagRequired("emqx-secret")
	cmd.MarkFlagRequired("server-id")
	cmd.MarkFlagRequired("org-id")

	return cmd
}


