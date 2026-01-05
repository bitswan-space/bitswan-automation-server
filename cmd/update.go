package cmd

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

type updateOptions struct {
	gitopsImage    string
	editorImage    string
	kafkaImage     string
	zookeeperImage string
	couchdbImage   string
	staging        bool
	trustCA        bool
}

func newUpdateCmd() *cobra.Command {
	o := &updateOptions{}
	cmd := &cobra.Command{
		Use:          "update <workspace-name>",
		Short:        "bitswan workspace update",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			// Pass through original args (excluding binary)
			if err := client.WorkspaceUpdate(os.Args[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&o.gitopsImage, "gitops-image", "", "Custom image for the gitops")
	cmd.Flags().StringVar(&o.editorImage, "editor-image", "", "Custom image for the editor")
	cmd.Flags().StringVar(&o.kafkaImage, "kafka-image", "", "Custom image for Kafka")
	cmd.Flags().StringVar(&o.zookeeperImage, "zookeeper-image", "", "Custom image for Zookeeper")
	cmd.Flags().StringVar(&o.couchdbImage, "couchdb-image", "", "Custom image for CouchDB")
	cmd.Flags().BoolVar(&o.staging, "staging", false, "Use staging images for editor and gitops")
	cmd.Flags().BoolVar(&o.trustCA, "trust-ca", false, "Install custom certificates from the default CA certificates directory.")

	return cmd
}
