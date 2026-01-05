package cmd

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/daemon"
	"github.com/spf13/cobra"
)

type initOptions struct {
	remoteRepo         string
	workspaceBranch    string
	domain             string
	certsDir           string
	verbose            bool
	mkCerts            bool
	noIde              bool
	setHosts           bool
	local              bool
	gitopsImage        string
	editorImage        string
	gitopsDevSourceDir string
	oauthConfigFile    string
	noOauth            bool
	sshPort            string
}

func defaultInitOptions() *initOptions {
	return &initOptions{}
}

func newInitCmd() *cobra.Command {
	o := defaultInitOptions()

	cmd := &cobra.Command{
		Use:   "init [flags] <workspace-name>",
		Short: "Initializes a new GitOps, Caddy and Bitswan editor",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := daemon.NewClient()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				fmt.Fprintln(os.Stderr, "Run 'bitswan automation-server-daemon init' to start it.")
				os.Exit(1)
			}

			// Pass through original args (excluding binary)
			if err := client.WorkspaceInit(os.Args[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&o.remoteRepo, "remote", "", "The remote repository to clone")
	cmd.Flags().StringVar(&o.workspaceBranch, "branch", "", "The branch to clone from the remote repository (defaults to the repository's default branch)")
	cmd.Flags().StringVar(&o.domain, "domain", "", "The domain to use for the Caddyfile")
	cmd.Flags().StringVar(&o.certsDir, "certs-dir", "", "The directory where the certificates are located")
	cmd.Flags().BoolVar(&o.noIde, "no-ide", false, "Do not start Bitswan Editor")
	cmd.Flags().BoolVarP(&o.verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&o.mkCerts, "mkcerts", false, "Automatically generate local certificates using the mkcerts utility")
	cmd.Flags().BoolVar(&o.setHosts, "set-hosts", false, "Automatically set hosts to /etc/hosts file")
	cmd.Flags().BoolVar(&o.local, "local", false, "Automatically use flag --set-hosts and --mkcerts. If no domain is set defaults to bs-<workspacename>.localhost")
	cmd.Flags().StringVar(&o.gitopsImage, "gitops-image", "", "Custom image for the gitops")
	cmd.Flags().StringVar(&o.editorImage, "editor-image", "", "Custom image for the editor")
	cmd.Flags().StringVar(&o.gitopsDevSourceDir, "gitops-dev-source-dir", "", "Directory to mount as /src/app in gitops container for development")
	cmd.Flags().StringVar(&o.oauthConfigFile, "oauth-config", "", "OAuth config file")
	cmd.Flags().BoolVar(&o.noOauth, "no-oauth", false, "Disable automatically fetching OAuth configuration from AOC")
	cmd.Flags().StringVar(&o.sshPort, "ssh-port", "", "Use SSH over a custom port with custom SSH config for repositories behind firewalls (e.g., 443, 22)")
	return cmd
}
