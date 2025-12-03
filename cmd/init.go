package cmd

import (
	"fmt"
	"os"

	"github.com/bitswan-space/bitswan-workspaces/internal/commands"
	"github.com/bitswan-space/bitswan-workspaces/internal/daemonapi"
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

type DockerNetwork struct {
	Name      string `json:"Name"`
	ID        string `json:"ID"`
	CreatedAt string `json:"CreatedAt"`
	Driver    string `json:"Driver"`
	IPv6      string `json:"IPv6"`
	Internal  string `json:"Internal"`
	Labels    string `json:"Labels"`
	Scope     string `json:"Scope"`
}

type RepositoryInfo struct {
	Hostname string
	Org      string
	Repo     string
	IsSSH    bool
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
		RunE:  o.run,
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

func (o *initOptions) run(cmd *cobra.Command, args []string) error {
	// Execute directly (we're in the daemon or daemon is not running)
	opts := commands.WorkspaceInitOptions{
		WorkspaceName:      args[0],
		RemoteRepo:         o.remoteRepo,
		WorkspaceBranch:    o.workspaceBranch,
		Domain:             o.domain,
		CertsDir:           o.certsDir,
		Verbose:            o.verbose,
		MkCerts:            o.mkCerts,
		NoIde:              o.noIde,
		SetHosts:           o.setHosts,
		Local:              o.local,
		GitopsImage:        o.gitopsImage,
		EditorImage:        o.editorImage,
		GitopsDevSourceDir: o.gitopsDevSourceDir,
		OauthConfigFile:    o.oauthConfigFile,
		NoOauth:            o.noOauth,
		SSHPort:            o.sshPort,
	}
	
	// Generate workspace token if daemon is running
	bitswanConfig := os.Getenv("HOME") + "/.config/bitswan/"
	var workspaceToken string
	tokenManager, err := daemonapi.NewTokenManager(bitswanConfig)
	if err == nil {
		workspaceToken, err = tokenManager.CreateWorkspaceToken(args[0], fmt.Sprintf("GitOps token for workspace %s", args[0]))
		if err != nil {
			fmt.Printf("Warning: Failed to create workspace token: %v\n", err)
		} else {
			fmt.Printf("Generated workspace token for GitOps container\n")
		}
	} else {
		fmt.Printf("Warning: Failed to initialize token manager: %v\n", err)
	}
	opts.WorkspaceToken = workspaceToken
	
	return commands.ExecuteWorkspaceInit(opts)
}
