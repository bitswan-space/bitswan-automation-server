package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type MetadataOpen struct {
	EditorURL *string `yaml:"editor-url,omitempty"`
}

func newOpenCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "open",
		Short:             "Open the editor for a workspace",
		Args:              cobra.ExactArgs(1),
		SilenceUsage:      true,
		ValidArgsFunction: validWorkspaceArgs,
		RunE:              runOpenCmd,
	}
}

func runOpenCmd(cmd *cobra.Command, args []string) error {
	workspacePath := filepath.Join(os.Getenv("HOME"), ".config/bitswan/workspaces", args[0])
	metadataPath := filepath.Join(workspacePath, "metadata.yaml")

	metadata, err := loadMetadata(metadataPath)
	if err != nil {
		return err
	}

	if metadata.EditorURL == nil {
		return fmt.Errorf("no editor URL found in metadata.yaml")
	}

	fmt.Printf("Opening editor at: %s\n", *metadata.EditorURL)
	return openURL(*metadata.EditorURL)
}

func loadMetadata(metadataPath string) (*MetadataOpen, error) {
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	var metadata MetadataOpen
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata file: %w", err)
	}

	return &metadata, nil
}

func openURL(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return fmt.Errorf("unsupported operating system")
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to open URL: %w", err)
	}

	return nil
}
