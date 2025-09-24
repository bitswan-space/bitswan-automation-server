package ingress

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/bitswan-space/bitswan-workspaces/internal/caddyapi"
	"github.com/bitswan-space/bitswan-workspaces/internal/dockercompose"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var verbose bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initializes an ingress proxy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := InitIngress(verbose); err != nil {
				return fmt.Errorf("failed to initialize ingress: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	return cmd
}

func runCommandVerbose(cmd *exec.Cmd, verbose bool) error {
	var stdoutBuf, stderrBuf bytes.Buffer

	if verbose {
		// Set up pipes for real-time streaming
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to create stdout pipe: %w", err)
		}

		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			return fmt.Errorf("failed to create stderr pipe: %w", err)
		}

		// Create multi-writers to both stream and capture output
		stdoutWriter := io.MultiWriter(os.Stdout, &stdoutBuf)
		stderrWriter := io.MultiWriter(os.Stderr, &stderrBuf)

		// Start the command
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start command: %w", err)
		}

		// Copy stdout and stderr in separate goroutines
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(stdoutWriter, stdoutPipe)
		}()

		go func() {
			defer wg.Done()
			io.Copy(stderrWriter, stderrPipe)
		}()

		// Wait for all output to be processed
		wg.Wait()

		// Wait for command to complete
		err = cmd.Wait()
		return err
	} else {
		// Not verbose, just capture output for potential error reporting
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf

		err := cmd.Run()

		// If command failed, print the captured output
		if err != nil {
			if stdoutBuf.Len() > 0 {
				fmt.Println("Command stdout:")
				fmt.Println(stdoutBuf.String())
			}

			if stderrBuf.Len() > 0 {
				fmt.Println("Command stderr:")
				fmt.Println(stderrBuf.String())
			}
		}

		return err
	}
}

func InitIngress(verbose bool) error {
	bitswanConfig := os.Getenv("HOME") + "/.config/bitswan/"
	caddyConfig := bitswanConfig + "caddy"
	caddyCertsDir := caddyConfig + "/certs"

	fmt.Println("Setting up ingress proxy...")
	if err := os.MkdirAll(caddyConfig, 0755); err != nil {
		return fmt.Errorf("failed to create ingress config directory: %w", err)
	}

	// Create Caddyfile with email and modify admin listener
	caddyfile := `
		{
			email info@bitswan.space
			admin 0.0.0.0:2019
		}`

	caddyfilePath := caddyConfig + "/Caddyfile"
	if err := os.WriteFile(caddyfilePath, []byte(caddyfile), 0755); err != nil {
		panic(fmt.Errorf("failed to write Caddyfile: %w", err))
	}

	caddyDockerCompose, err := dockercompose.CreateCaddyDockerComposeFile(caddyConfig)
	if err != nil {
		panic(fmt.Errorf("failed to create ingress docker-compose file: %w", err))
	}

	caddyDockerComposePath := caddyConfig + "/docker-compose.yml"
	if err := os.WriteFile(caddyDockerComposePath, []byte(caddyDockerCompose), 0755); err != nil {
		panic(fmt.Errorf("failed to write ingress docker-compose file: %w", err))
	}

	err = os.Chdir(caddyConfig)
	if err != nil {
		panic(fmt.Errorf("failed to change directory to ingress config: %w", err))
	}

	caddyProjectName := "bitswan-caddy"
	caddyDockerComposeCom := exec.Command("docker", "compose", "-p", caddyProjectName, "up", "-d")

	// Capture both stdout and stderr
	var stdout, stderr bytes.Buffer
	caddyDockerComposeCom.Stdout = &stdout
	caddyDockerComposeCom.Stderr = &stderr

	// Create certs directory if it doesn't exist
	if _, err := os.Stat(caddyCertsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(caddyCertsDir, 0740); err != nil {
			return fmt.Errorf("failed to create ingress certs directory: %w", err)
		}
	}

	fmt.Println("Starting ingress proxy...")
	if err := runCommandVerbose(caddyDockerComposeCom, verbose); err != nil {
		// Combine stdout and stderr for complete output
		fullOutput := stdout.String() + stderr.String()
		return fmt.Errorf("failed to start ingress:\nError: %v\nOutput:\n%s", err, fullOutput)
	}

	// wait 5s to make sure Caddy is up
	time.Sleep(5 * time.Second)
	err = caddyapi.InitCaddy()
	if err != nil {
		panic(fmt.Errorf("failed to init ingress: %w", err))
	}

	fmt.Println("Ingress proxy is ready!")
	return nil
} 