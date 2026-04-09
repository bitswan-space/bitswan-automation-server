package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate the autocompletion script for the specified shell",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(
		newCompletionBashCmd(),
		newCompletionZshCmd(),
		newCompletionFishCmd(),
		newCompletionPowerShellCmd(),
		newCompletionInstallCmd(),
	)
	return cmd
}

func newCompletionBashCmd() *cobra.Command {
	var noDesc bool
	cmd := &cobra.Command{
		Use:   "bash",
		Short: "Generate the autocompletion script for bash",
		Long: `Generate the autocompletion script for the bash shell.

To load completions in your current shell session:
  source <(bitswan completion bash)

To load completions for every new session, execute once:
  # Linux:
  bitswan completion bash > /etc/bash_completion.d/bitswan
  # macOS:
  bitswan completion bash > $(brew --prefix)/etc/bash_completion.d/bitswan`,
		Args:                  cobra.NoArgs,
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var buf bytes.Buffer
			if err := cmd.Root().GenBashCompletionV2(&buf, !noDesc); err != nil {
				return err
			}
			// Trim trailing newline so our appended block sits cleanly.
			script := strings.TrimRight(buf.String(), "\n")
			fmt.Fprintln(os.Stdout, script)
			// Also register for ./bitswan so tab-completion works when invoking
			// the binary via a relative path (common during development).
			fmt.Fprintln(os.Stdout, "\n# Also register for ./bitswan (relative-path invocation)")
			fmt.Fprintln(os.Stdout, `if [[ $(type -t compopt) = "builtin" ]]; then`)
			fmt.Fprintln(os.Stdout, `    complete -o default -F __start_bitswan ./bitswan`)
			fmt.Fprintln(os.Stdout, `else`)
			fmt.Fprintln(os.Stdout, `    complete -o default -o nospace -F __start_bitswan ./bitswan`)
			fmt.Fprintln(os.Stdout, `fi`)
			return nil
		},
	}
	cmd.Flags().BoolVar(&noDesc, "no-descriptions", false, "disable completion descriptions")
	return cmd
}

func newCompletionZshCmd() *cobra.Command {
	var noDesc bool
	cmd := &cobra.Command{
		Use:   "zsh",
		Short: "Generate the autocompletion script for zsh",
		Long: `Generate the autocompletion script for the zsh shell.

To load completions in your current shell session:
  source <(bitswan completion zsh)

To load completions for every new session, execute once:
  bitswan completion zsh > "${fpath[1]}/_bitswan"`,
		Args:                  cobra.NoArgs,
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if noDesc {
				return cmd.Root().GenZshCompletionNoDesc(os.Stdout)
			}
			return cmd.Root().GenZshCompletion(os.Stdout)
		},
	}
	cmd.Flags().BoolVar(&noDesc, "no-descriptions", false, "disable completion descriptions")
	return cmd
}

func newCompletionFishCmd() *cobra.Command {
	var noDesc bool
	cmd := &cobra.Command{
		Use:   "fish",
		Short: "Generate the autocompletion script for fish",
		Long: `Generate the autocompletion script for the fish shell.

To load completions in your current shell session:
  bitswan completion fish | source

To load completions for every new session, execute once:
  bitswan completion fish > ~/.config/fish/completions/bitswan.fish`,
		Args:                  cobra.NoArgs,
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Root().GenFishCompletion(os.Stdout, !noDesc)
		},
	}
	cmd.Flags().BoolVar(&noDesc, "no-descriptions", false, "disable completion descriptions")
	return cmd
}

func newCompletionPowerShellCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "powershell",
		Short: "Generate the autocompletion script for powershell",
		Long: `Generate the autocompletion script for powershell.

To load completions in your current shell session:
  bitswan completion powershell | Out-String | Invoke-Expression`,
		Args:                  cobra.NoArgs,
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		},
	}
	return cmd
}

func newCompletionInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install shell completions for your current shell",
		Long: `Install shell completions for your current shell.

Detects the current shell from $SHELL and writes the completion script
to the appropriate user-level directory:

  bash  ~/.local/share/bash-completion/completions/bitswan
        (auto-loaded by bash-completion v2+ — no ~/.bashrc change needed)
  zsh   ~/.zsh/completions/_bitswan
        (add 'fpath=(~/.zsh/completions $fpath)' to ~/.zshrc if not present)
  fish  ~/.config/fish/completions/bitswan.fish

Run once after installing bitswan. Changes take effect in new shell sessions.`,
		Args:                  cobra.NoArgs,
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			shell := filepath.Base(os.Getenv("SHELL"))
			if shell == "" || shell == "." {
				return fmt.Errorf("$SHELL is not set; run 'bitswan completion <shell>' manually")
			}

			var dir, file string
			var generate func() error

			switch shell {
			case "bash":
				xdgData := os.Getenv("XDG_DATA_HOME")
				if xdgData == "" {
					xdgData = filepath.Join(os.Getenv("HOME"), ".local", "share")
				}
				dir = filepath.Join(xdgData, "bash-completion", "completions")
				file = filepath.Join(dir, "bitswan")
				generate = func() error {
					var buf bytes.Buffer
					if err := cmd.Root().GenBashCompletionV2(&buf, true); err != nil {
						return err
					}
					script := strings.TrimRight(buf.String(), "\n")
					script += "\n\n# Also register for ./bitswan (relative-path invocation)\n"
					script += "if [[ $(type -t compopt) = \"builtin\" ]]; then\n"
					script += "    complete -o default -F __start_bitswan ./bitswan\n"
					script += "else\n"
					script += "    complete -o default -o nospace -F __start_bitswan ./bitswan\n"
					script += "fi\n"
					return os.WriteFile(file, []byte(script), 0o644)
				}

			case "zsh":
				dir = filepath.Join(os.Getenv("HOME"), ".zsh", "completions")
				file = filepath.Join(dir, "_bitswan")
				generate = func() error {
					var buf bytes.Buffer
					if err := cmd.Root().GenZshCompletion(&buf); err != nil {
						return err
					}
					return os.WriteFile(file, buf.Bytes(), 0o644)
				}

			case "fish":
				xdgConfig := os.Getenv("XDG_CONFIG_HOME")
				if xdgConfig == "" {
					xdgConfig = filepath.Join(os.Getenv("HOME"), ".config")
				}
				dir = filepath.Join(xdgConfig, "fish", "completions")
				file = filepath.Join(dir, "bitswan.fish")
				generate = func() error {
					var buf bytes.Buffer
					if err := cmd.Root().GenFishCompletion(&buf, true); err != nil {
						return err
					}
					return os.WriteFile(file, buf.Bytes(), 0o644)
				}

			default:
				return fmt.Errorf("shell %q is not supported; run 'bitswan completion --help' to generate manually", shell)
			}

			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("creating completion directory: %w", err)
			}
			if err := generate(); err != nil {
				return fmt.Errorf("writing completion file: %w", err)
			}

			fmt.Fprintf(os.Stdout, "Completions installed to %s\n", file)

			switch shell {
			case "bash":
				fmt.Fprintln(os.Stdout, "Restart your shell or run:")
				fmt.Fprintf(os.Stdout, "  source %q\n", file)
			case "zsh":
				fmt.Fprintln(os.Stdout, "Ensure your ~/.zshrc contains:")
				fmt.Fprintln(os.Stdout, "  fpath=(~/.zsh/completions $fpath)")
				fmt.Fprintln(os.Stdout, "  autoload -Uz compinit && compinit")
			}

			return nil
		},
	}
}
