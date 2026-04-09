package cmd

import (
	"bytes"
	"fmt"
	"os"
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
