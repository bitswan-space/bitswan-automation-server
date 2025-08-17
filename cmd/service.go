package cmd

import (
	"github.com/bitswan-space/bitswan-workspaces/cmd/service"
	"github.com/spf13/cobra"
)

func newServiceCmd() *cobra.Command {
	return service.NewServiceCmd()
} 