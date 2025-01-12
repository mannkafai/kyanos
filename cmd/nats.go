package cmd

import (
	"kyanos/agent/protocol/nats"

	"github.com/spf13/cobra"
)

var natsCmd *cobra.Command = &cobra.Command{
	Use:   "nats",
	Short: "watch NATS message",
	Run: func(cmd *cobra.Command, args []string) {
		options.MessageFilter = nats.NATSFilter{}
		options.LatencyFilter = initLatencyFilter(cmd)
		options.SizeFilter = initSizeFilter(cmd)
		startAgent()
	},
}

func init() {
	natsCmd.PersistentFlags().SortFlags = false
	copy := *natsCmd
	watchCmd.AddCommand(&copy)
	copy2 := *natsCmd
	statCmd.AddCommand(&copy2)
}
