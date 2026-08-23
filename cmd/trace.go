package cmd

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/ndepa-scan/ndepa-scan/pkg/ebpf"
)

var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "Start dynamic eBPF runtime monitoring for NDPA PII egress compliance",
	Run: func(cmd *cobra.Command, args []string) {
                log.Println("Starting eBPF dynamic egress tracer...")
		if err := ebpf.RunTracer(); err != nil {
			log.Fatalf("eBPF tracer error: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(traceCmd)
}
