package cmd

import (
	"fmt"

	"github.com/spf13/cobra"   
	"github.com/ndepa-scan/ndepa-scan/pkg/exporter"
)

var (
	staticInput  string
	dynamicInput string
	outputDir    string
	companyName  string
	dpcoID       string
)

// exportCarCmd represents the export-car subcommand
var exportCarCmd = &cobra.Command{
	Use:   "export-car",
	Short: "Export DPCO Compliance Audit Return (CAR) evidence bundle",
	Long: `Aggregates static IaC scan findings and dynamic eBPF network egress logs
into a formatted DPCO compliance audit bundle containing executive reports and raw evidence.`,
	 RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("[+] Initializing DPCO Evidence Exporter...")
		fmt.Printf("    Organization: %s\n", companyName)
		fmt.Printf("    DPCO ID:      %s\n", dpcoID)

		agg := exporter.NewAggregator(companyName, dpcoID, "Kubernetes Cluster Scope")
		report, err := agg.Aggregate(staticInput, dynamicInput)
		if err != nil {
			return fmt.Errorf("failed to aggregate audit evidence: %w", err)
		}

		fmt.Printf("[+] Aggregated %d static findings and %d runtime egress events.\n",
			len(report.Findings), len(report.Egress))

		bundlePath, err := exporter.CreateBundle(report, outputDir)
		if err != nil {
			return fmt.Errorf("failed to generate evidence bundle: %w", err)
		}

		fmt.Printf("[+] CAR evidence bundle created successfully: %s\n", bundlePath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(exportCarCmd)

	exportCarCmd.Flags().StringVarP(&staticInput, "static-input", "s", "", "Path to static scan findings (JSON)")
	exportCarCmd.Flags().StringVarP(&dynamicInput, "dynamic-input", "d", "", "Path to dynamic eBPF egress log file (JSON)")
	exportCarCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "./car-output", "Directory where the generated evidence bundle will be saved")
	exportCarCmd.Flags().StringVar(&companyName, "company-name", "", "Name of the Data Controller / Organization")
	exportCarCmd.Flags().StringVar(&dpcoID, "dpco-id", "", "Registered DPCO auditor/partner identifier")

	_ = exportCarCmd.MarkFlagRequired("company-name")
	_ = exportCarCmd.MarkFlagRequired("dpco-id")
}
