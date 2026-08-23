package cmd

import (
	"embed"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ndepa-scan/ndepa-scan/pkg/parser"
        "github.com/spf13/cobra" 
	"github.com/open-policy-agent/opa/rego"
)

//go:embed ndpa_policies.rego
var embeddedPolicies embed.FS

type ScanResult struct {
	Target     string   `json:"target"`
	Time       string   `json:"timestamp"`
	Status     string   `json:"status"`
	Violations []string `json:"violations"`
}

var (
	policyDir    string
	outputFormat string
)

var rootCmd = &cobra.Command{
	Use:   "ndepa-scan [targetPath]",
	Short: "NDPA static policy scanner and eBPF dynamic egress tracer",
	Args:  cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			return
		}

		targetPath := args[0]

		// 1. Handle input reading
		var reader io.Reader
		if targetPath == "-" {
			reader = os.Stdin
		} else {
			file, err := os.Open(targetPath)
			if err != nil {
				log.Fatalf("Failed to open file: %v", err)
			}
			defer file.Close()
			reader = file
		}

		// 2. Parse documents 
		documents, err := parser.ParseYAMLOrJSON(reader)
		if err != nil {
                	log.Fatalf("Error parsing input: %v", err)
		}
		// 3. Prepare Rego evaluation options
		var regoOptions []func(*rego.Rego)
		regoOptions = append(regoOptions, rego.Query("data.ndepa.policies"))




	// 1. Load Embedded Policies
	policyBytes, err := embeddedPolicies.ReadFile("ndpa_policies.rego")
	if err != nil {
		log.Fatalf("Failed to read embedded policy file: %v", err)
	}
	regoOptions = append(regoOptions, rego.Module("ndpa_policies.rego", string(policyBytes)))

	// 2. Load Custom Policy Directory (if flag is passed)
	if policyDir != "" {
		files, err := os.ReadDir(policyDir)
		if err != nil {
			log.Fatalf("Failed to read custom policy dir: %v", err)
		}
		for _, f := range files {
			if !f.IsDir() && filepath.Ext(f.Name()) == ".rego" {
				content, err := os.ReadFile(filepath.Join(policyDir, f.Name()))
				if err != nil {
					log.Fatalf("Failed to read policy %s: %v", f.Name(), err)
				}
				regoOptions = append(regoOptions, rego.Module(f.Name(), string(content)))
			}
		}
	}

	ctx := context.Background()
	query, err := rego.New(regoOptions...).PrepareForEval(ctx)
	if err != nil {
		log.Fatalf("Failed to compile OPA policy: %v", err)
	}

	var allViolations []string
	for _, doc := range documents {
		results, err := query.Eval(ctx, rego.EvalInput(doc))
		if err != nil {
		log.Fatalf("Policy evaluation failed: %v", err)
		}
		if len(results) > 0 {
			for _, expression := range results[0].Expressions {
				if items, ok := expression.Value.([]interface{}); ok {
					for _, item := range items {
						allViolations = append(allViolations, fmt.Sprintf("%v", item))
					}
				}
			}
		}
	}


// Output Formatting
	timestamp := time.Now().UTC().Format(time.RFC3339)
	status := "PASS"
	if len(allViolations) > 0 {
		status = "FAIL"
	}

	switch outputFormat {
	case "json":
		res := ScanResult{
			Target:     targetPath,
			Time:       timestamp,
			Status:     status,
			Violations: allViolations,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(res)

	case "sarif":
        	sarifBytes, err := parser.ConvertViolationsToSARIF(targetPath, allViolations)
		if err != nil {
			log.Fatalf("Error generating SARIF output: %v", err)
		}
		fmt.Println(string(sarifBytes))

	default:
		fmt.Println("==================================================")
		fmt.Println("       NDPA 2023 COMPLIANCE SCANNER RESULTS       ")
		fmt.Println("==================================================")
		fmt.Printf("Target: %s\n", targetPath)
		fmt.Printf("Time:   %s\n", timestamp)
		fmt.Println("==================================================")
		fmt.Println()

                if len(allViolations) > 0 {
		   fmt.Printf("❌ VIOLATIONS DETECTED (%d):\n", len(allViolations))
		   for i, v := range allViolations {
		      fmt.Printf("  %d. %s\n", i+1, v)
		   }
		} else {
		   fmt.Println("PASS: No NDPA violations detected!")
		}
	     } // Closes switch *outputFormat
          }, // Closes func main()
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringVarP(&policyDir, "policy-dir", "p", "", "Directory containing custom Rego policies")
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "text", "Output format (text, json, sarif)")
}

