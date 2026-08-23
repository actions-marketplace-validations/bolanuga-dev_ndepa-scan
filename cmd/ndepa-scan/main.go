package main

import (
	"log"

	"github.com/ndepa-scan/ndepa-scan/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatalf("Execution failed: %v", err)
	}
}
