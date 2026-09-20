package exporter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Aggregator struct {
	Metadata AuditMetadata
}

func NewAggregator(companyName, dpcoID, scope string) *Aggregator {
	return &Aggregator{
		Metadata: AuditMetadata{
			CompanyName: companyName,
			DPCOID:      dpcoID,
			Timestamp:   time.Now().UTC(),
			TargetScope: scope,
		},
	}
}

// Aggregate parses static findings and dynamic eBPF runtime trace events.
func (a *Aggregator) Aggregate(staticPath, dynamicPath string) (*ComplianceReport, error) {
	report := &ComplianceReport{
		Metadata: a.Metadata,
		Findings: make([]StaticFinding, 0),
		Egress:   make([]EgressEvent, 0),
	}

	if staticPath != "" {
		findings, err := parseStaticFindings(staticPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse static findings: %w", err)
		}
		report.Findings = findings
	}

	if dynamicPath != "" {
		events, err := parseEgressEvents(dynamicPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse dynamic egress events: %w", err)
		}
		report.Egress = events
	}

	return report, nil
}

func parseStaticFindings(path string) ([]StaticFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var findings []StaticFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, err
	}
	return findings, nil
}

func parseEgressEvents(path string) ([]EgressEvent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var events []EgressEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, err
	}
	return events, nil
}
