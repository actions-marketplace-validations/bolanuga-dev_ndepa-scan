package exporter

import "time"

// AuditMetadata contains high-level organizational details for the return.
type AuditMetadata struct {
	CompanyName string    `json:"company_name"`
	DPCOID      string    `json:"dpco_id"`
	Timestamp   time.Time `json:"timestamp"`
	TargetScope string    `json:"target_scope"`
}

// StaticFinding represents an IaC or Kubernetes manifest scan violation.
type StaticFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Line        int    `json:"line,omitempty"`
}

// EgressEvent represents dynamic eBPF sys_enter_connect socket telemetry.
type EgressEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	PodName     string    `json:"pod_name"`
	Namespace   string    `json:"namespace"`
	DestIP      string    `json:"dest_ip"`
	DestPort    int       `json:"dest_port"`
	Protocol    string    `json:"protocol"`
	ProcessName string    `json:"process_name"`
	Action      string    `json:"action"`
}

// ComplianceReport aggregates all gathered evidence for export.
type ComplianceReport struct {
	Metadata AuditMetadata   `json:"metadata"`
	Findings []StaticFinding `json:"findings"`
	Egress   []EgressEvent   `json:"egress_events"`
}
