package exporter

import (
	"fmt"
	"path/filepath"

	"github.com/go-pdf/fpdf"
)

// GeneratePDF renders the DPCO compliance summary report to a PDF file.
func GeneratePDF(report *ComplianceReport, outputDir string) (string, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)

	// Header / Title
	pdf.Cell(40, 10, "DPCO Compliance Audit Return Report")
	pdf.Ln(12)

	// Metadata Section
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 8, "Organization Metadata")
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 10)
	pdf.Cell(40, 6, fmt.Sprintf("Company Name: %s", report.Metadata.CompanyName))
	pdf.Ln(6)
	pdf.Cell(40, 6, fmt.Sprintf("DPCO ID:      %s", report.Metadata.DPCOID))
	pdf.Ln(6)
	pdf.Cell(40, 6, fmt.Sprintf("Generated:    %s", report.Metadata.Timestamp.Format("2006-01-02 15:04:05 UTC")))
	pdf.Ln(10)

	// Summary Section
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 8, "Audit Findings Summary")
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 10)
	pdf.Cell(40, 6, fmt.Sprintf("Static IaC Violations Found: %d", len(report.Findings)))
	pdf.Ln(6)
	pdf.Cell(40, 6, fmt.Sprintf("Dynamic eBPF Egress Events Traced: %d", len(report.Egress)))
	pdf.Ln(10)

	pdfPath := filepath.Join(outputDir, "audit_return.pdf")
	err := pdf.OutputFileAndClose(pdfPath)
	if err != nil {
		return "", fmt.Errorf("failed to save PDF report: %w", err)
	}

	return pdfPath, nil
}
