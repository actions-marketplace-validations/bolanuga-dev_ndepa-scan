package exporter

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// CreateBundle packages the PDF summary report and raw JSON findings into a .zip archive.
func CreateBundle(report *ComplianceReport, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	pdfPath, err := GeneratePDF(report, outputDir)
	if err != nil {
		return "", err
	}

	zipFileName := fmt.Sprintf("dpco_evidence_%s_%s.zip", 
		report.Metadata.CompanyName, 
		time.Now().Format("20060102_150405"))
	
	zipPath := filepath.Join(outputDir, zipFileName)
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip file: %w", err)
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	// Add PDF Report
	if err := addFileToZip(archive, pdfPath, "audit_return.pdf"); err != nil {
		return "", err
	}

	// Add Static Findings Raw JSON
	staticData, _ := json.MarshalIndent(report.Findings, "", "  ")
	if err := addBytesToZip(archive, staticData, "static_findings.json"); err != nil {
		return "", err
	}

	// Add Dynamic eBPF Telemetry Raw JSON
	egressData, _ := json.MarshalIndent(report.Egress, "", "  ")
	if err := addBytesToZip(archive, egressData, "ebpf_runtime_events.json"); err != nil {
		return "", err
	}

	return zipPath, nil
}

func addFileToZip(archive *zip.Writer, srcPath, destName string) error {
	file, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer, err := archive.Create(destName)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, file)
	return err
}

func addBytesToZip(archive *zip.Writer, data []byte, destName string) error {
	writer, err := archive.Create(destName)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}
