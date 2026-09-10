# ndepa-scan

`ndepa-scan` is a Kubernetes-native compliance auditing platform built for the **Nigeria Data Protection Act (NDPA 2023)** standards. It combines static Infrastructure-as-Code (IaC) security analysis with dynamic eBPF-based runtime network egress tracing to produce verifiable Compliance Audit Returns (CAR).

---

## Features

- **Static IaC Scanner**: Evaluates Kubernetes manifests (`Pod`, `Deployment`, etc.) using Open Policy Agent (OPA) Rego rules.
- **Dynamic eBPF Trace Agent**: Monitored DaemonSet agent capturing real-time socket connections (`sys_enter_connect`) to identify unauthorized egress and PII exposure risks.
- **CAR Evidence Bundler**: Generates executive `audit_return.pdf` reports and exports timestamped ZIP archives (`.zip`) containing static findings and dynamic telemetry logs for DPCO submission.

---

## Quick Start

### Prerequisites
- Go `1.21+`
- Linux Kernel `5.4+` with BTF (`CONFIG_DEBUG_INFO_BTF=y`) enabled
- `clang` & `llvm` (for eBPF compilation)
- `kubectl` with access to a running Kubernetes cluster

### Installation & Build

```bash
# Clone repository
git clone [https://github.com/your-org/ndepa-scan.git](https://github.com/your-org/ndepa-scan.git)
cd ndepa-scan

# Download dependencies
go mod download

# Build CLI binary
go build -o bin/ndepa-scan ./cmd/ndepa-scan

