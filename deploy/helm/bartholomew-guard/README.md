# Bartholomew Data Centre Helm Chart (BTP v6.4.3)

Official Helm chart for deploying Bartholomew Keystone Guard, Confidential Enclave Attestation, and eBPF Ring-0 Kernel Gating across Kubernetes clusters (AWS EKS, GCP GKE, Azure AKS, on-premises).

---

## Architecture Overview

```
                      +---------------------------------------+
                      |   Bartholomew Control Plane Gateway   |
                      |   (/api/v1/enclave/attest, govern)    |
                      +-------------------+-------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                                                   |
+-------v-------------------------+                       +-----------------v---------------+
|    eBPF Kernel Guard DaemonSet   |                       |    Workload Admission Webhook   |
|  - Ring-0 execve/connect hook   |                       |  - Enforce memory ceilings      |
|  - Sub-microsecond kill-switch  |                       |  - Inject Keystone passkeys     |
+---------------------------------+                       +---------------------------------+
```

---

## Installation

```bash
# Add repo or clone
git clone https://github.com/bartholomew-security/bartholomew.git
cd bartholomew/deploy/helm/bartholomew-guard

# Install release
helm install bartholomew-guard . \
  --namespace bartholomew-system \
  --create-namespace \
  --set datacenter.ebpfDaemon.enabled=true \
  --set datacenter.enclaveAttestation.enabled=true
```

---

## Configuration Parameters

| Parameter | Description | Default |
| :--- | :--- | :--- |
| `replicaCount` | Number of control plane gateway replicas | `3` |
| `image.repository` | Docker image repository | `ghcr.io/ivegotahunnitonit/bartholomew` |
| `image.tag` | Docker image tag | `6.4.3` |
| `datacenter.ebpfDaemon.enabled` | Deploy Ring-0 eBPF syscall interceptor DaemonSet | `true` |
| `datacenter.enclaveAttestation.enabled` | Enable confidential enclave hardware attestation | `true` |
| `datacenter.quotas.defaultMemoryMb` | Default memory quota ceiling per agent pod | `2048.0` |
| `datacenter.quotas.defaultEgressKb` | Default network egress cap per agent pod | `100000.0` |
| `ast.maxLatencyUs` | Maximum allowed AST evaluation SLA | `35` |

---

## Verification

```bash
# Verify DaemonSet status across nodes
kubectl get daemonset -n bartholomew-system

# Check eBPF kernel interceptor logs
kubectl logs -n bartholomew-system -l app.kubernetes.io/name=bartholomew-guard-ebpf --tail=50
```

Distributed under the MIT License.
