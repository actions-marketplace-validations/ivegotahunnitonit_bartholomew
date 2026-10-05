import pytest
from fastapi.testclient import TestClient
from src.api.cloud_engine_server import app
from src.kernel_interceptor import KernelTrajectoryInterceptor

@pytest.fixture
def client():
    return TestClient(app)

def test_datacenter_enclave_attestation_success(client):
    payload = {
        "module_id": "dc-nitro-pod-99",
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAXtestHardwareAttestationKey000000000000000000000=\n-----END PUBLIC KEY-----",
        "nonce": "fresh-challenge-nonce-12345"
    }
    response = client.post("/api/v1/enclave/attest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["attested"] is True
    assert data["hardware_certified"] is True
    assert data["module_id"] == "dc-nitro-pod-99"
    assert "receipt_sha256" in data
    assert "enclave_ticket" in data
    assert data["pcr_measurements"]["nonce"] == "fresh-challenge-nonce-12345"
    assert data["latency_us"] > 0

def test_datacenter_enclave_attestation_tampered_fails(client):
    payload = {
        "module_id": "dc-nitro-pod-tampered",
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAXtestHardwareAttestationKey000000000000000000000=\n-----END PUBLIC KEY-----",
        "nonce": "fresh-challenge-nonce-12345",
        "custom_pcr0": "tampered_unauthorized_kernel_hash_00000000000000000000000000000000"
    }
    response = client.post("/api/v1/enclave/attest", json=payload)
    assert response.status_code == 403
    assert "Enclave Attestation Rejected" in response.json()["detail"]

def test_datacenter_workload_govern_approved(client):
    payload = {
        "tenant_id": "tenant-finance-01",
        "container_id": "container-pod-88",
        "action": "sys_enter_execve",
        "payload": {"cmd": "python train_risk_model.py", "batch": 100},
        "compute_units": 2.0,
        "memory_mb": 512.0,
        "egress_kb": 1024.0
    }
    response = client.post("/api/v1/workload/govern", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] is True
    assert data["verdict"] == "APPROVED"
    assert "receipt_sha256" in data
    assert data["quota_status"]["used_memory_mb"] == 512.0

def test_datacenter_workload_govern_blocked_destructive(client):
    payload = {
        "tenant_id": "tenant-finance-01",
        "container_id": "container-pod-rogue",
        "action": "sys_enter_execve",
        "payload": {"cmd": "rm -rf / --no-preserve-root"},
        "compute_units": 1.0,
        "memory_mb": 128.0,
        "egress_kb": 0.0
    }
    response = client.post("/api/v1/workload/govern", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] is False
    assert data["verdict"] == "BLOCKED"
    assert "eBPF KILL-SWITCH" in data["reason"]

def test_datacenter_workload_govern_memory_cap(client):
    payload = {
        "tenant_id": "tenant-finance-capped",
        "container_id": "container-pod-leak",
        "action": "sys_enter_execve",
        "payload": {"cmd": "load_massive_dataset"},
        "compute_units": 1.0,
        "memory_mb": 4096.0,  # Exceeds default 2048 MB
        "egress_kb": 10.0
    }
    response = client.post("/api/v1/workload/govern", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["allowed"] is False
    assert data["verdict"] == "QUOTA_EXCEEDED"
    assert "RESOURCE-CAP" in data["reason"]

def test_kernel_interceptor_direct():
    interceptor = KernelTrajectoryInterceptor()
    interceptor.register_tenant("tenant-test", max_memory_mb=500.0, max_egress_kb=1000.0)

    # Allowed
    allowed, msg, meta = interceptor.govern_syscall(
        syscall="sys_enter_openat",
        process_pid=1234,
        agent_ctx="ctx-1",
        payload_args=["/var/log/app.log"],
        tenant_id="tenant-test",
        memory_mb=200.0
    )
    assert allowed is True
    assert meta["status"] == "APPROVED"
    assert meta["latency_us"] < 100.0

    # Quota exceeded
    allowed2, msg2, meta2 = interceptor.govern_syscall(
        syscall="sys_enter_openat",
        process_pid=1235,
        agent_ctx="ctx-1",
        payload_args=["/var/log/app2.log"],
        tenant_id="tenant-test",
        memory_mb=600.0
    )
    assert allowed2 is False
    assert meta2["status"] == "QUOTA_EXCEEDED"
