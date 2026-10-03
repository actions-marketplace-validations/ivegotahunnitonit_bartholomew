# Bartholomew Trust Boundary & Reproducible Demo
**Verifiable Security Proof: What Bartholomew Protects, What It Blocks, and What It Does NOT Cover**

---

## 1. Why Precision Matters More Than Sweeping Claims

In enterprise developer security, sweeping claims ("100% impenetrable AI security") erode trust. Platform engineers and CISOs need to know **exact deterministic boundaries**:

1. What happens during routine safe work? (Must be zero friction / sub-35µs).
2. What happens during a rogue or hallucinated destructive command? (Must be fail-closed, sub-millisecond, logged).
3. What is deliberately **out of scope**? (What Bartholomew does *not* claim to fix).

---

## 2. The 3-Part Reproducible Demonstration

You can run this live test on any machine with Python 3.9+ in 2 seconds:

```bash
# Clone or run inside your workspace:
python -m btp_guard.demo_trust_boundary
```

### Case 1: Allowed Action (Routine Developer Tool Call)
* **Scenario**: Cursor / Claude Code agent runs unit tests and checks git status.
* **Command**: `npm test -- --coverage`
* **Verdict**: `[ALLOW]` (Exit Code: 0)
* **Overhead**: Sub-35 microseconds.
* **Merkle Proof**: Ed25519-signed execution receipt.
* **Developer Experience**: Zero latency, zero false positives on standard toolchains.

### Case 2: Blocked Action (Catastrophic / Rogue Operation)
* **Scenario**: Prompt injection, hallucinated wipe, or unauthorized script exfiltration.
* **Command**: `rm -rf / --no-preserve-root` (or `format C: /q /y` on Windows)
* **Verdict**: `[DENY - BLOCKED FAIL-CLOSED]` (Exit Code: 1)
* **Interception**: Sub-millisecond in-process AST gating.
* **Audit Trail**: Tamper-evident SHA-256 event logged to local `.btp/audit.log`.
* **Developer Experience**: Host filesystem preserved, clear explanatory feedback returned to the agent context.

### Case 3: Case Bartholomew Does NOT Cover (Explicit Scope Boundary)
* **Scenario**: Agent generates syntactically valid code containing a logical flaw (e.g. wrong tax bracket calculation or $O(N^3)$ nested loops).
* **Code Snippet**: `def calculate_tax(income): return income * 0.00`
* **Verdict**: `[PASSED UNTOUCHED]`
* **Why It Passes**: Bartholomew is an **Agentic Runtime Protection (ARP)** firewall for **operating system boundaries** (files, terminals, sockets, micro-billing spend). Bartholomew is **NOT** a code quality linter or an LLM truth judge.
* **Boundary Guarantee**: We guarantee an agent cannot wipe your disk or exfiltrate your API keys. We do **not** guarantee that code written by an LLM is bug-free.

---

## 3. Scope Matrix

| Action / Threat Vector | Bartholomew Posture | Mechanism |
| :--- | :---: | :--- |
| **Destructive Terminal Wipe (`rm -rf`, `mkfs`, `format C:`)** | **BLOCKED** | In-process AST invariant gate (<35µs) |
| **Credential / Key Leaks (`.env`, `id_rsa`, API tokens)** | **BLOCKED** | In-flight secret regex scrubber |
| **Pipe-to-Shell Remote Exploits (`curl ... \| bash`)** | **BLOCKED** | Quarantine barrier |
| **Unbounded Agent Micro-Billing Spend** | **BLOCKED** | Keystone passkey budget ceiling |
| **Semantic Code Bugs & Hallucinated Logic** | **OUT OF SCOPE** | Use your existing test suite / CI |
| **Code Formatting & Style** | **OUT OF SCOPE** | Use Prettier, ESLint, or Black |
| **Manual Human Terminal Commands** | **OUT OF SCOPE** | Bartholomew inspects agentic invocations |

---

## 4. Verification in Your Repository

You can verify that Bartholomew is armed and enforcing policies in your workspace right now:

```bash
# Run local verification probe
python -m btp_guard.cli prove
```

Or open the **Bartholomew Guard** tab in VS Code / Cursor and click:
**`[⚡ Run 60-Second Live Security Probe]`**

---

## 5. Commercial Team Pilot (30 Days • $199/mo or $950 One-Time)

* **Developer Edition**: 100% Free and open-source forever.
* **Team Pilot**: For engineering organizations wanting centralized repo policies, team-wide pre-commit hooks, and a CISO/SOC2-ready compliance audit log:
  * Learn more: [https://bartholomew.info/#pricing](https://bartholomew.info/#pricing)
  * Self-enroll: `python -m btp_guard.cli pilot --enroll`
