# Bartholomew BTP v6.5.6 Release Consistency Audit

**Document Identifier**: `docs/release-consistency.md`  
**Current Protocol Release**: BTP v6.5.6  
**Audit Date**: 2026-10-13  

---

## 1. Registry and Package Version Audit

| Component | Target Version | Declared Version | Registry Status | External Action Required |
|---|---|---|---|---|
| `btp-guard` (npm) | 6.5.6 | 6.5.6 | Published on npm | None (Active: 6.5.6) |
| `bartholomew-vault` (npm) | 6.5.6 | 6.5.6 | Published on npm | None (Active: 6.5.6) |
| `bartholomew-guard-vscode` (Open VSX) | 6.5.6 | 6.5.6 | Built: 6.5.6 (Ready for publish) | Publish vsix to Open VSX Registry |
| `site/.well-known/agent-manifest.json` | 6.5.6 | 6.5.6 | Synchronized in repo | Deploy site |
| `site/agent-manifest.json` | 6.5.6 | 6.5.6 | Synchronized in repo | Deploy site |
| `site/.well-known/mcp.json` | 6.5.6 | 6.5.6 | Synchronized in repo | Deploy site |
| `site/llms.txt` | 6.5.6 | 6.5.6 | Synchronized in repo | Deploy site |
| `site/llms-full.txt` | 6.5.6 | 6.5.6 | Synchronized in repo | Deploy site |
| `site/mcp-catalog.json` | 6.5.6 | 6.5.6 | Synchronized in repo | Deploy site |
| `site/tools.json` | 6.5.6 | 6.5.6 | Synchronized in repo | Deploy site |

---

## 2. Corrected Discrepancies

1. **Agent Manifest Version**:
   - `site/.well-known/agent-manifest.json` and `site/agent-manifest.json` previously reported `protocol_version: 6.4.4`. Updated and synchronized to `6.5.6`.
2. **MCP Manifest Version**:
   - `site/.well-known/mcp.json` previously reported `version: 6.5.5`. Synchronized to `6.5.6`.
3. **Documentation Header Versions**:
   - `site/llms.txt` previously stated `BTP v6.4.7`. Synchronized to `BTP v6.5.6`.
   - `site/llms-full.txt` previously stated `BTP v6.4.4`. Synchronized to `BTP v6.5.6`.
4. **Universal Tool Catalogs**:
   - `site/mcp-catalog.json` and `site/tools.json` previously stated `version: 6.4.4`. Synchronized to `6.5.6`.

---

## 3. Pending External Publishing Steps

- **VS Code Extension**:
  - `packages/vscode-extension/package.json` is currently `6.5.5`.
  - Next step: Update `package.json` to `6.5.6`, package with `vsce package`, and publish to Open VSX Registry (`ovsx publish`).
- **Website Manifest Deployment**:
  - Static site files in `site/` must be deployed to the production web host (`bartholomew.info`).
