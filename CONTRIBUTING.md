# Contributing to CoReason Installer

Thank you for your interest in contributing to the CoReason Swarm-in-a-Box Installer. 

To maintain security, supply chain integrity, and clean intellectual property boundaries, all contributions must agree to our Contributor License Agreement (CLA) and sign off on their commits in compliance with the Developer Certificate of Origin (DCO).

---

## 1. Contributor License Agreement (CLA)

By contributing to this repository, you agree that:
1. **License Grant**: Your contributions are solely to **CoReason, Inc.** and are licensed exclusively under the [Prosperity Public License 3.0.0](LICENSE) for inclusion in the platform. There are no MIT or other open-source exceptions for any part of this installer codebase.
2. **Original Work**: You represent that your contribution is your own original creation and that you have the legal right to grant this license.

### Corporate Tenant & License Review
To verify compliance and execute tenant-level reviews, all contributions are bound to the following parent tenant context:
- **CoReason global `tenant_cid`**: `889955217295c2bfef2d6812071b633b0819477e67f57853febf116f69f30531`
- **Canonical JCS (RFC 8785) JSON Text**:
  ```json
  {"date_of_incorporation":"2025-10-16","file_number":"10369312","jurisdiction":"US-DE","legal_name":"CoReason, Inc."}
  ```
  *(This structured text is canonicalized and hashed using SHA-256 to deterministically produce the `tenant_cid` defined in the root `coreason-manifest` schema).*

---

## 2. Developer Certificate of Origin (DCO)

We enforce commit signing to certify the origin of the code. Every commit must be signed off by the author using `git commit -s`. By signing your commits, you certify the following:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004 Lawrence Rosen <lrosen@openloop.com>

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### How to Sign Off
Use the `-s` or `--signoff` flag when committing changes:
```bash
git commit -s -m "feat: add docker group check to diagnostics"
```
This automatically appends the following line to your commit message:
```text
Signed-off-by: Jane Dev <jane.dev@example.com>
```

---

## 3. CoReason Clean Room Protocol Compliance (PIP-001)

All contributions must comply with the **CoReason Clean Room Protocol**:
- Contributions must be created in an independent environment.
- Do not paste proprietary code, decompiled snippets, or third-party assets that violate intellectual property bounds.
- All code submissions must be subsequent to the individual's **Temporal Firewall Date**.

---

## 4. Coding & Verification Standards

To maintain cross-platform correctness:
1. **Linter & Formatters**: We use `ruff` for linting and formatting. Run checks locally before committing:
   ```bash
   uv run ruff check src/
   ```
2. **Cross-Platform Compatibility**: Always write platform-agnostic code. Use Python's `platform` and `shutil` libraries instead of hardcoded shell bindings (e.g. use `shutil.which` instead of `which`).
3. **mTLS Integrity**: Do not bypass or disable mTLS certificate verification. The platform enforces strict token gating; all HTTPS certificates are managed and auto-generated via Caddy's PKI engine.
