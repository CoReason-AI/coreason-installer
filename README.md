# CoReason Swarm-in-a-Box Installer

This helper repository provides an interactive, zero-dependency command-line installer designed to deploy the full CoReason tripartite swarm in a local development environment. 

It handles host capability detection (NVIDIA GPUs & CDI device configurations), environment variable projection (`.env`), local PKI HTTPS integration (Caddy), and container orchestration (Docker Compose).

---

## Prerequisites

Before running the installer, ensure you have:
1. **Docker & Docker Compose** (installed and running).
2. **NVIDIA Container Toolkit** (optional, required only for local GPU hardware acceleration).
3. **Python 3.14+** (optional, the wrapper script will automatically bootstrap it via `uv` if missing).

---

## Quickstart

Clone this repository and run the bootstrap script appropriate for your operating system.

### Linux / macOS
```bash
git clone https://github.com/CoReason-AI/coreason-installer.git
cd coreason-installer
chmod +x install.sh
./install.sh
```

### Windows (PowerShell)
```powershell
git clone https://github.com/CoReason-AI/coreason-installer.git
cd coreason-installer
.\install.ps1
```

---

## Configuration & Command Line Options

The installer supports several parameters to customize your deployment. You can pass these directly to the wrapper scripts:

| Argument | Description | Default |
|---|---|---|
| `--target-dir PATH` | Workspace path where configurations, volumes, and assets will be written. | `.` (Current directory) |
| `--hf-token TOKEN` | Hugging Face token required for GPU gating checks. | Prompts if GPU is detected |
| `--no-gpu` | Run in CPU-only mode even if an NVIDIA GPU is found. | `False` |
| `--timeout SECONDS` | Seconds to wait for the platform services to start and respond. | `90` |

### Examples

**Deploy to a dedicated folder with CPU-only mode:**
```bash
./install.sh --target-dir ~/coreason-workspace --no-gpu
```

---

## Network Egress Security Profiles & Enterprise Firewall Rules

The installer prompts you to select a **Network Egress Profile** depending on your organization's security posture. This determines whether the container networks are fully isolated (`internal: true` in Docker Compose) or permitted to reach external resources.

### 1. Egress Profiles Matrix

| Profile | Compose network (`swarm-mesh`) | Gateway network (`sensory-gateway`) | Use Case |
|---|---|---|---|
| **Air-Gapped / Sovereign** (`air-gapped`) | `internal: true` (Isolated) | `internal: true` (Isolated) | Highly secure offline environments. Requires pre-loaded Docker images and local cache volumes for LLM weights. |
| **Hybrid / Model Egress** (`hybrid`) | `internal: true` (Isolated) | `internal: false` (Permitted) | Default state database remains isolated. The runtime API and Caddy gateway can contact external model providers or OIDC endpoints. |
| **Fully Connected** (`connected`) | `internal: false` (Permitted) | `internal: false` (Permitted) | Standard development environment with full outbound access. |

### 2. Standard Enterprise Egress Firewall Whitelist

For **Hybrid** or **Fully Connected** deployments behind an enterprise next-generation firewall (NGFW), you must configure **FQDN (Fully Qualified Domain Name) filtering** to whitelist egress traffic. IP-based filtering is discouraged due to dynamic IP rotation in cloud infrastructure.

#### A. Container & Package Registry Egress
Required during the install and update phases to pull platform images:
*   **GitHub Container Registry (GHCR):**
    *   `ghcr.io` (HTTPS Port 443)
    *   `pkg-containers.githubusercontent.com` (HTTPS Port 443)
*   **Docker Hub (Base runtime and database images):**
    *   `registry-1.docker.io` (HTTPS Port 443)
    *   `auth.docker.io` (HTTPS Port 443)
    *   `index.docker.io` (HTTPS Port 443)
    *   `production.cloudflare.docker.com` (HTTPS Port 443)

#### B. Model Weight Downloads (Hugging Face)
Required by the local cognitive engine (`sglang`) or runtime to download open weights at boot:
*   `huggingface.co` (HTTPS Port 443)
*   `cdn-lfs.hf.co` (HTTPS Port 443 - Large File Storage CDN redirect)
*   `cdn-lfs-us-1.hf.co` (HTTPS Port 443)
*   `cdn-lfs-eu-1.hf.co` (HTTPS Port 443)
*   `cas-bridge.xethub.hf.co` (HTTPS Port 443)

#### C. Identity Federation & OIDC
Required by `dex` to authenticate users against corporate identity provider (IdP) systems:
*   **Microsoft Entra ID:** `login.microsoftonline.com` (HTTPS Port 443)
*   **Okta Tenants:** `*.okta.com` (HTTPS Port 443)
*   **Google Identity:** `accounts.google.com` (HTTPS Port 443)

#### D. Cloud Cognitive & Inference APIs
Required if the runtime delegates inference to managed cloud backends instead of local GPU engines:
*   **OpenAI API:** `api.openai.com` (HTTPS Port 443)
*   **Anthropic Claude API:** `api.anthropic.com` (HTTPS Port 443)
*   **Google Cloud Vertex AI:** `*.googleapis.com`, `us-central1-aiplatform.googleapis.com` (HTTPS Port 443)
*   **AWS Bedrock endpoints:** `bedrock.*.amazonaws.com` (HTTPS Port 443)

> [!TIP]
> **Zero-Public-Egress Best Practice (Private Endpoints):**
> For enterprise cloud deployments in AWS or GCP, do not open public internet egress to access cognitive APIs. Instead, use **AWS PrivateLink (Interface VPC Endpoints)** for AWS Bedrock or **Google Private Service Connect (PSC)** for Vertex AI. This routes API calls entirely within the cloud vendor's private backbone, maintaining compliance and avoiding egress firewall overhead.

---

## Orchestrated Services

Upon completion, the installer configures and spawns the following container stack:

- **Ingress Gateway (Caddy)**: Exposes Ports `80` and `443` to route requests via HTTPS.
- **Identity Provider (Dex)**: Exposes Port `5556` for federated OIDC callbacks.
- **CoReason Runtime API**: Exposes Port `8000` for FastAPI telemetry streams.
- **Workflow Orchestration (Temporal)**: Exposes Port `7233` (gRPC) and Port `8233` (dashboard).
- **PostgreSQL**: State database backing Temporal.
- **Cognitive Engine (SGLang)**: Exposes Port `30000` (spawned only under the `gpu` profile).

---

## File Layout & Generated Assets

When executed, the installer writes the following files to your target workspace:
```
target-workspace/
├── caddy_data/         # Caddy data directory containing auto-generated local certificates
│   └── caddy/pki/authorities/local/root.crt # Caddy Root CA Certificate
├── data/
│   ├── lancedb/        # Vector Database storage (chown 10000:10000)
│   ├── bronze/         # Ingested datasets storage (chown 10000:10000)
│   ├── silver/         # Standardized ontology ledger (chown 10000:10000)
│   ├── gold/           # Curated golden assets (chown 10000:10000)
│   └── plugins/        # Actuator WASM plugins (chown 10000:10000)
├── .env                # Hardware-customized environment properties
├── compose.yaml        # Docker Compose configuration spec
├── Caddyfile           # Caddy ingress reverse proxy rules
└── dex-config.yaml     # Dex client configurations
```
