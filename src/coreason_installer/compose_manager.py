# compose_manager.py
import os
import shutil
from pathlib import Path
import platform

def prepare_directories(target_dir: str | Path, tenant_cid: str | None = None) -> list[Path]:
    """Create local volume directories required by the containers."""
    target_path = Path(target_dir)
    dirs_to_create = [
        target_path / "data" / "lancedb",
        target_path / "data" / "bronze",
        target_path / "data" / "silver",
        target_path / "data" / "gold",
        target_path / "data" / "plugins",
        target_path / "data" / "vault"
    ]
    
    if tenant_cid:
        dirs_to_create.append(target_path / "logs" / "tenants" / tenant_cid)
        
    for d in dirs_to_create:
        d.mkdir(parents=True, exist_ok=True)
        
    return dirs_to_create


def handle_permissions(target_dir: str | Path, dirs: list[Path]) -> tuple[bool, str]:
    """On Unix systems, transfer ownership of data directories to UID 10000."""
    if platform.system() in ["Linux", "Darwin"]:
        # We need to set ownership to UID 10000 so the unprivileged container can write to them
        uid = 10000
        gid = 10000
        
        try:
            # Try doing it using Python's os.chown (might require root)
            if hasattr(os, "chown"):
                for d in dirs:
                    # Recursively chown the directory
                    os.chown(d, uid, gid)  # type: ignore[attr-defined]
                    for root, ndirs, files in os.walk(d):
                        for name in ndirs:
                            os.chown(os.path.join(root, name), uid, gid)  # type: ignore[attr-defined]
                        for name in files:
                            os.chown(os.path.join(root, name), uid, gid)  # type: ignore[attr-defined]
            return True, "Volume permissions updated to UID/GID 10000 successfully."
        except PermissionError:
            # Fallback: container-native init-permissions service will handle ownership adjustments
            return True, "Host permissions read-only. Container-native permissions initializer will chown volumes on container startup."
                
    return True, "No permission adjustment needed on this operating system."


def generate_egress_rules(target_dir: str | Path, selected_categories: list[str]) -> tuple[Path, Path]:
    """Generate plaintext firewall rules and Squid whitelist ACL configuration based on selected categories."""
    target_path = Path(target_dir)
    
    category_domains = {
        "registries": [
            "ghcr.io",
            "pkg-containers.githubusercontent.com",
            "registry-1.docker.io",
            "auth.docker.io",
            "index.docker.io",
            "production.cloudflare.docker.com"
        ],
        "huggingface": [
            "huggingface.co",
            "cdn-lfs.hf.co",
            "cdn-lfs-us-1.hf.co",
            "cdn-lfs-eu-1.hf.co",
            "cas-bridge.xethub.hf.co"
        ],
        "oidc": [
            "login.microsoftonline.com",
            "accounts.google.com"
        ],
        "cognitive": [
            "api.openai.com",
            "api.anthropic.com",
            "us-central1-aiplatform.googleapis.com",
            "bedrock.us-east-1.amazonaws.com",
            "bedrock.us-west-2.amazonaws.com"
        ]
    }
    
    allowed_domains = []
    for cat in selected_categories:
        if cat in category_domains:
            allowed_domains.extend(category_domains[cat])
            
    # 1. Write plain rules file for IT administration
    rules_file = target_path / "egress-whitelist.rules"
    with open(rules_file, "w") as f:
        f.write("# CoReason Enterprise Outbound Firewall Rules (FQDN Whitelist)\n")
        f.write("# Hand this file to your network/firewall security administrator.\n\n")
        for domain in allowed_domains:
            f.write(f"{domain}\n")
            
    # 2. Write Squid config file for local enforcement container
    squid_file = target_path / "egress-whitelist.squid.conf"
    squid_lines = [
        "# Squid Proxy Whitelist Configuration for CoReason Sandbox Egress",
        "acl SSL_ports port 443",
        "acl Safe_ports port 80",
        "acl Safe_ports port 443",
        "acl CONNECT method CONNECT",
        "",
        "http_access deny !Safe_ports",
        "http_access deny CONNECT !SSL_ports",
        "http_access allow localhost manager",
        "http_access deny manager",
        "",
        "# Allow local traffic within docker bridge network",
        "acl localnet src 10.0.0.0/8",
        "acl localnet src 172.16.0.0/12",
        "acl localnet src 192.168.0.0/16",
        "http_access allow localhost",
        "http_access allow localnet",
        ""
    ]
    
    squid_lines.append("# Whitelisted destination domains")
    for domain in allowed_domains:
        # We define allow lists for FQDNs
        squid_lines.append(f"acl allowed_domains dstdomain {domain}")
        # Match subdomains
        if not domain.startswith(".") and domain != "pkg-containers.githubusercontent.com":
            squid_lines.append(f"acl allowed_domains dstdomain .{domain}")
            
    squid_lines.append("http_access allow allowed_domains")
    squid_lines.append("")
    squid_lines.append("# Deny all other outbound traffic")
    squid_lines.append("http_access deny all")
    
    # Run proxy on port 3128
    squid_lines.append("http_port 3128")
    
    with open(squid_file, "w") as f:
        f.write("\n".join(squid_lines) + "\n")
        
    return rules_file, squid_file


def copy_templates(
    target_dir: str | Path,
    template_source_dir: str | Path,
    egress_profile: str = "air-gapped",
    use_local_proxy: bool = False,
    selected_categories: list[str] | None = None
) -> None:
    """Copy Envoy/Dex configs and write compose.yaml with configured egress profile."""
    target_path = Path(target_dir)
    source_path = Path(template_source_dir)
    
    shutil.copy(source_path / "Caddyfile", target_path / "Caddyfile")
    shutil.copy(source_path / "dex-config.yaml", target_path / "dex-config.yaml")
    
    compose_template = source_path / "compose.yaml"
    compose_target = target_path / "compose.yaml"
    
    with open(compose_template, "r") as f:
        content = f.read()
        
    if use_local_proxy:
        # Local whitelisting proxy requested
        proxy_service = """
  # Local Egress proxy to enforce domain whitelisting
  egress-proxy:
    image: ubuntu/squid:latest
    restart: unless-stopped
    volumes:
      - ./egress-whitelist.squid.conf:/etc/squid/squid.conf:ro
    networks:
      - swarm-mesh
      - egress-network
"""
        # Insert before networks:
        content = content.replace("networks:", proxy_service + "\nnetworks:")
        
        # Add egress-network bridge
        content = content.replace(
            "networks:\n  swarm-mesh:\n    internal: true\n  sensory-gateway:\n    internal: true",
            "networks:\n  swarm-mesh:\n    internal: true\n  sensory-gateway:\n    internal: true\n  egress-network:\n    driver: bridge"
        )
        content = content.replace(
            "networks:\r\n  swarm-mesh:\r\n    internal: true\r\n  sensory-gateway:\r\n    internal: true",
            "networks:\r\n  swarm-mesh:\r\n    internal: true\r\n  sensory-gateway:\r\n    internal: true\r\n  egress-network:\r\n    driver: bridge"
        )
    else:
        if egress_profile == "hybrid":
            # Keep swarm-mesh internal, make sensory-gateway open for remote model endpoints
            # Look for the sensory-gateway section block
            content = content.replace("sensory-gateway:\n    internal: true", "sensory-gateway:\n    internal: false")
            # Backup replace for different newline formats
            content = content.replace("sensory-gateway:\r\n    internal: true", "sensory-gateway:\r\n    internal: false")
        elif egress_profile == "connected":
            # Make all networks open
            content = content.replace("internal: true", "internal: false")
        
    with open(compose_target, "w") as f:
        f.write(content)
        
    if use_local_proxy and selected_categories:
        generate_egress_rules(target_path, selected_categories)


def generate_env_file(
    target_dir: str | Path,
    template_source_dir: str | Path,
    gpu_detected: bool,
    hf_token: str = "hf_your_token_here",
    custom_vars: dict[str, str] | None = None
) -> Path:
    """Generate .env file based on the capability matrix and user tokens."""
    target_path = Path(target_dir)
    source_path = Path(template_source_dir)
    
    env_example = source_path / "env.example"
    env_target = target_path / ".env"
    
    if not env_example.exists():
        # Fallback inline template if file not found
        content = [
            "SGLANG_URL=",
            "LANCEDB_URI=/app/data/lancedb",
            "PLUGINS_DIR=/app/data/plugins",
            "TELEMETRY_BROKER_URL=http://localhost:8000",
            "TEMPORAL_HOST=temporal:7233",
            "COMPOSE_PROFILES=",
            "EXTRAS=",
            "HF_TOKEN=hf_your_token_here",
            "OUTLINES_MODEL=meta-llama/Llama-3-8B-Instruct",
            "COREASON_VLLM_VRAM_UTILIZATION=0.5",
            "COREASON_VLLM_MAX_MODEL_LEN=4096",
            "COREASON_MASTER_GATEWAY_URL=http://host.docker.internal:8080",
            "EPISTEMIC_MERKLE_ROOT=0000000000000000000000000000000000000000000000000000000000000000"
        ]
    else:
        with open(env_example, "r") as f:
            content = f.read().splitlines()

    # Determine variables
    profiles_list = []
    if gpu_detected:
        profiles_list.append("gpu")
    if custom_vars and custom_vars.get("COREASON_CONTRIBUTE_COMPUTE") == "true":
        profiles_list.append("share-compute")
    if custom_vars and custom_vars.get("COREASON_USE_VAULT") == "true":
        profiles_list.append("vault")
    profiles = ",".join(profiles_list)

    extras = "inference" if gpu_detected else ""
    sglang_url = "http://sglang:30000" if gpu_detected else ""

    from . import diagnostics
    config = {
        "COMPOSE_PROFILES": profiles,
        "EXTRAS": extras,
        "SGLANG_URL": sglang_url,
        "HF_TOKEN": hf_token,
        "COREASON_HARDWARE_FINGERPRINT_HASH": diagnostics.calculate_host_fingerprint(),
    }
    
    if custom_vars:
        config.update(custom_vars)

    new_content = []
    processed_keys = set()

    for line in content:
        matched = False
        for key, val in config.items():
            if line.startswith(f"{key}="):
                new_content.append(f"{key}={val}")
                processed_keys.add(key)
                matched = True
                break
        if not matched:
            new_content.append(line)

    for key, val in config.items():
        if key not in processed_keys:
            new_content.append(f"{key}={val}")

    with open(env_target, "w") as f:
        f.write("\n".join(new_content) + "\n")

    return env_target
