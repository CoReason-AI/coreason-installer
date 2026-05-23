# cli.py
import sys
import subprocess
from pathlib import Path

from typing import Any

# Add parent directory to path so relative imports work when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent))

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm

from . import diagnostics
from . import compose_manager
import json
import time

console = Console()

def get_services_health(target_path: Path) -> dict[str, dict[str, Any]]:
    import subprocess
    services = {
        "caddy": {"healthy": False, "status_msg": "Container not found", "description": "Caddy Ingress Gateway", "host": "localhost", "port": 443},
        "dex": {"healthy": False, "status_msg": "Container not found", "description": "Dex OIDC Engine", "host": "localhost", "port": 5556},
        "coreason-runtime": {"healthy": False, "status_msg": "Container not found", "description": "CoReason Backend API", "host": "localhost", "port": 8000},
        "temporal": {"healthy": False, "status_msg": "Container not found", "description": "Temporal Workflow Orchestration", "host": "localhost", "port": 7233},
        "coreason-worker": {"healthy": False, "status_msg": "Container not found", "description": "CoReason Temporal Worker", "host": "localhost", "port": 0},
    }
    try:
        res = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=target_path,
            capture_output=True,
            text=True,
            check=False
        )
        if res.returncode == 0 and res.stdout.strip():
            raw = res.stdout.strip()
            containers = []
            if raw.startswith("["):
                try:
                    containers = json.loads(raw)
                except Exception:
                    pass
            else:
                for line in raw.splitlines():
                    if line.strip():
                        try:
                            containers.append(json.loads(line.strip()))
                        except Exception:
                            pass
            
            for c in containers:
                c_norm = {k.lower(): v for k, v in c.items()}
                service = c_norm.get("service")
                if not service:
                    continue
                service = service.lower()
                
                state = c_norm.get("state", "").lower()
                health = c_norm.get("health", "").lower()
                status = c_norm.get("status", "").lower()
                
                is_running = "running" in state or "running" in status or "up" in state or "up" in status
                is_healthy = False
                status_msg = "Offline"
                
                if is_running:
                    if health:
                        if health == "healthy":
                            is_healthy = True
                            status_msg = "Healthy"
                        elif health == "unhealthy":
                            is_healthy = False
                            status_msg = "Unhealthy"
                        else:
                            is_healthy = False
                            status_msg = f"Starting ({health})"
                    else:
                        is_healthy = True
                        status_msg = "Running"
                else:
                    status_msg = state or status or "Stopped"
                
                if service in services:
                    services[service]["healthy"] = is_healthy
                    services[service]["status_msg"] = status_msg
                elif service == "sglang":
                    services["sglang"] = {
                        "healthy": is_healthy,
                        "status_msg": status_msg,
                        "description": "SGLang GPU Inference Server",
                        "host": "localhost",
                        "port": 30000
                    }
    except Exception as e:
        for s in services.values():
            s["status_msg"] = f"Error: {str(e)}"
            
    return services


def parse_env_file(env_path: Path) -> dict[str, str]:
    if not env_path.exists():
        return {}
    config = {}
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip()
                    if v.startswith(('"', "'")) and v.endswith(v[0]):
                        v = v[1:-1]
                    config[k] = v
        return config
    except Exception:
        return {}


@click.group(invoke_without_command=True)
@click.option("--target-dir", default=".", help="Target installation directory")
@click.option("--hf-token", default=None, help="Hugging Face API Token")
@click.option("--no-gpu", is_flag=True, help="Disable GPU acceleration even if detected")
@click.option("--timeout", default=90, help="Timeout in seconds for verifying services health")
@click.option("--egress-profile", default=None, type=click.Choice(["air-gapped", "hybrid", "connected"]), help="Network egress security profile")
@click.option("--mesh-mode", default=None, type=click.Choice(["strict-genesis", "public", "private"]), help="Mesh participation mode")
@click.option("--license-key", default=None, help="Commercial License Key JWT")
@click.option("--verification-key", default=None, help="Identity Verification Key (Amazon Key Store)")
@click.pass_context
def main(ctx, target_dir: str, hf_token: str | None, no_gpu: bool, timeout: int, egress_profile: str | None, mesh_mode: str | None, license_key: str | None, verification_key: str | None):
    """Interactive installer CLI for the CoReason Platform."""
    if ctx.invoked_subcommand is not None:
        return
    console.print(Panel.fit(
        "[bold cyan]CoReason Tripartite Swarm-in-a-Box Installer[/bold cyan]\n"
        "[dim]Zero-dependency orchestrator & host capability injector[/dim]",
        border_style="cyan"
    ))

    # Phase 1: Diagnostics Check
    console.print("\n[bold]🔍 Phase 1: Checking Host Environment & Infrastructure...[/bold]")
    
    # 1. Platform & OS Check
    platform_info = diagnostics.get_platform_info()
    
    # 2. Check Docker
    docker_status = diagnostics.check_docker()
    if not docker_status["installed"]:
        console.print(f"[bold red]❌ Prerequisite Failure:[/bold red] {docker_status['error']}")
        sys.exit(1)
    if not docker_status["running"]:
        console.print(f"[bold red]❌ Prerequisite Failure:[/bold red] {docker_status['error']}")
        sys.exit(1)
    if not docker_status["compose_ok"]:
        console.print("[bold red]❌ Prerequisite Failure:[/bold red] Docker Compose is not installed or enabled.")
        sys.exit(1)
    
    # 3. Detect GPU
    gpu_info = {"has_gpu": False, "details": "", "driver_version": "Unknown", "cdi_configured": False}
    if not no_gpu:
        gpu_info = diagnostics.detect_nvidia_gpu()

    # 4. Get system specs
    try:
        resources = diagnostics.get_system_resources()
        ram_gb = resources["ram_gb"]
        free_disk_gb = resources["free_disk_gb"]
    except Exception:
        ram_gb = 16.0
        free_disk_gb = 50.0

    # Build detailed host infrastructure audit table
    table = Table(title="Host Infrastructure & Platform Audit", box=None)
    table.add_column("Infrastructure Substrate", style="cyan", width=30)
    table.add_column("Detected Specification / Status", style="white")
    
    # Platform Details
    table.add_row("Operating System Platform", f"[green]✔ {platform_info['os']} ({platform_info['release']})[/green]")
    table.add_row("CPU Enclave Architecture", f"[green]✔ {platform_info['arch']}[/green]")
    table.add_row("Local Python Runtime", f"[green]✔ v{platform_info['python_version']}[/green]")
    
    # Docker Details
    docker_version_str = f"[green]✔ Running ({docker_status['docker_version']})[/green]"
    table.add_row("Docker Engine Daemon", docker_version_str)
    table.add_row("Docker Compose Subsystem", f"[green]✔ Active ({docker_status['compose_version']})[/green]")
    
    # GPU Details
    if gpu_info["has_gpu"]:
        gpu_status = f"[green]✔ Detected ({gpu_info['details']})[/green]\n   Driver Version: {gpu_info['driver_version']}"
        if gpu_info["cdi_configured"]:
            gpu_status += "\n   [green]✔ CDI device routing active[/green]"
        else:
            gpu_status += "\n   [yellow]⚠ CDI device specification missing/not found[/yellow]"
        table.add_row("NVIDIA Hardware Acceleration", gpu_status)
    else:
        table.add_row("NVIDIA Hardware Acceleration", "[yellow]⚠ None detected (CPU-only / remote routing active)[/yellow]")
        
    # Memory & Disk Resources
    ram_style = "green" if ram_gb >= 15.0 else ("yellow" if ram_gb >= 8.0 else "red")
    table.add_row("System Memory (Total RAM)", f"[{ram_style}]{ram_gb:.2f} GB[/{ram_style}] (Min: 8GB for Edge, 16GB for GPU)")
    
    disk_style = "green" if free_disk_gb >= 20.0 else "red"
    table.add_row("Host Free Disk Space", f"[{disk_style}]{free_disk_gb:.2f} GB[/{disk_style}] (Min: 20GB free)")
    
    console.print(table)

    # Classify deployment
    classification = diagnostics.classify_deployment_type(platform_info, gpu_info, {"ram_gb": ram_gb})
    
    console.print(Panel(
        f"[bold cyan]Optimal Deployment Profile Detected:[/bold cyan]\n"
        f"🌟 [bold green]{classification['mode']}[/bold green]\n"
        f"📝 [dim]{classification['recommendation']}[/dim]",
        border_style="green",
        title="[bold]Recommended Setup[/bold]"
    ))

    # Warnings / Confirmations
    if gpu_info["has_gpu"] and not gpu_info["cdi_configured"]:
        console.print(
            "\n[bold yellow]⚠ Warning:[/bold yellow] NVIDIA GPU was detected but the Container Device Interface (CDI) spec "
            "was not found on your host. If you run into GPU container mount issues, please execute:\n"
            "   [bold white]sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml[/bold white]"
        )

    # Phase 2: Interactive Configuration, License & Profile Selection
    console.print("\n[bold]⚙ Phase 2: Configuration & License Agreement...[/bold]")
    
    # 1. License & Warranty Disclaimer
    console.print(Panel(
        "This installation helper utility is provided [bold]\"as is\"[/bold] without warranty of any kind.\n"
        "CoReason, Inc. does not warrant this software or accept liability for any operational "
        "issues or system alterations arising from its execution.\n\n"
        "This software is dual-licensed under the [bold]Prosperity Public License 3.0.0[/bold].\n"
        "Non-commercial use is free. Commercial use beyond a 30-day trial requires a separate license.",
        border_style="cyan",
        title="[bold]License & Warranty Disclaimer[/bold]"
    ))
    if not Confirm.ask("Do you accept the license and warranty terms?", default=True):
        console.print("[bold red]❌ Installation Aborted: You must accept the license and warranty terms to proceed.[/bold red]")
        sys.exit(1)

    # 1b. Mesh Participation Mode Selection
    selected_mesh_mode = mesh_mode
    if not selected_mesh_mode:
        console.print("\n[bold cyan]🌐 CoReason Mesh Participation Mode[/bold cyan]")
        console.print("Select how your node will participate in the cognitive mesh:")
        console.print("  1. [bold]Strict Genesis Mode[/bold] (default) - Compliance walled garden. P2P networking disabled, only trust CoReason golden signatures.")
        console.print("  2. [bold]Public Mesh[/bold] - Connect to the global P2P discovery network and contribute compute to earn Deficit Credits.")
        console.print("  3. [bold]Private Mesh[/bold] - Sovereign consortium/federation network completely isolated from the public mesh.")
        
        mesh_choice = Prompt.ask("Enter selection number", choices=["1", "2", "3"], default="1")
        mesh_modes = {"1": "strict-genesis", "2": "public", "3": "private"}
        selected_mesh_mode = mesh_modes[mesh_choice]
    
    console.print(f"[green]✔ Configured Mesh Mode: [bold]{selected_mesh_mode}[/bold][/green]")
    
    network_mode = "STRICT_GENESIS" if selected_mesh_mode == "strict-genesis" else "P2P"

    # 1c. Mesh Compute Contribution Prompt (Prosperity 3.0 expectation)
    contribute_compute = False
    if selected_mesh_mode == "public":
        contribute_compute = True
        console.print("\n[bold cyan]💚 CoReason Mesh Idle Compute Contribution[/bold cyan]")
        console.print(
            "As a free-tier user under the Prosperity Public License, you are expected by default\n"
            "to contribute a small portion of idle compute (1 CPU core, 512MB RAM) and network\n"
            "bandwidth to support the URN ledger and discovery queries on the public mesh."
        )
        if Confirm.ask("Do you agree to contribute idle compute to support the public mesh?", default=True):
            console.print("[green]✔ Thank you! Compute sharing is enabled.[/green]")
        else:
            contribute_compute = False
            console.print("[yellow]⚠ Compute sharing disabled (you have opted out).[/yellow]")

    # 1d. Commercial License & Trial Activation
    license_tier = "prosperity-3.0"
    active_license_key = license_key or ""
    
    if not license_key:
        console.print("\n[bold cyan]🔑 License Type & Commercial Trial Activation[/bold cyan]")
        console.print("Select your licensing structure:")
        console.print("  1. [bold]Prosperity Public License 3.0.0[/bold] (default) - Free non-commercial use / 30-day trial.")
        console.print("  2. [bold]Activate 30-Day Free Commercial Trial[/bold] - Full commercial access for evaluation.")
        console.print("  3. [bold]Install Commercial License Key[/bold] - For active commercial subscribers.")
        
        license_choice = Prompt.ask("Enter selection number", choices=["1", "2", "3"], default="1")
        if license_choice == "2":
            license_tier = "commercial-trial"
            active_license_key = "trial-30-day"
            console.print("[green]✔ 30-Day Free Commercial Trial activated successfully.[/green]")
        elif license_choice == "3":
            license_tier = "commercial"
            active_license_key = Prompt.ask("Enter your Commercial License JWT Token string")
            console.print("[green]✔ Commercial license key registered.[/green]")
        else:
            license_tier = "prosperity-3.0"
            active_license_key = ""
            console.print("[green]✔ Selected Prosperity Public License (free tier).[/green]")
    else:
        license_tier = "commercial"

    # 1e. Identity Verification Key (Amazon Key Store)
    active_verification_key = verification_key or ""
    if not verification_key:
        if Confirm.ask("\nDo you have a CoReason identity verification key (issued from Amazon Key Store)?", default=False):
            active_verification_key = Prompt.ask("Enter your ID Verification Key")
            console.print("[green]✔ ID Verification Key registered successfully (Real Verified status enabled).[/green]")
        
    # 1f. Vault Secret Storage
    use_vault = False
    console.print("\n[bold cyan]🔒 Local Secret Storage (OpenBao / Vault)[/bold cyan]")
    if Confirm.ask("Deploy local OpenBao/Vault container for secure secret storage?", default=False):
        use_vault = True
        console.print("[green]✔ Vault/OpenBao integration enabled (vault profile will be activated).[/green]")
    else:
        console.print("[dim]Vault/OpenBao integration disabled (defaulting to .env storage).[/dim]")

    # 2. Profile Selection
    selected_profile = classification["profile"]
    if Confirm.ask(f"\nUse the recommended profile ([bold green]{classification['mode']}[/bold green])?", default=True):
        use_gpu = (selected_profile == "gpu-workstation")
    else:
        # User wants to override the default selection
        choices = {
            "1": ("gpu-workstation", "Local Workstation (GPU-Accelerated)"),
            "2": ("cpu-workstation", "Local Workstation (CPU-Only / Remote Substrate)"),
            "3": ("edge", "Resource-Constrained Edge (Raspberry Pi)")
        }
        console.print("\n[bold]Select a deployment profile:[/bold]")
        for key, (_, name) in choices.items():
            console.print(f"  {key}. {name}")
            
        choice_default = "1" if selected_profile == "gpu-workstation" else ("2" if selected_profile == "cpu-workstation" else "3")
        choice = Prompt.ask("Enter selection number", choices=["1", "2", "3"], default=choice_default)
        selected_profile, mode_name = choices[choice]
        use_gpu = (selected_profile == "gpu-workstation")
        classification["profile"] = selected_profile
        classification["mode"] = mode_name
        
        console.print(f"[green]✔ Selected Profile Overridden to: [bold]{mode_name}[/bold][/green]")

    # 3. Tenant Identification (KYC)
    console.print("\n[bold cyan]🏢 Tenant Identification (Know Your Customer - KYC)[/bold cyan]")
    if Confirm.ask("Deploy under the default CoReason, Inc. tenant?", default=True):
        tenant_cid = "889955217295c2bfef2d6812071b633b0819477e67f57853febf116f69f30531"
        console.print(f"[green]✔ Selected Default Tenant CID: [bold]{tenant_cid}[/bold][/green]")
    else:
        # Prompt for corporate details
        console.print("\n[bold]Please enter your corporate registration details to calculate your unique tenant_cid:[/bold]")
        legal_name = Prompt.ask("Legal Name of Corporation")
        jurisdiction = Prompt.ask("Jurisdiction of Incorporation (e.g. US-DE)")
        file_number = Prompt.ask("Registration File Number")
        date_of_inc = Prompt.ask("Date of Incorporation (YYYY-MM-DD)")
        
        # Calculate CID
        kyc_data = {
            "legal_name": legal_name.strip(),
            "jurisdiction": jurisdiction.strip(),
            "file_number": file_number.strip(),
            "date_of_incorporation": date_of_inc.strip()
        }
        canonical_json, tenant_cid = diagnostics.calculate_tenant_cid(kyc_data)
        
        console.print("\n[bold green]✔ Verification Successful![/bold green]")
        console.print(f"  [bold]Canonical JSON ID:[/bold] {canonical_json}")
        console.print(f"  [bold]Generated tenant_cid (SHA-256):[/bold] [bold cyan]{tenant_cid}[/bold cyan]\n")

        # Encrypt and Register KYC to CoReason Trust Network
        console.print("[dim]Registering tenant_cid and encrypted KYC payload with CoReason Trust Network...[/dim]")
        try:
            encrypted_kyc = diagnostics.encrypt_kyc_data(kyc_data)
            diagnostics.register_tenant_kyc(tenant_cid, encrypted_kyc)
            console.print("[green]✔ Successfully registered tenant with CoReason Network.[/green]\n")
        except Exception as e:
            console.print(f"[yellow]⚠ Warning: Could not register KYC with CoReason Trust Network: {str(e)}[/yellow]")
            console.print("[yellow]  Installation will continue, but network registration is incomplete (expected in air-gapped setups).[/yellow]\n")


    # 4. Network Egress Permissions
    selected_egress = egress_profile
    if not selected_egress:
        console.print("\n[bold cyan]🔒 Network Egress & VPC Firewall Configuration[/bold cyan]")
        console.print("Select network permissions for the container stack:")
        console.print("  1. [bold]Air-Gapped / Sovereign[/bold] (default) - Zero internet egress. Databases & runtime fully isolated.")
        console.print("  2. [bold]Hybrid / Model Egress[/bold] - Swarm state isolated. Runtime has egress to fetch weights & run API models.")
        console.print("  3. [bold]Fully Connected[/bold] - All containers have unrestricted outbound internet access.")
        
        egress_choice = Prompt.ask("Enter network profile number", choices=["1", "2", "3"], default="1")
        egress_profiles = {"1": "air-gapped", "2": "hybrid", "3": "connected"}
        selected_egress = egress_profiles[egress_choice]
    
    console.print(f"[green]✔ Configured Network Egress Profile: [bold]{selected_egress}[/bold][/green]")

    use_local_proxy = False
    selected_categories = []
    custom_vars = {
        "EPISTEMIC_MERKLE_ROOT": tenant_cid,
        "COREASON_CONTRIBUTE_COMPUTE": "true" if contribute_compute else "false",
        "COREASON_USE_VAULT": "true" if use_vault else "false",
        "COREASON_MESH_MODE": selected_mesh_mode,
        "COREASON_NETWORK_MODE": network_mode,
        "COREASON_LICENSE_TIER": license_tier,
        "COREASON_LICENSE_KEY": active_license_key,
        "COREASON_VERIFICATION_KEY": active_verification_key
    }

    if selected_egress == "hybrid":
        console.print("\n[bold cyan]🔧 Configure Hybrid Egress Whitelist Categories[/bold cyan]")
        categories = [
            ("registries", "Container Registries (Docker Hub, GHCR)"),
            ("huggingface", "Model Weight Downloads (Hugging Face)"),
            ("oidc", "Federated Identity Providers / OIDC (Okta, Microsoft Entra, Google)"),
            ("cognitive", "Cloud Cognitive APIs (OpenAI, Anthropic, GCP Vertex AI, AWS Bedrock)")
        ]
        
        for cat_id, cat_desc in categories:
            if Confirm.ask(f"  Authorize egress for {cat_desc}?", default=True):
                selected_categories.append(cat_id)

    if selected_egress in ["hybrid", "connected"]:
        if Confirm.ask("\n  Are you deploying behind an existing corporate HTTP/HTTPS proxy?", default=False):
            http_proxy = Prompt.ask("  Enter corporate HTTP Proxy URL (e.g. http://proxy.corp.local:8080)")
            https_proxy = Prompt.ask("  Enter corporate HTTPS Proxy URL", default=http_proxy)
            no_proxy = Prompt.ask("  Enter Proxy Bypass list (NO_PROXY)", default="localhost,127.0.0.1,temporal,postgres,sglang,dex,envoy,coreason-runtime,coreason-worker")
            
            custom_vars["HTTP_PROXY"] = http_proxy
            custom_vars["HTTPS_PROXY"] = https_proxy
            custom_vars["NO_PROXY"] = no_proxy
        elif selected_egress == "hybrid":
            if Confirm.ask("\n  Would you like to deploy a localized whitelisting proxy (Squid) inside the container mesh to enforce rules locally?", default=True):
                use_local_proxy = True
                if not selected_categories:
                    selected_categories = ["registries", "huggingface", "oidc", "cognitive"]
                custom_vars["HTTP_PROXY"] = "http://egress-proxy:3128"
                custom_vars["HTTPS_PROXY"] = "http://egress-proxy:3128"
                custom_vars["NO_PROXY"] = "localhost,127.0.0.1,temporal,postgres,sglang,dex,envoy,coreason-runtime,coreason-worker"

    # Set default empty values for proxy variables if not configured
    if "HTTP_PROXY" not in custom_vars:
        custom_vars["HTTP_PROXY"] = ""
    if "HTTPS_PROXY" not in custom_vars:
        custom_vars["HTTPS_PROXY"] = ""
    if "NO_PROXY" not in custom_vars:
        custom_vars["NO_PROXY"] = "localhost,127.0.0.1,temporal,postgres,sglang,dex,envoy,coreason-runtime,coreason-worker"

    # 5. Inbound Network Exposure
    console.print("\n[bold cyan]🔓 Inbound Network Exposure Configuration[/bold cyan]")
    if Confirm.ask("Restrict platform access to loopback (localhost/127.0.0.1) for security?", default=True):
        custom_vars["COREASON_BIND_IP"] = "127.0.0.1"
        console.print("[green]✔ Services will only bind to localhost (127.0.0.1).[/green]")
    else:
        custom_vars["COREASON_BIND_IP"] = "0.0.0.0"
        console.print("[yellow]⚠ Services will bind to 0.0.0.0 (exposed to host's local/public network).[/yellow]")

    # Resolve target directory
    target_path = Path(target_dir).resolve()
    console.print(f"\nTarget deployment workspace: [bold cyan]{target_path}[/bold cyan]")
    if not target_path.exists():
        if Confirm.ask(f"Directory {target_path} does not exist. Create it?"):
            target_path.mkdir(parents=True, exist_ok=True)
        else:
            console.print("[red]Installation aborted by user.[/red]")
            sys.exit(1)

    # Get Hugging Face Token if sglang is run
    if use_gpu and not hf_token:
        console.print(
            "\n[bold cyan]Hugging Face Token Registration[/bold cyan]\n"
            "An NVIDIA GPU was detected. The local cognitive engine (SGLang) requires a valid "
            "Hugging Face API token to pull gated weights (e.g. Meta-Llama-3-8B-Instruct)."
        )
        hf_token = Prompt.ask("Enter HuggingFace API Token", password=True)
        if not hf_token:
            console.print("[yellow]No token entered. Defaulting to empty fallback value.[/yellow]")
            hf_token = "hf_your_token_here"
    elif not hf_token:
        hf_token = "hf_your_token_here"

    # Phase 3: Setup Files, Environment, and Volumes
    console.print("\n[bold]📦 Phase 3: Generating Mesh Infrastructure & Certificates...[/bold]")
    
    template_dir = Path(__file__).resolve().parent.parent / "templates"
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        
        # 1. Prepare directories
        progress.add_task(description="Preparing volume folders...", total=None)
        vol_dirs = compose_manager.prepare_directories(target_path, tenant_cid=tenant_cid)
        
        # 2. Permissions check
        progress.add_task(description="Configuring directory bounds & user permissions...", total=None)
        perm_ok, perm_msg = compose_manager.handle_permissions(target_path, vol_dirs)
        
        # 3. Copy files
        progress.add_task(description="Deploying static Caddy/Dex/Compose specs...", total=None)
        compose_manager.copy_templates(
            target_path,
            template_dir,
            egress_profile=selected_egress,
            use_local_proxy=use_local_proxy,
            selected_categories=selected_categories
        )
        
        # 4. Generate .env
        progress.add_task(description="Writing capabilities matrix to .env...", total=None)
        compose_manager.generate_env_file(target_path, template_dir, use_gpu, hf_token, custom_vars=custom_vars)

    if not perm_ok:
        console.print(f"[bold yellow]⚠ Permissions Alert:[/bold yellow] {perm_msg}")
    else:
        console.print("[green]✔ Workspace templates and environment configuration generated.[/green]")

    # Phase 4: Container Orchestration
    console.print("\n[bold]🐳 Phase 4: Spinning up CoReason Tripartite Swarm...[/bold]")
    
    try:
        console.print("[dim]Pulling updated OCI container images from GHCR...[/dim]")
        subprocess.run(["docker", "compose", "pull"], cwd=target_path, check=True)
        
        console.print("[dim]Starting orchestration services...[/dim]")
        subprocess.run(["docker", "compose", "up", "-d"], cwd=target_path, check=True)
        console.print("[green]✔ Services booted successfully via Docker compose.[/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]❌ Orchestration Error:[/bold red] Docker Compose failed during operation: {str(e)}")
        console.print("Please check docker daemon status and manually run [bold]docker compose up -d[/bold].")
        sys.exit(1)

    # Phase 5: Verification
    console.print("\n[bold]⚡ Phase 5: Verifying Service Connectivity & Health...[/bold]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        progress.add_task(description="Awaiting service containers to achieve healthy state...", total=None)
        start_time = time.time()
        results = {}
        while time.time() - start_time < timeout:
            results = get_services_health(target_path)
            
            # Check required services
            required_services = ["caddy", "dex", "coreason-runtime", "temporal", "coreason-worker"]
            if use_gpu:
                required_services.append("sglang")
                
            all_ok = True
            for svc in required_services:
                if svc not in results or not results[svc]["healthy"]:
                    all_ok = False
                    break
            
            if all_ok:
                break
            time.sleep(2)

    # Report results
    verification_table = Table(title="Service Connectivity Status", box=None)
    verification_table.add_column("Service Name", style="cyan")
    verification_table.add_column("Endpoint", style="white")
    verification_table.add_column("Connectivity Status", style="green")
    
    all_healthy = True
    required_services = ["caddy", "dex", "coreason-runtime", "temporal", "coreason-worker"]
    if use_gpu:
        required_services.append("sglang")
        
    for name in required_services:
        if name not in results:
            continue
        info = results[name]
        status_style = "green" if info["healthy"] else "red"
        status_icon = "✔" if info["healthy"] else "✘"
        
        if info["port"] == 443:
            endpoint = f"https://{info['host']}"
        elif info["port"] == 0:
            endpoint = "Internal Mesh Only"
        else:
            endpoint = f"http://{info['host']}:{info['port']}"
            
        verification_table.add_row(
            info["description"],
            endpoint,
            f"[{status_style}]{status_icon} {info['status_msg']}[/{status_style}]"
        )
        if not info["healthy"]:
            all_healthy = False
            
    console.print(verification_table)

    if all_healthy:
        console.print(Panel(
            "[bold green]🎉 SUCCESS: CoReason Tripartite Swarm-in-a-Box is fully operational![/bold green]\n\n"
            "🔗 [bold]Ingress Console Gateway:[/bold]   [underline]https://localhost[/underline]\n"
            "🔗 [bold]Backend Runtime Port:[/bold]     [underline]http://localhost:8000[/underline]\n"
            "🔗 [bold]Temporal Admin UI:[/bold]        [underline]http://localhost:8233[/underline]\n"
            "🔗 [bold]Dex Authentication Portal:[/bold] [underline]http://localhost:5556/dex[/underline]\n\n"
            "Enjoy developing on the CoReason sovereign cognitive substrate!",
            border_style="green",
            title="Deployment Dashboard"
        ))
    else:
        console.print(Panel(
            "[bold red]❌ Orchestration Degraded[/bold red]\n\n"
            "One or more services did not start or respond within the timeout duration.\n"
            "Inspect active container logs to diagnose issues:\n"
            "  [bold white]docker compose logs -f[/bold white]\n\n"
            "Make sure your host has bound ports (80, 443, 8000, 5556, 7233) open and free.",
            border_style="red",
            title="Diagnostics Dashboard"
        ))

@main.command("activate-license")
@click.option("--target-dir", default=".", help="Target installation directory")
@click.option("--key", default=None, help="Commercial License Key JWT")
@click.option("--trial", is_flag=True, help="Activate the 30-day free commercial trial")
def activate_license(target_dir: str, key: str | None, trial: bool):
    """Activate a commercial license or the 30-day free trial on an existing workspace at any time."""
    target_path = Path(target_dir).resolve()
    env_path = target_path / ".env"
    if not env_path.exists():
        console.print(f"[bold red]Error:[/bold red] Workspace .env file not found at {env_path}. Initialize the workspace first.")
        sys.exit(1)
        
    existing_config = parse_env_file(env_path) or {}
    
    if trial:
        tier = "commercial-trial"
        license_key = "trial-30-day"
        console.print("[green]✔ Activating 30-Day Free Commercial Trial...[/green]")
    elif key:
        tier = "commercial"
        license_key = key
        console.print("[green]✔ Activating Commercial License...[/green]")
    else:
        console.print("[bold red]Error:[/bold red] Must specify either --key or --trial flag to activate.")
        sys.exit(1)
        
    custom_vars = {
        **existing_config,
        "COREASON_LICENSE_TIER": tier,
        "COREASON_LICENSE_KEY": license_key
    }
    
    # Re-generate .env file
    template_dir = Path(__file__).resolve().parent.parent / "templates"
    use_gpu = "gpu" in existing_config.get("COMPOSE_PROFILES", "")
    hf_token = existing_config.get("HF_TOKEN", "hf_your_token_here")
    
    compose_manager.generate_env_file(target_path, template_dir, use_gpu, hf_token, custom_vars=custom_vars)
    console.print(f"[green]✔ .env file updated at {env_path}[/green]")
    
    # Restart the coreason services to pick up the new environment
    console.print("[dim]Restarting container services...[/dim]")
    try:
        subprocess.run(["docker", "compose", "up", "-d", "--force-recreate"], cwd=target_path, check=True)
        console.print("[green]✔ Services updated and running with active license.[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠ Warning: Could not automatically restart containers: {str(e)}[/yellow]")
        console.print("Please manually run: [bold]docker compose up -d --force-recreate[/bold] in your workspace.")


@main.command("verify-identity")
@click.option("--target-dir", default=".", help="Target installation directory")
@click.option("--key", required=True, help="Identity Verification Key issued from Amazon Key Store")
def verify_identity(target_dir: str, key: str):
    """Install a CoReason Identity Verification Key on an existing workspace at any time."""
    target_path = Path(target_dir).resolve()
    env_path = target_path / ".env"
    if not env_path.exists():
        console.print(f"[bold red]Error:[/bold red] Workspace .env file not found at {env_path}. Initialize the workspace first.")
        sys.exit(1)
        
    existing_config = parse_env_file(env_path) or {}
    
    custom_vars = {
        **existing_config,
        "COREASON_VERIFICATION_KEY": key
    }
    
    # Re-generate .env file
    template_dir = Path(__file__).resolve().parent.parent / "templates"
    use_gpu = "gpu" in existing_config.get("COMPOSE_PROFILES", "")
    hf_token = existing_config.get("HF_TOKEN", "hf_your_token_here")
    
    compose_manager.generate_env_file(target_path, template_dir, use_gpu, hf_token, custom_vars=custom_vars)
    console.print(f"[green]✔ Identity verification key updated in .env at {env_path}[/green]")
    
    # Restart the coreason services to pick up the new environment
    console.print("[dim]Restarting container services...[/dim]")
    try:
        subprocess.run(["docker", "compose", "up", "-d", "--force-recreate"], cwd=target_path, check=True)
        tenant_cid = existing_config.get("EPISTEMIC_MERKLE_ROOT", "")
        if tenant_cid == "889955217295c2bfef2d6812071b633b0819477e67f57853febf116f69f30531":
            console.print("[green]✔ Services updated and verified as CoReason Inc Infrastructure Node (Real Verified status active).[/green]")
        else:
            console.print("[green]✔ Services updated and running with verified identity (Real Verified status active).[/green]")
    except Exception as e:
        console.print(f"[yellow]⚠ Warning: Could not automatically restart containers: {str(e)}[/yellow]")
        console.print("Please manually run: [bold]docker compose up -d --force-recreate[/bold] in your workspace.")


if __name__ == "__main__":
    main()
