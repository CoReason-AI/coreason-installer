# diagnostics.py
import subprocess
import shutil
import os
import platform
from typing import Any

def get_platform_info() -> dict[str, str]:
    """Retrieve detailed OS and CPU architecture information."""
    system = platform.system()
    machine = platform.machine().lower()
    
    # Standardize architecture names
    if machine in ["amd64", "x86_64", "x64"]:
        arch = "x86_64"
    elif machine in ["arm64", "aarch64"]:
        arch = "arm64"
    else:
        arch = machine
        
    os_name = "macOS" if system == "Darwin" else system
    
    return {
        "os": os_name,
        "release": platform.release(),
        "arch": arch,
        "python_version": platform.python_version()
    }


def check_docker() -> dict[str, Any]:
    """Verify Docker installation, running status, and retrieve version details."""
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return {"installed": False, "running": False, "compose_ok": False, "error": "Docker executable not found in PATH."}
    
    # Get Docker CLI and Server version
    docker_version = "Unknown"
    running = False
    error_msg = ""
    try:
        res = subprocess.run(["docker", "version", "--format", "{{.Client.Version}}//{{.Server.Version}}"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            running = True
            parts = res.stdout.strip().split("//")
            docker_version = f"Client {parts[0]}"
            if len(parts) > 1 and parts[1]:
                docker_version += f" / Server {parts[1]}"
        else:
            # Maybe docker daemon is not running
            res_client = subprocess.run(["docker", "--version"], capture_output=True, text=True, check=False)
            docker_version = res_client.stdout.strip().replace("Docker version ", "")
            error_msg = "Docker daemon is not running. Please start the Docker engine."
    except Exception as e:
        error_msg = f"Failed to inspect Docker: {str(e)}"

    # Check Compose compatibility
    compose_ok = False
    compose_version = "Unknown"
    try:
        res = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            compose_ok = True
            compose_version = res.stdout.strip().replace("Docker Compose version ", "")
    except Exception:
        pass
        
    if not compose_ok:
        try:
            res = subprocess.run(["docker-compose", "version"], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                compose_ok = True
                compose_version = res.stdout.strip().replace("docker-compose version ", "")
        except Exception:
            pass

    return {
        "installed": True,
        "running": running,
        "docker_version": docker_version,
        "compose_ok": compose_ok,
        "compose_version": compose_version,
        "error": error_msg
    }


def detect_nvidia_gpu() -> dict[str, Any]:
    """Detect presence of NVIDIA GPUs, driver versions, and CDI configurations."""
    has_gpu = False
    details = ""
    driver_version = "Unknown"
    
    # 1. Try running nvidia-smi
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        try:
            res = subprocess.run([nvidia_smi, "-L"], capture_output=True, text=True, check=False)
            if res.returncode == 0 and "NVIDIA" in res.stdout:
                has_gpu = True
                details = res.stdout.splitlines()[0].strip()
                
            # Get driver and CUDA versions
            res_ver = subprocess.run(
                [nvidia_smi, "--query-gpu=driver_version", "--format=csv,noheader"],
                capture_output=True, text=True, check=False
            )
            if res_ver.returncode == 0:
                driver_version = res_ver.stdout.strip()
        except Exception:
            pass

    # 2. Try Windows Win32_VideoController via WMI
    if not has_gpu and platform.system() == "Windows":
        try:
            res = subprocess.run(
                ["powershell", "-Command", "Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion | ConvertTo-Json"],
                capture_output=True, text=True, check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                import json
                gpus = json.loads(res.stdout)
                if not isinstance(gpus, list):
                    gpus = [gpus]
                for gpu in gpus:
                    name = gpu.get("Name", "")
                    if "NVIDIA" in name.upper():
                        has_gpu = True
                        details = name.strip()
                        driver_version = gpu.get("DriverVersion", "Unknown")
                        break
        except Exception:
            pass

    # 3. Try Linux lspci
    if not has_gpu and platform.system() == "Linux":
        lspci = shutil.which("lspci")
        if lspci:
            try:
                res = subprocess.run([lspci], capture_output=True, text=True, check=False)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        if "NVIDIA" in line:
                            has_gpu = True
                            details = line.strip()
                            break
            except Exception:
                pass

    cdi_configured = False
    if has_gpu:
        if platform.system() == "Linux":
            # Check standard CDI specs path
            cdi_paths = ["/etc/cdi/nvidia.yaml", "/var/run/cdi/nvidia.yaml"]
            for path in cdi_paths:
                if os.path.exists(path):
                    cdi_configured = True
                    break
        elif platform.system() == "Windows":
            # WSL2 integration injects GPUs dynamically
            cdi_configured = True

    return {
        "has_gpu": has_gpu,
        "details": details,
        "driver_version": driver_version,
        "cdi_configured": cdi_configured
    }


def get_system_resources() -> dict[str, Any]:
    """Retrieve system RAM and disk space availability."""
    import psutil  # type: ignore[import-untyped]
    
    # Virtual Memory
    mem = psutil.virtual_memory()
    total_ram_gb = mem.total / (1024 ** 3)
    
    # Disk Space (Current directory)
    disk = psutil.disk_usage(".")
    free_disk_gb = disk.free / (1024 ** 3)
    
    return {
        "ram_gb": total_ram_gb,
        "free_disk_gb": free_disk_gb
    }


def classify_deployment_type(platform_info: dict, gpu_info: dict, resources: dict) -> dict[str, str]:
    """Classifies the host system and recommends the optimal deployment profile."""
    has_gpu = gpu_info.get("has_gpu", False)
    ram_gb = resources.get("ram_gb", 16.0)
    arch = platform_info.get("arch", "x86_64")
    os_name = platform_info.get("os", "Linux")
    
    if arch == "arm64" and os_name == "Linux" and ram_gb <= 12.0:
        mode = "Resource-Constrained Edge (Raspberry Pi)"
        recommendation = "CPU-only inference, minimal pi_bridge sandbox constraints, and remote substrate routing."
        profile = "edge"
    elif has_gpu and ram_gb >= 12.0:
        mode = "Local Workstation (GPU-Accelerated)"
        recommendation = "Full Swarm-in-a-Box with SGLang GPU cognitive engine, native CDI device routing, and WASM sandbox caging."
        profile = "gpu-workstation"
    else:
        mode = "Local Workstation (CPU-Only / Remote Substrate)"
        recommendation = "Full Swarm-in-a-Box with CPU fallback or remote cloud cognitive substrate routing."
        profile = "cpu-workstation"
        
    return {
        "mode": mode,
        "recommendation": recommendation,
        "profile": profile
    }


def calculate_tenant_cid(kyc_data: dict[str, str]) -> tuple[str, str]:
    """Serializes KYC dictionary to a canonical JSON string (RFC 8785 sorted keys)
    using canonicaljson and computes its SHA-256 hash to generate the unique tenant_cid.
    """
    import hashlib
    import canonicaljson
    
    # Encode using the same JCS package used in coreason-manifest
    canonical_bytes = canonicaljson.encode_canonical_json(kyc_data)
    canonical_str = canonical_bytes.decode('utf-8')
    
    # Compute SHA-256
    sha256_hash = hashlib.sha256(canonical_bytes).hexdigest()
    
    return canonical_str, sha256_hash


COREASON_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsmXEGlQ49wGcSV6bI4tQ
vuo9TqovW9Z0f20ZXgHNpNh1omrama9sHsCt3FC5w8uG7KqhIS4R97wFmC7bBqK5
RgjkgJ5SSVMaex4icgcbalNm2eyLylsThuPB3w1YpaTZOM2N5Ztv1dCrC/juA73Y
juBeNFxMlMaSRjXi2q/Np0ZlgrACWAImOEWQ2RTzCT9uBrKNyEGarVXktRsCf7us
QcUD5muGrQtVNtfJ9ZYq5eaAoXz9wIjq/CqztR2cGOGVy9A2QCLitf8+vVBK7+WC
mzI1K8EPjCWczRWch0eC/s50gsrhJnqhFDkaDFkx5EUXsQXE7vxJjK23J046lRZ1
TQIDAQAB
-----END PUBLIC KEY-----"""


def encrypt_kyc_data(kyc_data: dict[str, str]) -> str:
    """Encrypts the canonical representation of the corporate KYC payload using
    hybrid encryption (AES-256-GCM + RSA-OAEP with SHA-256).
    """
    import base64
    import json
    import os
    import canonicaljson
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Serialize to canonical JCS JSON
    canonical_bytes = canonicaljson.encode_canonical_json(kyc_data)

    # Ephemeral key and IV generation
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)

    # AES-GCM Encrypt
    ciphertext_with_tag = aesgcm.encrypt(iv, canonical_bytes, None)
    tag = ciphertext_with_tag[-16:]
    ciphertext = ciphertext_with_tag[:-16]

    # Encrypt AES key using CoReason public RSA key
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    public_key = serialization.load_pem_public_key(COREASON_PUBLIC_KEY_PEM.encode())
    assert isinstance(public_key, RSAPublicKey)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Base64 encode all elements and bundle in JSON structure
    payload = {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }

    # Base64 encode the serialized JSON bundle
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


def register_tenant_kyc(tenant_cid: str, encrypted_kyc: str) -> dict[str, Any]:
    """Registers the public tenant_cid with the encrypted corporate KYC payload
    on the CoReason Trust Network API.
    """
    import urllib.request
    import urllib.error
    import json

    url = "https://trusted.coreason.ai/api/v1/tenant/register"
    req_data = {
        "tenant_cid": tenant_cid,
        "encrypted_kyc": encrypted_kyc
    }
    req_body = json.dumps(req_data).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=req_body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=5) as response:
        res_body = response.read().decode("utf-8")
        return json.loads(res_body)


def calculate_host_fingerprint() -> str:
    """Generate a deterministic, unique SHA-256 fingerprint hash of the host substrate hardware."""
    import uuid
    import hashlib
    
    system = platform.system()
    hardware_ids = []
    
    # 1. Get MAC address (guaranteed unique per machine interface)
    try:
        mac_num = uuid.getnode()
        # uuid.getnode() returns a fallback random 48-bit number if it fails, 
        # but we check if the 8th bit is 1 (which indicates multicast/locally administered, i.e., random fallback)
        if (mac_num >> 40) & 1 == 0:
            hardware_ids.append(str(mac_num))
    except Exception:
        pass
        
    # 2. Get OS-specific UUID
    if system == "Windows":
        try:
            res = subprocess.run(
                ["powershell", "-Command", "(Get-CimInstance Win32_ComputerSystemProduct).UUID"],
                capture_output=True, text=True, check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                hardware_ids.append(res.stdout.strip())
            else:
                # Fallback to wmic bios get serialnumber
                res = subprocess.run(["wmic", "bios", "get", "serialnumber"], capture_output=True, text=True, check=False)
                if res.returncode == 0 and len(res.stdout.splitlines()) > 1:
                    hardware_ids.append(res.stdout.splitlines()[1].strip())
        except Exception:
            pass
            
    elif system == "Linux":
        paths = [
            "/sys/class/dmi/id/product_uuid",
            "/etc/machine-id",
            "/var/lib/dbus/machine-id"
        ]
        for path in paths:
            try:
                if os.path.exists(path):
                    with open(path, "r") as f:
                        val = f.read().strip()
                        if val:
                            hardware_ids.append(val)
                            break
            except Exception:
                pass
                
    elif system == "Darwin":
        try:
            res = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, check=False
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "IOPlatformUUID" in line:
                        parts = line.split("=")
                        if len(parts) > 1:
                            uuid_val = parts[1].replace('"', '').strip()
                            hardware_ids.append(uuid_val)
                            break
        except Exception:
            pass
            
    if not hardware_ids:
        # Fallback using hostname + processor
        hardware_ids.append(platform.node())
        hardware_ids.append(platform.processor())
        
    combined = "//".join(hardware_ids)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()



