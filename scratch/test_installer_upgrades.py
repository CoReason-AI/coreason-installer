# scratch/test_installer_upgrades.py
import sys
from pathlib import Path
import json
import unittest

# Add src to the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from coreason_installer import diagnostics, compose_manager, web_gui

class TestInstallerUpgrades(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path("temp_upgrade_test")
        self.test_dir.mkdir(exist_ok=True)
        # Create templates dummy files inside test_dir to avoid modifying repo templates/
        self.template_dir = self.test_dir / "templates"
        self.template_dir.mkdir(exist_ok=True)
        
        # Write dummy files to templates
        with open(self.template_dir / "env.example", "w") as f:
            f.write("COREASON_MESH_MODE=strict-genesis\nCOREASON_LICENSE_TIER=prosperity-3.0\nCOMPOSE_PROFILES=\nCOREASON_HARDWARE_FINGERPRINT_HASH=\n")
        with open(self.template_dir / "Caddyfile", "w") as f:
            f.write("# Dummy Caddyfile")
        with open(self.template_dir / "dex-config.yaml", "w") as f:
            f.write("# Dummy Dex Config")
        with open(self.template_dir / "compose.yaml", "w") as f:
            f.write("# Dummy compose.yaml\nnetworks:\n  swarm-mesh:\n    internal: true\n")

    def tearDown(self):
        # Cleanup temp files recursively
        def cleanup_path(p: Path):
            if not p.exists():
                return
            if p.is_dir():
                for child in p.iterdir():
                    cleanup_path(child)
                try:
                    p.rmdir()
                except Exception:
                    pass
            else:
                try:
                    p.unlink()
                except Exception:
                    pass

        cleanup_path(self.test_dir)

    def test_calculate_host_fingerprint(self):
        # Test that fingerprint calculation generates a valid 64-character SHA-256 hash
        fingerprint = diagnostics.calculate_host_fingerprint()
        self.assertEqual(len(fingerprint), 64)
        # Ensure it's valid hexadecimal
        int(fingerprint, 16)

    def test_verify_jwt_license_trial(self):
        # Test 30-day trial license is handled correctly offline
        result = web_gui.verify_jwt_license("trial-30-day")
        self.assertTrue(result["valid"])
        self.assertIsNone(result["error"])
        claims = result["claims"]
        self.assertEqual(claims["sub"], "trial-30-day")
        self.assertIn("COMMERCIAL_USE", claims["entitlements"])
        self.assertIn("IP_SOVEREIGNTY_EXCEPTION", claims["entitlements"])

    def test_verify_jwt_license_invalid(self):
        # Test invalid JWT structure returns correct error
        result = web_gui.verify_jwt_license("invalid.token")
        self.assertFalse(result["valid"])
        self.assertIn("Invalid JWS token format", result["error"])

    def test_verify_jwt_license_fallback_alg(self):
        # Test other algorithms (e.g. RS256/ML-DSA) return signature_valid for mock compliance
        # Formulate a mock JWT header: {"alg": "RS256"} and payload: {"exp": 9999999999, "entitlements": ["COMMERCIAL"]}
        import base64
        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"exp": 9999999999, "entitlements": ["COMMERCIAL"]}).encode()).decode().rstrip("=")
        mock_jwt = f"{header}.{payload}.signature"
        
        result = web_gui.verify_jwt_license(mock_jwt)
        self.assertTrue(result["valid"])
        self.assertEqual(result["claims"]["entitlements"], ["COMMERCIAL"])

    def test_verify_jwt_license_eddsa_success(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        import base64
        
        # Header with alg=EdDSA
        header_json = json.dumps({"alg": "EdDSA", "typ": "JWT"})
        header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip("=")
        
        # Payload
        payload_json = json.dumps({"exp": 9999999999, "entitlements": ["COMMERCIAL_USE"]})
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
        
        message = f"{header_b64}.{payload_b64}".encode()
        
        # Sign with the seed corresponding to COREASON_ED25519_PUBKEY_HEX
        seed = bytes.fromhex("33fa04a0956be1146a3ce10eeff0435597035202d177c98c51dc633252095114")
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        sig = priv_key.sign(message)
        sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        
        token = f"{header_b64}.{payload_b64}.{sig_b64}"
        result = web_gui.verify_jwt_license(token)
        self.assertTrue(result["valid"])
        self.assertIsNone(result["error"])
        self.assertIn("COMMERCIAL_USE", result["claims"]["entitlements"])

    def test_verify_jwt_license_es256_success(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        from cryptography.hazmat.primitives import serialization, hashes
        import base64
        
        header_json = json.dumps({"alg": "ES256", "typ": "JWT"})
        header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip("=")
        
        payload_json = json.dumps({"exp": 9999999999, "entitlements": ["COMMERCIAL_USE"]})
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
        
        message = f"{header_b64}.{payload_b64}".encode()
        
        priv_pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyMFghYzIrJAwU8Uo\n"
            "knLhWHpPV7ssTSqhkms7UIptGiahRANCAARHjW864PhxzoLHvlm93m59tIsnNqnX\n"
            "/z6P0rhwrru71aH2UNNh1BAJVgwbDhm4KbGNiOUj8DpfVwn4Xs6Vh+QJ\n"
            "-----END PRIVATE KEY-----"
        )
        priv_key = serialization.load_pem_private_key(priv_pem.encode("utf-8"), password=None)
        der_sig = priv_key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        r_bytes = r.to_bytes(32, byteorder="big")
        s_bytes = s.to_bytes(32, byteorder="big")
        sig_raw = r_bytes + s_bytes
        sig_b64 = base64.urlsafe_b64encode(sig_raw).decode().rstrip("=")
        
        token = f"{header_b64}.{payload_b64}.{sig_b64}"
        result = web_gui.verify_jwt_license(token)
        self.assertTrue(result["valid"])
        self.assertIsNone(result["error"])

    def test_prepare_directories_with_tenant_cid_and_vault(self):
        # Test folder structure includes the vault path and tenant-isolated logs path
        tenant_cid = "test-tenant-cid-abc-123"
        vol_dirs = compose_manager.prepare_directories(self.test_dir, tenant_cid=tenant_cid)
        
        expected_dirs = [
            self.test_dir / "data" / "lancedb",
            self.test_dir / "data" / "bronze",
            self.test_dir / "data" / "silver",
            self.test_dir / "data" / "gold",
            self.test_dir / "data" / "plugins",
            self.test_dir / "data" / "vault",
            self.test_dir / "logs" / "tenants" / tenant_cid
        ]
        
        for d in expected_dirs:
            self.assertTrue(d.exists() and d.is_dir(), f"Expected directory {d} to be created.")
            self.assertIn(d, vol_dirs)

    def test_generate_env_file_with_vault_profile(self):
        # Test that COREASON_USE_VAULT=true correctly appends vault to COMPOSE_PROFILES
        custom_vars = {
            "COREASON_USE_VAULT": "true",
            "COREASON_CONTRIBUTE_COMPUTE": "false"
        }
        
        compose_manager.generate_env_file(
            self.test_dir,
            self.template_dir,
            gpu_detected=False,
            hf_token="dummy_token",
            custom_vars=custom_vars
        )
        
        env_file = self.test_dir / ".env"
        self.assertTrue(env_file.exists())
        
        # Read the generated .env config
        config = {}
        with open(env_file, "r") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    config[k] = v
                    
        self.assertEqual(config.get("COMPOSE_PROFILES"), "vault")
        self.assertEqual(config.get("COREASON_USE_VAULT"), "true")
        self.assertIsNotNone(config.get("COREASON_HARDWARE_FINGERPRINT_HASH"))

if __name__ == "__main__":
    unittest.main()
