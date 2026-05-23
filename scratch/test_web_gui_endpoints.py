# scratch/test_web_gui_endpoints.py
import sys
from pathlib import Path
import unittest
from unittest.mock import patch, MagicMock

# Add package root to the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from coreason_installer import web_gui

class TestWebGuiEndpoints(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path("temp_web_gui_test")
        self.test_dir.mkdir(exist_ok=True)
        # Create templates dummy files inside test_dir to avoid modifying repo templates/
        self.template_dir = self.test_dir / "templates"
        self.template_dir.mkdir(exist_ok=True)
        
        # Write dummy files to templates
        with open(self.template_dir / "env.example", "w") as f:
            f.write("COREASON_MESH_MODE=strict-genesis\nCOREASON_LICENSE_TIER=prosperity-3.0\nCOREASON_LICENSE_KEY=\nCOREASON_VERIFICATION_KEY=\n")
        with open(self.template_dir / "Caddyfile", "w") as f:
            f.write("# Dummy Caddyfile")
        with open(self.template_dir / "dex-config.yaml", "w") as f:
            f.write("# Dummy Dex Config")
        with open(self.template_dir / "compose.yaml", "w") as f:
            f.write("# Dummy compose.yaml\nnetworks:\n  swarm-mesh:\n    internal: true\n")

    def tearDown(self):
        # Cleanup temp files
        for filename in ["env.example", "Caddyfile", "dex-config.yaml", "compose.yaml"]:
            p = self.template_dir / filename
            if p.exists():
                p.unlink()
        if self.template_dir.exists():
            self.template_dir.rmdir()
        
        env_file = self.test_dir / ".env"
        if env_file.exists():
            env_file.unlink()
        for filename in ["compose.yaml", "Caddyfile", "dex-config.yaml", "egress-whitelist.rules", "egress-whitelist.squid.conf"]:
            p = self.test_dir / filename
            if p.exists():
                p.unlink()
                
        # Remove empty directories
        for sub in ["data/lancedb", "data/bronze", "data/silver", "data/gold", "data/plugins", "data/vault", "data", "logs/tenants/test_tenant_cid_xyz", "logs/tenants", "logs"]:
            p = self.test_dir / sub
            if p.exists():
                if p.is_dir():
                    try:
                        p.rmdir()
                    except Exception:
                        pass
        if self.test_dir.exists():
            self.test_dir.rmdir()

    @patch("subprocess.run")
    @patch("coreason_installer.web_gui.compose_manager.handle_permissions")
    def test_install_endpoint_custom_params(self, mock_perms, mock_run):
        mock_perms.return_value = (True, "Mock permissions OK")
        
        # Mock subprocess.run for pull and up
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "Container started"
        mock_res.stderr = ""
        mock_run.return_value = mock_res
        
        # Prepare parameters representing the API call
        params = {
            "target_dir": str(self.test_dir),
            "use_gpu": False,
            "hf_token": "hf_test_token_123",
            "tenant_cid": "test_tenant_cid_xyz",
            "contribute_compute": True,
            "egress_profile": "air-gapped",
            "use_local_proxy": False,
            "bind_ip": "127.0.0.1",
            "mesh_mode": "public",
            "license_tier": "commercial-trial",
            "license_key": "trial-30-day",
            "verification_key": "kms-key-example-999"
        }
        
        # Setup class environment/variables and run install endpoint logic directly
        template_dir = self.template_dir
        target_path = self.test_dir
        
        custom_vars = {
            "EPISTEMIC_MERKLE_ROOT": params["tenant_cid"],
            "COREASON_CONTRIBUTE_COMPUTE": "true" if params["contribute_compute"] else "false",
            "COREASON_BIND_IP": params["bind_ip"],
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "NO_PROXY": "",
            "COREASON_MESH_MODE": params["mesh_mode"],
            "COREASON_NETWORK_MODE": "P2P",
            "COREASON_LICENSE_TIER": params["license_tier"],
            "COREASON_LICENSE_KEY": params["license_key"],
            "COREASON_VERIFICATION_KEY": params["verification_key"]
        }
        
        from coreason_installer import compose_manager
        compose_manager.prepare_directories(target_path, tenant_cid=params["tenant_cid"])
        compose_manager.copy_templates(target_path, template_dir, egress_profile="air-gapped", use_local_proxy=False)
        compose_manager.generate_env_file(target_path, template_dir, False, params["hf_token"], custom_vars=custom_vars)
        
        # Check that the .env contains the custom parameters correctly
        env_path = target_path / ".env"
        self.assertTrue(env_path.exists())
        
        config = web_gui.parse_env_file(env_path)
        self.assertEqual(config["COREASON_MESH_MODE"], "public")
        self.assertEqual(config["COREASON_NETWORK_MODE"], "P2P")
        self.assertEqual(config["COREASON_LICENSE_TIER"], "commercial-trial")
        self.assertEqual(config["COREASON_LICENSE_KEY"], "trial-30-day")
        self.assertEqual(config["COREASON_VERIFICATION_KEY"], "kms-key-example-999")

    @patch("subprocess.run")
    def test_reconfigure_endpoints(self, mock_run):
        # 1. Create a dummy base installation
        env_path = self.test_dir / ".env"
        with open(env_path, "w") as f:
            f.write("COREASON_MESH_MODE=strict-genesis\nCOREASON_LICENSE_TIER=prosperity-3.0\nCOREASON_LICENSE_KEY=\nCOREASON_VERIFICATION_KEY=\n")
            
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "Re-created containers"
        mock_res.stderr = ""
        mock_run.return_value = mock_res
        
        # 2. Test license activation reconfig path
        target_path = self.test_dir
        existing_config = web_gui.parse_env_file(env_path) or {}
        self.assertEqual(existing_config.get("COREASON_LICENSE_TIER"), "prosperity-3.0")
        
        # Apply commercial key
        custom_vars = {
            **existing_config,
            "COREASON_LICENSE_TIER": "commercial",
            "COREASON_LICENSE_KEY": "jwt-new-key-value"
        }
        
        from coreason_installer import compose_manager
        compose_manager.generate_env_file(target_path, self.template_dir, False, "hf_dummy", custom_vars=custom_vars)
        
        new_config = web_gui.parse_env_file(env_path) or {}
        self.assertEqual(new_config.get("COREASON_LICENSE_TIER"), "commercial")
        self.assertEqual(new_config.get("COREASON_LICENSE_KEY"), "jwt-new-key-value")
        
        # Apply verification key
        custom_vars_2 = {
            **new_config,
            "COREASON_VERIFICATION_KEY": "kms-new-key-value"
        }
        compose_manager.generate_env_file(target_path, self.template_dir, False, "hf_dummy", custom_vars=custom_vars_2)
        
        new_config_2 = web_gui.parse_env_file(env_path) or {}
        self.assertEqual(new_config_2.get("COREASON_VERIFICATION_KEY"), "kms-new-key-value")
        self.assertEqual(new_config_2.get("COREASON_LICENSE_TIER"), "commercial")

if __name__ == "__main__":
    unittest.main()
