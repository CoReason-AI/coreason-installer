# scratch/test_compose_profile.py
import sys
from pathlib import Path
import os
import yaml

# Add package root to the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from coreason_installer import compose_manager

def test_compose_profiles():
    print("Running compose profile tests...")
    
    # Verify templates/compose.yaml contains coreason-mesh-node service under share-compute
    compose_path = Path(__file__).resolve().parent.parent / "templates" / "compose.yaml"
    assert compose_path.exists(), "compose.yaml template does not exist"
    
    with open(compose_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        
    services = data.get("services", {})
    assert "coreason-mesh-node" in services, "coreason-mesh-node service missing from templates/compose.yaml"
    
    mesh_node = services["coreason-mesh-node"]
    assert "profiles" in mesh_node, "profiles key missing from coreason-mesh-node service"
    assert "share-compute" in mesh_node["profiles"], "share-compute profile not defined for coreason-mesh-node"
    print("SUCCESS: templates/compose.yaml is properly configured with coreason-mesh-node under share-compute.")


def test_env_profile_compilation():
    print("Running env profile compilation tests...")
    test_dir = Path("temp_test_env_workspace")
    test_dir.mkdir(exist_ok=True)
    template_dir = Path(__file__).resolve().parent.parent / "templates"
    
    try:
        # Case 1: Compute sharing = True, GPU = False
        custom_vars = {"COREASON_CONTRIBUTE_COMPUTE": "true"}
        env_file = compose_manager.generate_env_file(
            test_dir,
            template_dir,
            gpu_detected=False,
            custom_vars=custom_vars
        )
        
        # Read generated .env
        with open(env_file, "r") as f:
            lines = f.read().splitlines()
            
        profiles_line = [line for line in lines if line.startswith("COMPOSE_PROFILES=")][0]
        assert "share-compute" in profiles_line
        assert "gpu" not in profiles_line
        print("SUCCESS: share-compute profile correctly enabled on CPU workload.")
        
        # Case 2: Compute sharing = True, GPU = True
        custom_vars = {"COREASON_CONTRIBUTE_COMPUTE": "true"}
        env_file = compose_manager.generate_env_file(
            test_dir,
            template_dir,
            gpu_detected=True,
            custom_vars=custom_vars
        )
        
        with open(env_file, "r") as f:
            lines = f.read().splitlines()
            
        profiles_line = [line for line in lines if line.startswith("COMPOSE_PROFILES=")][0]
        assert "share-compute" in profiles_line
        assert "gpu" in profiles_line
        print("SUCCESS: both gpu and share-compute profiles correctly enabled on GPU workload.")
        
        # Case 3: Compute sharing = False, GPU = False
        custom_vars = {"COREASON_CONTRIBUTE_COMPUTE": "false"}
        env_file = compose_manager.generate_env_file(
            test_dir,
            template_dir,
            gpu_detected=False,
            custom_vars=custom_vars
        )
        
        with open(env_file, "r") as f:
            lines = f.read().splitlines()
            
        profiles_line = [line for line in lines if line.startswith("COMPOSE_PROFILES=")][0]
        assert "share-compute" not in profiles_line
        assert "gpu" not in profiles_line
        print("SUCCESS: profiles empty when compute sharing is disabled.")
        
    finally:
        env_path = test_dir / ".env"
        if env_path.exists():
            os.remove(env_path)
        if test_dir.exists():
            os.rmdir(test_dir)


if __name__ == "__main__":
    try:
        test_compose_profiles()
        test_env_profile_compilation()
        print("\nALL TESTS PASSED SUCCESSFULLY!")
    except Exception as e:
        print(f"\nTEST FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
