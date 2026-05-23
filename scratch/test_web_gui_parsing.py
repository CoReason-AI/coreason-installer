# scratch/test_web_gui_parsing.py
import sys
from pathlib import Path
import os

# Add src to the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import web_gui

def test_parse_env_file():
    print("Running env parsing test...")
    
    # Create a temporary workspace and .env file
    test_dir = Path("temp_test_workspace")
    test_dir.mkdir(exist_ok=True)
    env_path = test_dir / ".env"
    
    env_content = """
    # This is a comment
    EPISTEMIC_MERKLE_ROOT=889955217295c2bfef2d6812071b633b0819477e67f57853febf116f69f30531
    COREASON_BIND_IP="127.0.0.1"
    HTTP_PROXY='http://proxy.local:8080'
    HTTPS_PROXY=http://proxy.local:8080
    NO_PROXY=localhost,127.0.0.1
    HF_TOKEN=hf_abc123xyz
    
    # Another comment or empty line
    """
    
    with open(env_path, "w", encoding="utf-8") as f:
        f.write(env_content)
        
    try:
        config = web_gui.parse_env_file(env_path)
        assert config is not None
        assert config["EPISTEMIC_MERKLE_ROOT"] == "889955217295c2bfef2d6812071b633b0819477e67f57853febf116f69f30531"
        assert config["COREASON_BIND_IP"] == "127.0.0.1"
        assert config["HTTP_PROXY"] == "http://proxy.local:8080"
        assert config["HTTPS_PROXY"] == "http://proxy.local:8080"
        assert config["NO_PROXY"] == "localhost,127.0.0.1"
        assert config["HF_TOKEN"] == "hf_abc123xyz"
        print("SUCCESS: Existing config parsed correctly from .env file!")
    finally:
        # Cleanup
        if env_path.exists():
            os.remove(env_path)
        if test_dir.exists():
            os.rmdir(test_dir)

if __name__ == "__main__":
    try:
        test_parse_env_file()
        print("\nALL TESTS PASSED SUCCESSFULLY!")
    except Exception as e:
        print(f"\nTEST FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
