# scratch/test_kyc_flow.py
import sys
from pathlib import Path
import json
import base64
from unittest.mock import patch, MagicMock

# Add src to the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from coreason_installer import diagnostics

# The private key corresponding to the hardcoded public key in diagnostics.py
PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCyZcQaVDj3AZxJ
Xpsji1C+6j1Oqi9b1nR/bRleAc2k2HWiatqZr2wewK3cULnDy4bsqqEhLhH3vAWY
LtsGorlGCOSAnlJJUxp7HiJyBxtqU2bZ7IvKWxOG48HfDVilpNk4zY3lm2/V0KsL
+O4DvdiO4F40XEyUxpJGNeLar82nRmWCsAJYAiY4RZDZFPMJP24Gso3IQZqtVeS1
GwJ/u6xBxQPma4atC1U218n1lirl5oChfP3AiOr8KrO1HZwY4ZXL0DZAIuK1/z69
UErv5YKbMjUrwQ+MJZzNFZyHR4L+znSCyuEmeqEUORoMWTHkRRexBcTu/EmMrbcn
TjqVFnVNAgMBAAECggEAKUKTM/m1wR88u9VnMTXYA4fejRKcaHO1twEPJGhrXQx5
TIrFK1Vgvs4WiAWdqVSpzJP8N1XV7wOsEZIIs0SwcCu/WaYEZxQS5FXIZrIRG6rV
d2KXxEIDRqfnn4SRM6JoYRRdlLS6DWw5G0hEGFZwvz7SWu7cAW7ZxuZQpP6TJHQn
OairJkaZ+W//2KyRFzhok0yGOprCZDHLV8WQSZVw1Jp2g6Bd2GchrujXK0K5hwU+
J4zL8nv3MMFr2u8tnfYURihfVPtULkc7fxaKdKEux8lpk5+3G4T3zugW+F8VKaDD
R6b2JjQVG/uZ4NattfhH24t2FI34z2WSG7p0tDZ0GwKBgQDeJ2m7jVCuclzQv0+m
qMdSpbQ0NcwDnnamWGtd2gOFcnz/BxBcAwDHzFMaGQNlXLYavJ27zgqhznIM21An
3FJkP6aVtR9fFYEXwFFKzIDw9L3sWZSRkLKp7YKzICHfsugnZznW4/7HiFpfabPE
sIdx8AN8phdTewL8VVx5a+IjcwKBgQDNk7zCJwGNhqAUSoGeSy4gbwkMftezQ5ju
xR1JpSh75bsRMRXplchpjzFt//32nLVj3MQbqa9UWwiR+DYS+h0I22v39Mnz3Pdr
5lajdrBNXf7qFGZ+nrvYkgC+v+Qfo/7gcXQCu5OMdl3KMQFhMyIIOL+2AYk8z+s0
Zrz+UHpUPwKBgDLVKeh0iYWhPYO2gu9Lp3BN4lIgDTK2y8d8a/TpseyTKe7hGuky
9rbBFjLejlxfPnwXtLAIkX480vQGKu00CNZPijqvWyJStVtN8kv/R3HbTqoKRWiZ
h4hChKmgLKAXO+/oOt/lA6N8m9FBSpUzH4r+tI2NI8FCYIiEr8hI21HpAoGAfYj9
90GCfT38eueUh2k5XazwRaUfauSYexX7cIFeW2pJ9ZGX4/AHVg6PDLEKEJJZYgXp
60qPOl/st9ZujuAU4te68suUl0oT/NvHhEJyHoyLob2baS7dXr6pndHoKDoo5j3h
rdmFnHybgWCzivuCiKq+xxHhEDWXV4R1XIcgbFkCgYB9R7iuhHJxvEo4QVdd7WY0
SXo8lXUWI8adcvyo6GT/LZVyG+flkbcZp+NljE0kzUYZY2vVqtjsy591ctIQVtoJ
X0FMvth2VeJV80It59EJGpTsN+jXlWN6p+45a5d2yap7hVdpDucqyE+gsKZ6pQS7
L0fR77MBuUTXRYXoy1oM+g==
-----END PRIVATE KEY-----"""


def test_encryption_and_decryption():
    print("Running encryption test...")
    kyc_data = {
        "legal_name": "Test Corporation LLC",
        "jurisdiction": "US-DE",
        "file_number": "12345678",
        "date_of_incorporation": "2020-01-01"
    }

    # 1. Encrypt using diagnostics utility
    encrypted_base64 = diagnostics.encrypt_kyc_data(kyc_data)
    assert isinstance(encrypted_base64, str)
    assert len(encrypted_base64) > 0
    print("SUCCESS: Encrypted successfully. Length:", len(encrypted_base64))

    # 2. Decode the outer base64
    outer_json_bytes = base64.b64decode(encrypted_base64)
    payload = json.loads(outer_json_bytes.decode('utf-8'))

    # Verify keys exist
    assert "encrypted_key" in payload
    assert "iv" in payload
    assert "tag" in payload
    assert "ciphertext" in payload

    # 3. Decode the inner elements
    encrypted_key = base64.b64decode(payload["encrypted_key"])
    iv = base64.b64decode(payload["iv"])
    tag = base64.b64decode(payload["tag"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    # 4. Decrypt the AES key using the private RSA key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    private_key = serialization.load_pem_private_key(PRIVATE_KEY_PEM.encode(), password=None)
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    assert len(aes_key) == 32
    print("SUCCESS: AES key decrypted successfully with RSA private key.")

    # 5. Decrypt the ciphertext using the AES key
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = ciphertext + tag
    decrypted_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)

    # 6. Parse and assert JCS equivalence
    decrypted_json = json.loads(decrypted_bytes.decode('utf-8'))
    assert decrypted_json == kyc_data
    print("SUCCESS: Decrypted data matches the original KYC input perfectly!")


@patch("urllib.request.urlopen")
def test_network_registration(mock_urlopen):
    print("Running registration network test...")
    # Mock the http response from trusted.coreason.ai
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"status": "registered", "tenant_cid": "88995521"}'
    mock_urlopen.return_value.__enter__.return_value = mock_response

    tenant_cid = "88995521"
    encrypted_payload = "dummy_base64_payload"

    result = diagnostics.register_tenant_kyc(tenant_cid, encrypted_payload)
    assert result == {"status": "registered", "tenant_cid": "88995521"}
    print("SUCCESS: Mocked network registration completes successfully.")


if __name__ == "__main__":
    try:
        test_encryption_and_decryption()
        test_network_registration()
        print("\nALL TESTS PASSED SUCCESSFULLY!")
    except Exception as e:
        print(f"\nTEST FAILED: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
