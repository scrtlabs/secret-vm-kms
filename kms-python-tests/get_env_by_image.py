# test_get_env_by_image.py

import json
from secret_sdk.client.lcd import LCDClient
from secret_sdk.key.mnemonic import MnemonicKey

def hex_to_int_array(hex_str: str):
    """Convert a hex string to a list of integer byte values."""
    return list(bytearray.fromhex(hex_str.strip()))

# --- Configuration ---
CHAIN_ID = "secretdev-1"
LCD_URL = "http://51.8.118.178:1317"
CONTRACT_ADDRESS = "secret1dl264h03ufduej8wrl9f7t0f4a0q5fdqcsgftf"

# Initialize client (no wallet needed for queries)
client = LCDClient(chain_id=CHAIN_ID, url=LCD_URL)

# --- Prepare quote and collateral ---
with open("quote_and_collateral/quote.txt", "r", encoding="utf-8") as f:
    quote_hex = f.read()
with open("quote_and_collateral/collateral.txt", "r", encoding="utf-8") as f:
    collateral_hex = f.read()

quote = hex_to_int_array(quote_hex)
collateral = hex_to_int_array(collateral_hex)

# --- Query GetEnvByImage ---
query_msg = {
    "get_env_by_image": {
        "quote": quote,
        "collateral": collateral
    }
}

print(">>> Sending GetEnvByImage query message")
result = client.wasm.contract_query(CONTRACT_ADDRESS, query_msg)
print("Response:")
print(json.dumps(result, indent=2))
