# test_add_env_by_image.py

import json
from time import sleep
from secret_sdk.client.lcd import LCDClient
from secret_sdk.key.mnemonic import MnemonicKey

def hex_to_int_array(hex_str: str):
    """Convert a hex string to a list of integer byte values."""
    return list(bytearray.fromhex(hex_str.strip()))

# --- Configuration ---
CHAIN_ID = "secretdev-1"
LCD_URL = "http://51.8.118.178:1317"
CONTRACT_ADDRESS = "secret1dl264h03ufduej8wrl9f7t0f4a0q5fdqcsgftf"

MNEMONIC = (
    "grant rice replace explain federal release fix clever romance raise often wild taxi quarter "
    "soccer fiber love must tape steak together observe swap guitar"
)

# Initialize client and wallet
mk = MnemonicKey(mnemonic=MNEMONIC)
client = LCDClient(chain_id=CHAIN_ID, url=LCD_URL)
wallet = client.wallet(mk)

# --- Prepare quote and collateral ---
with open("quote_and_collateral/quote.txt", "r", encoding="utf-8") as f:
    quote_hex = f.read()
with open("quote_and_collateral/collateral.txt", "r", encoding="utf-8") as f:
    collateral_hex = f.read()

quote = hex_to_int_array(quote_hex)
collateral = hex_to_int_array(collateral_hex)

# --- Build the image filter from the quote (only the required fields) ---
# Offsets according to tdx_quote_t structure:
#   mr_td: bytes 184..232
#   rtmr1: bytes 424..472
#   rtmr2: bytes 472..520
#   rtmr3: bytes 520..568
quote_bytes = bytearray(quote)
image_filter = {
    "mr_td": list(quote_bytes[184:232]),
    "rtmr1": list(quote_bytes[424:472]),
    "rtmr2": list(quote_bytes[472:520]),
    "rtmr3": list(quote_bytes[520:568]),
}

# --- Execute AddEnvByImage ---
exec_msg = {
    "add_env_by_image": {
        "image_filter": image_filter,
        "secrets_plaintext": "my_environment_secret"
    }
}

print(">>> Sending AddEnvByImage execute message")
tx = wallet.execute_tx(CONTRACT_ADDRESS, exec_msg)
print("tx hash:", tx.txhash)

# Wait a bit for the transaction to be processed
sleep(5)

info = client.tx.tx_info(tx_hash=tx.txhash)
print("Transaction info:", info)
