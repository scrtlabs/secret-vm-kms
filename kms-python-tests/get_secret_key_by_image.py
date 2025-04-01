import json
from secret_sdk.client.lcd import LCDClient
from secret_sdk.key.mnemonic import MnemonicKey

def hex_to_int_array(hex_str):
    # Convert hex string to a list of integers (bytes)
    return list(bytearray.fromhex(hex_str.strip()))

# Network and contract configuration
CHAIN_ID = "secretdev-1"
LCD_URL = "http://51.8.118.178:1317"
CONTRACT_ADDRESS = "secret15dllw6yf2tqjjcvl4j3xtj59pvdzaktqfm4dx7"

# Mnemonic key for the wallet (queries do not necessarily need a wallet, but it can be used)
MNEMONIC = (
    "grant rice replace explain federal release fix clever romance raise often wild taxi quarter "
    "soccer fiber love must tape steak together observe swap guitar"
)

# Initialize LCD client
mk = MnemonicKey(mnemonic=MNEMONIC)
client = LCDClient(chain_id=CHAIN_ID, url=LCD_URL)

# Read quote and collateral from files
with open("quote_and_collateral/quote.txt", "r", encoding="utf-8") as f:
    quote_hex = f.read().strip()
with open("quote_and_collateral/collateral.txt", "r", encoding="utf-8") as f:
    collateral_hex = f.read().strip()

# Convert hex strings to integer arrays
quote = hex_to_int_array(quote_hex)
collateral = hex_to_int_array(collateral_hex)

# Build the query message for get_secret_key_by_image
query_msg = {
    "get_secret_key_by_image": {
        "quote": quote,
        "collateral": collateral,
    }
}

print("Sending query message: get_secret_key_by_image")
try:
    query_result = client.wasm.contract_query(CONTRACT_ADDRESS, query_msg)
    print("Query response:")
    print(json.dumps(query_result, indent=2))
except Exception as e:
    print("Error querying get_secret_key_by_image:", e)
