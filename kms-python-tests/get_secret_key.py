import json
from secret_sdk.client.lcd import LCDClient
from secret_sdk.key.mnemonic import MnemonicKey

# Load mnemonic and initialize the LCD client.
mnemonic = (
    "grant rice replace explain federal release fix clever romance raise often wild taxi quarter "
    "soccer fiber love must tape steak together observe swap guitar"
)
mk = MnemonicKey(mnemonic=mnemonic)
client = LCDClient(chain_id="secretdev-1", url="http://51.8.118.178:1317")

# Contract details.
contract_address = "secret17p5c96gksfwqtjnygrs0lghjw6n9gn6c804fdu"

# Read the hex-encoded quote and collateral from files.
with open("quote_and_collateral/quote.txt", "r", encoding="utf-8") as f:
    quote_hex = f.read().strip()
with open("quote_and_collateral/collateral.txt", "r", encoding="utf-8") as f:
    collateral_hex = f.read().strip()

# Decode hex strings into byte arrays and then convert to a list of integers.
quote = list(bytearray.fromhex(quote_hex))
collateral = list(bytearray.fromhex(collateral_hex))

# Construct the query message.
query_msg = {
    "get_secret_key": {
        "service_id": 1,
        "quote": quote,
        "collateral": collateral,
    }
}

# Query the contract.
result = client.wasm.contract_query(contract_address, query_msg)
print("Secret Key Response:")
print(json.dumps(result, indent=2))
