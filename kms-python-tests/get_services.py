import json
from secret_sdk.client.lcd import LCDClient
from secret_sdk.key.mnemonic import MnemonicKey

# Replace with your mnemonic
mnemonic = (
    "grant rice replace explain federal release fix clever romance raise often wild taxi quarter "
    "soccer fiber love must tape steak together observe swap guitar"
)

# Create a MnemonicKey and initialize the LCD client.
mk = MnemonicKey(mnemonic=mnemonic)
client = LCDClient(chain_id="secretdev-1", url="http://51.8.118.178:1317")

# Contract address (update if necessary).
contract_address = "secret17p5c96gksfwqtjnygrs0lghjw6n9gn6c804fdu"

# Construct the query message for list_services.
# Note: according to the contract, the query message is {"list_services": {}}.
query_msg = {"list_services": {}}

print("Query Message:")
print(json.dumps(query_msg, indent=2))

# Query the contract.
try:
    result = client.wasm.contract_query(contract_address, query_msg)
    print("List Services Response:")
    print(json.dumps(result, indent=2))
except Exception as e:
    print("Error querying contract:", e)
