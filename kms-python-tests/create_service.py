import json
from secret_sdk.client.lcd import LCDClient
from secret_sdk.key.mnemonic import MnemonicKey

# Replace with your mnemonic.
mnemonic = (
    "grant rice replace explain federal release fix clever romance raise often wild taxi quarter "
    "soccer fiber love must tape steak together observe swap guitar"
)

# Create a MnemonicKey from the mnemonic.
mk = MnemonicKey(mnemonic=mnemonic)

# Initialize the LCD client with your chain ID and LCD endpoint.
client = LCDClient(chain_id="secretdev-1", url="http://51.8.118.178:1317")

# Obtain the wallet from the client.
wallet = client.wallet(mk)

# Contract address (update if necessary).
contract_address = "secret17p5c96gksfwqtjnygrs0lghjw6n9gn6c804fdu"

# Build the execute message for creating a new service.
# This corresponds to the CreateService { name: String } variant.
create_service_msg = {
    "create_service": {
        "name": "TestService"
    }
}

print("Execute message:")
print(json.dumps(create_service_msg, indent=2))

# Broadcast the execute message.
# Note: You might need to adjust fees and gas parameters according to your chain.
try:
    tx_result = wallet.execute_tx(contract_address, create_service_msg)
    print("Transaction result:")
    print(json.dumps(tx_result, indent=2))
except Exception as e:
    print("Error executing contract:", e)
