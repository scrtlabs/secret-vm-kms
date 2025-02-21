import json
import os
from secret_sdk.client.lcd import LCDClient
from secret_sdk.key.mnemonic import MnemonicKey

def hex_to_int_array(hex_str):
    """Convert a hex string to a list of integer byte values."""
    return list(bytearray.fromhex(hex_str))

# Define the path to the image filter JSON file.
image_file_path = os.path.join("test_image", "image.json")

# Read the image filter JSON from file.
with open(image_file_path, "r", encoding="utf-8") as f:
    raw_image_data = json.load(f)

# Remove fields with null values and convert hex strings to arrays of integers.
clean_image_data = {
    key: hex_to_int_array(value)
    for key, value in raw_image_data.items()
    if value is not None
}

print("Clean image filter data:")
print(json.dumps(clean_image_data, indent=2))

# Build the execute message for remove_image_from_service.
# This message corresponds to the RemoveImageFromService { service_id, image_filter } variant.
execute_msg = {
    "remove_image_from_service": {
        "service_id": 0,
        "image_filter": clean_image_data
    }
}

print("Execute message:")
print(json.dumps(execute_msg, indent=2))

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

# Broadcast the execute message.
# You may need to adjust fees and gas parameters based on your chain's requirements.
try:
    tx_result = wallet.execute_tx(contract_address, execute_msg)
    print("Transaction result:")
    print(json.dumps(tx_result, indent=2))
except Exception as e:
    print("Error executing contract:", e)
