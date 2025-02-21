import json
from secret_sdk.client.lcd import LCDClient
from secret_sdk.key.mnemonic import MnemonicKey

def hex_to_int_array(hex_str):
    """Convert a hex string to a list of integer byte values."""
    return list(bytearray.fromhex(hex_str))

# Read the image filter JSON from file.
with open("test_image/image.json", "r", encoding="utf-8") as f:
    image_data = json.load(f)

# Remove fields with null values and convert hex strings to lists of integers.
clean_image_data = {
    key: hex_to_int_array(value)
    for key, value in image_data.items()
    if value is not None
}

print("Clean image filter data:")
print(json.dumps(clean_image_data, indent=2))

# Build the execute message for add_image_to_service.
execute_msg = {
    "add_image_to_service": {
        "service_id": 0,
        "image_filter": clean_image_data
    }
}

print("Execute message:")
print(json.dumps(execute_msg, indent=2))

# Initialize the LCD client with your mnemonic and endpoint.
mnemonic = (
    "grant rice replace explain federal release fix clever romance raise often wild taxi quarter "
    "soccer fiber love must tape steak together observe swap guitar"
)
mk = MnemonicKey(mnemonic=mnemonic)
client = LCDClient(chain_id="secretdev-1", url="http://51.8.118.178:1317")
wallet = client.wallet(mk)

# Contract address (update if necessary)
contract_address = "secret17p5c96gksfwqtjnygrs0lghjw6n9gn6c804fdu"

# Broadcast the execute message.
# Note: You may need to adjust fees and gas parameters depending on your chain.
try:
    result = wallet.execute_tx(contract_address, execute_msg)
    print("Execute result:")
    print(json.dumps(result, indent=2))
except Exception as e:
    print("Error executing contract:", e)
