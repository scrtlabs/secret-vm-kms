import json
from time import sleep

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
        "service_id": 1,
        "image_filter": clean_image_data
    }
}

# Print the execute message.
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

# Contract address.
contract_address = "secret17p5c96gksfwqtjnygrs0lghjw6n9gn6c804fdu"

# Broadcast the execute message.

t = wallet.execute_tx(contract_address, execute_msg)
print("Execute result:", t)

sleep(5)

tx_info = client.tx.tx_info(
    tx_hash=t.txhash,
)

print("Transaction info:", tx_info)


# --- Build a SecretCLI command string equivalent to the above execution.
# Convert the execute message to a JSON string.
json_msg = json.dumps(execute_msg)
# Escape every double-quote by inserting a backslash.
escaped_json_msg = json_msg.replace('"', '\\"')

# Build the final SecretCLI command string.
# (Here we assume an execute command; adjust "tx compute execute" as needed.)
secretcli_command = f'secretcli tx compute execute {contract_address} "{escaped_json_msg}"'
print("\nSecretCLI command:")
print(secretcli_command)
