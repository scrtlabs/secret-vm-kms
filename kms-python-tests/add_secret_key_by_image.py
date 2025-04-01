import json
from time import sleep
from secret_sdk.client.lcd import LCDClient
from secret_sdk.key.mnemonic import MnemonicKey


def hex_to_int_array(hex_str):
    # Convert hex string to a list of integers (bytes)
    return list(bytearray.fromhex(hex_str.strip()))


def extract_image_filter_from_quote(quote_bytes):
    """
    Extract image filter fields from the quote bytes using offsets defined by the tdx_quote_t structure.

    tdx_quote_t structure layout (in bytes):
      - header: 48 bytes
      - tcb_svn: 16 bytes (48 to 64)
      - mr_seam: 48 bytes (64 to 112)
      - mr_signer_seam: 48 bytes (112 to 160)
      - seam_attributes: 8 bytes (160 to 168)
      - td_attributes: 8 bytes (168 to 176)
      - xfam: 8 bytes (176 to 184)
      - mr_td: 48 bytes (184 to 232)
      - mr_config_id: 48 bytes (232 to 280)
      - mr_owner: 48 bytes (280 to 328)
      - mr_config: 48 bytes (328 to 376)
      - rtmr0: 48 bytes (376 to 424)
      - rtmr1: 48 bytes (424 to 472)
      - rtmr2: 48 bytes (472 to 520)
      - rtmr3: 48 bytes (520 to 568)
      - report_data: 64 bytes (568 to 632)
    """
    offsets = {
        "mr_seam": (64, 112),
        "mr_signer_seam": (112, 160),
        "mr_td": (184, 232),
        "mr_config_id": (232, 280),
        "mr_owner": (280, 328),
        "mr_config": (328, 376),
        "rtmr0": (376, 424),
        "rtmr1": (424, 472),
        "rtmr2": (472, 520),
        "rtmr3": (520, 568),
    }
    image_filter = {}
    for key, (start, end) in offsets.items():
        image_filter[key] = list(quote_bytes[start:end])
    return image_filter


# Network and contract configuration
CHAIN_ID = "secretdev-1"
LCD_URL = "http://51.8.118.178:1317"
CONTRACT_ADDRESS = "secret15dllw6yf2tqjjcvl4j3xtj59pvdzaktqfm4dx7"

# Mnemonic key for the wallet
MNEMONIC = (
    "grant rice replace explain federal release fix clever romance raise often wild taxi quarter "
    "soccer fiber love must tape steak together observe swap guitar"
)

# Initialize LCD client and wallet
mk = MnemonicKey(mnemonic=MNEMONIC)
client = LCDClient(chain_id=CHAIN_ID, url=LCD_URL)
wallet = client.wallet(mk)

# Read quote and collateral from files
with open("quote_and_collateral/quote.txt", "r", encoding="utf-8") as f:
    quote_hex = f.read().strip()
with open("quote_and_collateral/collateral.txt", "r", encoding="utf-8") as f:
    collateral_hex = f.read().strip()

# Convert hex strings to integer arrays
quote = hex_to_int_array(quote_hex)
collateral = hex_to_int_array(collateral_hex)

# Convert quote to bytes for parsing
quote_bytes = bytearray(quote)

# Extract image filter from quote
image_filter = extract_image_filter_from_quote(quote_bytes)

# Build the execute message for add_secret_key_by_image
execute_msg = {
    "add_secret_key_by_image": {
        "image_filter": image_filter
    }
}

print("Sending execute message: add_secret_key_by_image")
try:
    tx_response = wallet.execute_tx(CONTRACT_ADDRESS, execute_msg)
    print("Execute tx sent. Tx hash:", tx_response.txhash)
    # Wait for transaction confirmation (adjust sleep time if needed)
    sleep(10)
    tx_info = client.tx.tx_info(tx_hash=tx_response.txhash)
    print("Transaction info:", tx_info)
except Exception as e:
    print("Error executing add_secret_key_by_image:", e)