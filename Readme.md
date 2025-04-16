# Key Management System (KMS) Contract

The **Key Management System (KMS) Contract** is a CosmWasm smart contract designed to securely manage cryptographic keys for different services and images. It provides a robust framework for the creation, storage, and controlled retrieval of secret keys via attestation-based validation.

---

## Overview

The contract consists of two main functional areas:

1. **Service Key Management**

    - **Create Service:**  
      An administrator can create a new service by providing a service name. When a service is created, a secret key is generated based on the blockchain’s randomness and the service identifier. The service’s data—including its admin, secret key, and allowed image filters—is stored in the contract.

    - **Image Filter Management for Services:**  
      Each service can have one or more image filters added, which define the allowed attestation parameters. An image filter is a set of fields (each an `Option<Vec<u8>>`) corresponding to specific parts of a TDX quote (for example, `mr_td`, `mr_seam`, etc.). Only the service admin can add or remove these image filters.

    - **Get Service Key:**  
      Clients can retrieve a service key by sending a TDX quote and collateral. The contract validates the attestation by parsing the quote and comparing its fields against the stored image filters. If at least one image filter fully matches the attestation, the service key is encrypted using an ephemeral key pair and returned (along with the ephemeral public key).

2. **Image Secret Key Management**

    - **Add Secret Key by Image:**  
      The global contract admin can add a secret key specifically tied to an image. This message uses an image filter (similar to the filters used for service key access) to identify the image. A hash is computed from the provided image filter, and a new secret key is stored (as a hex-encoded string) in a separate bucket if one does not already exist.

    - **Get Secret Key by Image:**  
      Clients can retrieve the stored image secret key by submitting an attestation (quote and collateral). The contract reconstructs an image filter from the quote and compares it against the stored secret key entries. If a match is found, the image secret key is encrypted and returned, along with the ephemeral public key used during encryption.

3. **Environment Secret Key Management**

    - **AddEnvByImage:**  
      This endpoint allows the global contract admin to add or update an environment secret key. The operation requires an image filter (`MsgImageFilter`) where the fields `mr_td`, `rtmr1`, `rtmr2`, and `rtmr3` must be provided. Along with the image filter, a plaintext string (`secrets_plaintext`) is supplied. The contract computes a hash for the provided image filter and searches for an existing environment secret with matching fields. If one exists, its plaintext is updated; otherwise, a new record is created and stored.

    - **GetEnvByImage:**  
      Clients can retrieve an environment secret key by providing a TDX quote and collateral. The contract validates the attestation, extracts the fields `mr_td`, `rtmr1`, `rtmr2`, and `rtmr3` from the quote, and then searches the stored list of environment secrets for a match. If a match is found, the associated plaintext is returned.

---

## Attestation Verification

The contract verifies a TDX quote using a dedicated function that packs the input data into memory regions and passes it to an external function for verification. In production, the function uses FFI calls and memory region handling. In test mode, however, conditional compilation ensures that the attestation verification function returns success immediately (i.e., returns `Ok(0)`), allowing tests to run successfully on native (64-bit) environments.

---

## Encryption Methodology

For both service keys and image/environment keys, the following procedure is used:

1. **Seed Calculation:**  
   A seed is computed as the SHA-256 hash over the concatenation of several values: the secret key, the TDX quote, the “other” public key (extracted from the quote’s `report_data`), and the current block height (converted to bytes).

2. **Ephemeral Key Generation:**  
   An ephemeral key pair is generated using the computed seed.

3. **Shared Secret and AES-SIV Encryption:**  
   A shared secret is computed via Diffie–Hellman between the ephemeral private key and the “other” public key. An AES key is derived from this shared secret using AES-SIV, and the secret (service, image, or environment) is encrypted with this AES key. The encrypted key (as a hex-encoded string) and the ephemeral public key (also hex-encoded) are returned.

---

## Message Types

- **ExecuteMsg:**
    - `CreateService { name: String }`
    - `AddImageToService { service_id: u64, image_filter: MsgImageFilter }`
    - `RemoveImageFromService { service_id: u64, image_filter: MsgImageFilter }`
    - `AddSecretKeyByImage { image_filter: MsgImageFilter }`
    - `AddEnvByImage { image_filter: MsgImageFilter, secrets_plaintext: String }`

- **QueryMsg:**
    - `GetService { id: u64 }`
    - `ListServices {}`
    - `GetSecretKey { service_id: u64, quote: Vec<u8>, collateral: Vec<u8> }`
    - `GetSecretKeyByImage { quote: Vec<u8>, collateral: Vec<u8> }`
    - `GetEnvByImage { quote: Vec<u8>, collateral: Vec<u8> }`

- **Response Types:**
    - `SecretKeyResponse` — Contains `encrypted_secret_key` and `encryption_pub_key`.
    - `EnvSecretResponse` — Contains the `secrets_plaintext`.

---

## State Management

- **Global State:**  
  Maintains the service counter and the global admin's address.

- **Services:**  
  A list of service records is stored, where each record includes the service name, secret key, admin, and an array of image filters.

- **Buckets:**
    - A bucket for image secret keys maps a hash (computed from an image filter) to a stored secret key (hex-encoded).
    - Environment secrets are stored as a vector of records (`EnvSecret`), where each record includes the fields `mr_td`, `rtmr1`, `rtmr2`, `rtmr3`, and the corresponding `secrets_plaintext`.

---

## Deployment and Migration

- **Instantiation:**  
  At instantiation, the contract initializes:
    - The global admin (set to the instantiator),
    - The service counter to zero,
    - An empty list for services,
    - An empty bucket for image secret keys, and
    - An empty vector for environment secrets.

- **Migration:**  
  The migration endpoint (`MigrateMsg::Migrate`) allows the contract admin to update the global admin if required.

---

## Usage Examples

### Service Key Management

1. **Creating a Service**

   **Request:**
   ```json
   {
     "create_service": {
       "name": "ExampleService"
     }
   }
   ```

   **Response:**
   ```json
   {
     "attributes": [
       { "key": "action", "value": "create_service" },
       { "key": "service_id", "value": "0" },
       { "key": "name", "value": "ExampleService" },
       { "key": "admin", "value": "<creator_address>" }
     ]
   }
   ```

2. **Adding an Image Filter to a Service**

   **Request:**
   ```json
   {
     "add_image_to_service": {
       "service_id": 0,
       "image_filter": {
         "mr_td": [10, 10, 10, ... 48 bytes total],
         "rtmr1": [20, 20, 20, ... 48 bytes total],
         "rtmr2": [30, 30, 30, ... 48 bytes total],
         "rtmr3": [40, 40, 40, ... 48 bytes total]
         // Other fields may be null
       }
     }
   }
   ```

3. **Retrieving a Service Key**

   A client submits a valid TDX quote and collateral. If the attestation matches one of the allowed image filters, the contract encrypts the service key and returns it along with an ephemeral public key.

### Image Secret Key Management

1. **Adding a Secret Key by Image**

   **Request:**
   ```json
   {
     "add_secret_key_by_image": {
       "image_filter": {
         "mr_td": [10, 10, 10, ... 48 bytes total],
         "rtmr1": [20, 20, 20, ... 48 bytes total],
         "rtmr2": [30, 30, 30, ... 48 bytes total],
         "rtmr3": [40, 40, 40, ... 48 bytes total]
          ... 
         // All fields should be provided
       }
     }
   }
   ```
   Only the global admin is allowed to call this operation.

2. **Retrieving a Secret Key by Image**

   A client submits an attestation (quote and collateral). If a matching secret key for that image exists, the contract encrypts it and returns the encrypted secret key along with the ephemeral public key.

### Environment Secret Key Management

1. **Adding an Environment Secret by Image**

   **Request:**
   ```json
   {
     "add_env_by_image": {
       "image_filter": {
         "mr_td": [10, 10, 10, ... 48 bytes total],
         "rtmr1": [20, 20, 20, ... 48 bytes total],
         "rtmr2": [30, 30, 30, ... 48 bytes total],
         "rtmr3": [40, 40, 40, ... 48 bytes total]
         // Other fields may be null
       },
       "secrets_plaintext": "environment_secret_value"
     }
   }
   ```
   This operation stores or updates the environment secret associated with the specified image filter. Only the global admin may execute this message.

2. **Retrieving an Environment Secret by Image**

   **Request:**
   ```json
   {
     "get_env_by_image": {
       "quote": [ ... array of bytes representing the TDX quote ... ],
       "collateral": [ ... array of bytes representing the collateral ... ]
     }
   }
   ```

   **Response:**
   ```json
   {
     "secrets_plaintext": "environment_secret_value"
   }
   ```

   The contract parses the attestation to extract the required fields (`mr_td`, `rtmr1`, `rtmr2`, and `rtmr3`) and searches the stored environment secrets for a match. If a matching record is found, the plaintext is returned.

---

## Testing

During tests, the contract bypasses the actual FFI-based attestation verification by conditionally compiling the function `dcap_quote_verify_internal` to simply return `Ok(0)`. This allows the tests to run successfully on 64-bit native systems. The test suite includes coverage for service creation, image filter management, key retrieval (both for service and image secret keys), and environment secret key management functionality.

---

## Security Considerations

- **Access Control:**
    - Only the service admin (creator) is allowed to add or remove image filters for a service.
    - Only the global contract admin (set at instantiation or updated during migration) can add image secret keys or environment secrets.

- **Attestation Verification:**  
  The contract validates attestation data before processing key operations, ensuring that only legitimate requests proceed.

- **Encryption Practices:**  
  Ephemeral key pairs are generated for each encryption operation using a seed derived from the secret and dynamic inputs like the quote and block height. This ensures that even if the underlying key remains unchanged, each encryption is unique.

- **State Isolation:**  
  Service keys, image secret keys, and environment secrets are maintained in separate state buckets or vectors, ensuring clear separation and simpler access control management.

---

## Conclusion

The **Key Management System Contract** provides a robust solution for managing cryptographic keys across various services and images. In addition to the existing functionality for creating services and managing image secret keys, the contract now offers environment secret key management. This allows the global admin to add or update an environment secret associated with an image filter and enables clients to retrieve these secrets by validating a TDX quote and collateral.

For further details, please review the source code and accompanying tests.

---