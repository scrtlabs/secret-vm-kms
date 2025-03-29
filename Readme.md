# Key Management System (KMS) Contract

The **Key Management System (KMS) Contract** is a CosmWasm smart contract designed to securely manage cryptographic keys for different "services" and provide access to these keys only to entities that present a valid attestation. In addition to storing keys for services, it supports a similar mechanism for images—allowing a secret key to be added and later retrieved by validating an image attestation.

## Overview

This contract has two main functional areas:

1. **Service Key Management:**
    - **Create Service:** A new service can be created by an administrator. When a service is created, a secret key is generated based on the blockchain’s randomness and the service identifier. This key is stored along with the service information. Only allowed attestation images (validated against registered image filters) are granted access to the service key.
    - **Add/Remove Image Filters for a Service:** Each service can have one or more “image filters” added. An image filter is a set of optional fields corresponding to specific parts of a Trusted Domain Extensions (TDX) quote (for example, measurement values such as `mr_td`, `mr_seam`, etc.). Only the service admin can add or remove these filters.
    - **Get Service Key:** When a client submits a TDX quote and collateral, the contract parses the attestation. If the attestation matches one of the allowed image filters for the service, the contract encrypts the service key using an ephemeral key pair and returns the encrypted key along with the ephemeral public key.

2. **Image Secret Key Management:**
    - **Add Secret Key By Image:** Separate from service key management, the contract allows the global contract admin (set at instantiation or updated via migration) to add a secret key specific to an image. The image is identified by its image filter (the same structure used for attestation validation). This key is stored in a separate bucket (a key-value mapping) indexed by a hash of the image filter.
    - **Get Secret Key By Image:** A client can submit a TDX quote and collateral; the contract will reassemble an image filter from the quote and use it to look up the stored secret key. If the key has been added earlier, it is encrypted (using the same ephemeral key mechanism) and returned along with the public key used during encryption. If no secret key exists for that image, an error is returned.

## Key Concepts

- **Service:** A logical grouping for which a secret key is maintained. Only the service admin (creator) can configure allowed image filters for the service.
- **Image Filter:** A structure matching several fields of a TDX quote (e.g., measurements). An image filter defines which attestation parameters are permitted to access the corresponding key.
- **Attestation Verification:** The contract uses a function to “parse” the provided TDX quote and collateral. It verifies that the quote is valid (e.g., has the expected version and TEE type). Only valid attestations are processed.
- **Encryption Process:**
    - Before encrypting a key, a seed is computed as a SHA-256 hash of the secret key, the quote (or other image data), the “other” public key (extracted from the quote’s report data), and a height value (e.g., the block height).
    - This seed is then used to generate an ephemeral key pair.
    - A Diffie–Hellman shared secret is derived from the ephemeral private key and the “other” public key, which is used to build an AES key (using AES-SIV mode).
    - The secret key is then encrypted with the AES key and returned as a hex string along with the ephemeral public key (also hex-encoded).

## Contract Structure

- **Contract Functions (in `contract.rs`):**
    - `instantiate`: Sets up the initial global state with service count zero and assigns the instantiator as the global admin.
    - `migrate`: Allows an admin (or during migration) to update the global admin.
    - `execute`: Dispatches execution messages, which include:
        - `CreateService`: Create a new service with a generated secret key.
        - `AddImageToService` / `RemoveImageFromService`: Add or remove allowed image filters for a service.
        - `AddSecretKeyByImage`: For an image (as defined by an image filter), add a new secret key if one has not yet been stored.
    - `query`: Provides query endpoints:
        - `GetService` and `ListServices`: Retrieve service details.
        - `GetSecretKey`: Given a service ID and attestation (quote and collateral), encrypt and return the service’s secret key if the attestation is valid.
        - `GetSecretKeyByImage`: Given an attestation, look up the pre-stored image secret key and return it encrypted.

- **Messages (in `msg.rs`):**
    - Define the request and response formats (e.g., `ExecuteMsg`, `QueryMsg`, `SecretKeyResponse`, etc.).
    - The new messages `AddSecretKeyByImage` and `GetSecretKeyByImage` handle the image-based secret key functionality.

- **State (in `state.rs`):**
    - Uses CosmWasm storage helpers to manage a singleton for global state and a list for services.
    - A separate bucket is used for image secret keys, mapping an image hash to the secret key (stored as a hex string).

## Security Considerations

- **Access Control:**
    - Only the service admin (creator of the service) can add or remove image filters.
    - Only the global contract admin (set at instantiation or updated via migration) can add a secret key for an image.
- **Attestation Verification:**
    - The contract validates attestation quotes (TDX quotes) by checking critical fields such as version and TEE type.
    - Only quotes that pass verification are used to derive keys.
- **Ephemeral Key Generation:**
    - For each encryption, an ephemeral key pair is generated using a seed derived from a combination of the secret key, attestation data, and block height.
    - This mechanism ensures that each encryption operation uses a unique key, even if the underlying service key remains the same.
- **Storage Separation:**
    - Service keys and image secret keys are stored in separate storage buckets to help isolate access.

## Usage Examples

1. **Creating a Service:**  
   A user (the service admin) sends an `ExecuteMsg::CreateService` message with a chosen service name. The contract generates a secret key and stores it along with the service details.

2. **Adding an Image Filter to a Service:**  
   The service admin can add allowed attestation parameters (image filter) via `ExecuteMsg::AddImageToService`. This filter defines which attested images can access the service key.

3. **Adding a Secret Key by Image:**  
   The global admin can call `ExecuteMsg::AddSecretKeyByImage` with an image filter. The contract will compute a hash of the image filter and store a new secret key for that image if it does not already exist.

4. **Retrieving a Secret Key (by Service):**  
   A client can query `QueryMsg::GetSecretKey` by providing the service ID, along with a TDX quote and collateral. If the attestation matches one of the allowed image filters, the contract encrypts the service secret key and returns it along with an ephemeral public key.

5. **Retrieving a Secret Key (by Image):**  
   A client can query `QueryMsg::GetSecretKeyByImage` by providing a TDX quote and collateral. The contract reconstructs an image filter from the attestation, looks up the corresponding secret key (if it was added earlier via `AddSecretKeyByImage`), encrypts it, and returns it with the corresponding ephemeral public key.

## Deployment and Migration

- **Instantiation:**  
  When the contract is first instantiated, it sets the global admin to the sender.  
  Example instantiation message (empty object):

  ```json
  {}
  ```

- **Migration:**  
  The migration message (`MigrateMsg::Migrate`) now accepts an `admin` field. When a migration is performed, the global admin is updated to the provided address.

  Example migration message:

  ```json
  {
    "migrate": {
      "admin": "new_admin_address"
    }
  }
  ```

## Conclusion

The **Key Management System Contract** provides a robust framework for managing secret keys for services and images using attestation verification. It enforces strict access control, uses ephemeral key pairs for secure encryption, and separates storage for service keys and image-based secret keys. This ensures that only authorized parties, as verified through valid TDX quotes, can retrieve the sensitive keys.

For further details on how to integrate and interact with the contract, refer to the code examples provided in the tests and the comments within the source files.
