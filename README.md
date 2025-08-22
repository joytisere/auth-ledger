# AUTH-LEDGER Smart Contract

A Stacks blockchain smart contract for managing Decentralized Identifiers (DIDs) and Verifiable Credential references.

## Features

- **DID Registry**
  - Document URI storage
  - Lifecycle management (register, update, deactivate)
  - One DID per principal

- **Credential Reference Registry**
  - On-chain references to off-chain Verifiable Credentials
  - Revocation support with reason tracking
  - Credential counter for unique IDs

- **Access Control**
  - Owner-controlled administrative functions
  - Issuer allow-list for authorized credential issuers
  - Subject/issuer-only credential revocation

- **Safety Features**
  - Pausable functionality for emergency stops
  - Comprehensive error handling
  - Event logging for key operations

## Function Overview

### Administrative Functions
- `set-owner`: Transfer contract ownership
- `set-paused`: Pause/unpause contract operations
- `add-issuer`: Add authorized credential issuer
- `remove-issuer`: Remove issuer authorization

### DID Operations
- `register-did`: Register new DID with document URI
- `update-did`: Update DID document URI
- `deactivate-did`: Deactivate existing DID
- `get-did`: Query DID information

### Credential Operations
- `issue-credential`: Issue new credential reference
- `revoke-credential`: Revoke existing credential
- `get-credential`: Query credential information

## Error Codes

```
ERR-UNAUTHORIZED (u100): Access control violation
ERR-PAUSED (u101): Contract is paused
ERR-DID-EXISTS (u110): DID already registered
ERR-DID-MISSING (u111): DID not found
ERR-NOT-ISSUER (u120): Unauthorized issuer
ERR-CRED-MISSING (u130): Credential not found
ERR-ALREADY-REVOKED (u131): Credential already revoked
```

## Usage

Deploy this contract to the Stacks blockchain and interact with it using the Clarity console or through API calls.

