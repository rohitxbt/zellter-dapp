# Zeltter

A decentralized dead man's switch application for secure secret inheritance.

## What is Zeltter

Zeltter is a vault system built on Ethereum that lets you store encrypted secrets (private keys, passwords, or files) and pass them to a beneficiary if you become inactive. The system uses a heartbeat timer that you must reset periodically. If the timer runs out and you do not ping, the vault unlocks and your beneficiary can claim the secret.

## How It Works

<img width="1327" height="896" alt="image" src="https://github.com/user-attachments/assets/afd9ac94-21c7-4374-9329-25c1f4b86df3" />

<img width="1230" height="897" alt="Screenshot 2026-01-01 105825" src="https://github.com/user-attachments/assets/41cacbad-8385-4407-b7d6-0796a07b2fcd" />

<img width="1286" height="857" alt="Screenshot 2026-01-01 105857" src="https://github.com/user-attachments/assets/87b7e67e-ba27-4e3b-a74f-b13165d938c2" />


### Core Concept

1. You connect your wallet and create a vault
2. You store your secret (text or file) with encryption
3. You set a beneficiary address who will receive the secret
4. You set a heartbeat timer (for example, 30 days)
5. You must ping the vault before the timer expires to prove you are still active
6. If the timer expires without a ping, the beneficiary can claim and view the secret

### Storage Methods

Zeltter offers two storage modes for your secrets:

---

## On-Chain FHE Method

This method stores your encrypted secret directly on the blockchain using Fully Homomorphic Encryption (FHE) provided by the ZAMA FHEVM.

### How On-Chain FHE Works

1. **Secret Preparation**: Your secret text is converted to bytes and then to a large number (BigInt)

2. **FHE Encryption**: The ZAMA SDK encrypts this number using homomorphic encryption. This creates:
   - An encrypted handle (a reference to the ciphertext stored on the FHEVM coprocessor)
   - A proof that the encryption was done correctly

3. **Blockchain Storage**: The encrypted handle and proof are sent to the smart contract along with your vault settings (heartbeat duration, beneficiary address)

4. **Decryption Process**: When the beneficiary claims a vault after the timer expires:
   - They generate a keypair for decryption
   - They sign an EIP-712 message to authorize the decryption request
   - The ZAMA relayer performs the decryption using their signature
   - The decrypted secret is returned to the beneficiary

### Advantages

- Everything is on-chain, no external storage needed
- Cryptographic proofs ensure data integrity
- Uses military grade FHE encryption from ZAMA

### Limitations

- Limited payload size (only short text or numbers up to 256 bits)
- Higher gas costs for storing encrypted data on-chain
- Decryption requires interaction with the ZAMA relayer

---

## Off-Chain IPFS Method

This method stores the encrypted payload on IPFS while keeping only the encryption key on-chain using FHE.

### How Off-Chain IPFS Works

1. **Key Generation**: A random AES-256 encryption key is generated in your browser using the Web Crypto API

2. **Content Encryption**: Your file or text is encrypted locally using AES-GCM:
   - A random 12-byte initialization vector (IV) is generated
   - The content is encrypted with the AES key
   - The encrypted blob and IV are prepared for upload

3. **Key Protection with FHE**: The AES key is converted to a number and encrypted using ZAMA FHE:
   - This creates an encrypted handle stored on-chain
   - The actual AES key never touches the blockchain in plain form

4. **IPFS Upload**: A JSON package is uploaded to IPFS via Pinata containing:
   - The IV (needed for AES decryption)
   - The encrypted data (base64 encoded)
   - The file type and name
   - The FHE encrypted key handle (as reference)

5. **Smart Contract Storage**: The contract stores:
   - The IPFS CID (content identifier) pointing to the encrypted package
   - The FHE encrypted key handle

6. **Decryption Process**: When the beneficiary claims:
   - They fetch the encrypted package from IPFS using the CID
   - They decrypt the AES key using the FHE process (same as on-chain method)
   - They use the decrypted AES key with the IV to decrypt the actual content
   - For files, the decrypted file is downloaded; for text, it is displayed

### Advantages

- Can store large files (IPFS has no practical size limit)
- Lower gas costs since only the key and CID go on-chain
- Encrypted content is distributed across IPFS network

### Limitations

- Depends on IPFS availability (uses multiple gateways as fallback)
- Requires Pinata for pinning (files could become unavailable if not pinned)
- Two-step decryption process

---

## Vault Lifecycle

### Creating a Vault

1. Connect wallet (Privy handles authentication)
2. Choose storage mode (On-Chain FHE or Off-Chain IPFS)
3. Choose payload type (Text or File)
4. Enter your secret content
5. Set the heartbeat timer duration
6. Enter the beneficiary wallet address
7. Optionally add a vault name
8. Click Lock Vault to create

### Maintaining a Vault

- View your vaults in the My Vaults section
- Each vault shows the time remaining before it expires
- Click Ping to reset the timer and prove you are active
- If the status shows Breached, the timer has expired

### Claiming a Vault

1. Go to the Claim section
2. Vaults where you are the beneficiary appear here
3. If a vault shows Unlocked (timer expired and not pinged), you can claim it
4. Click Claim to unlock the vault
5. Click View to decrypt and see the secret

---

## Security Model

- Your secret is never stored in plain text on any server
- AES-256 encryption happens locally in your browser
- FHE encryption ensures even blockchain validators cannot read your data
- Only the designated beneficiary can decrypt after the timer expires
- The owner can always ping to reset the timer and prevent access

## Technical Stack

- Frontend: React with TypeScript
- Blockchain: Ethereum Sepolia testnet
- FHE: ZAMA FHEVM Relayer SDK
- Wallet: Privy authentication
- Storage: IPFS via Pinata
- Encryption: Web Crypto API for AES-GCM

## Smart Contract

The Zeltter smart contract handles:
- Vault creation with encrypted payloads
- Heartbeat tracking and ping functionality
- Beneficiary management
- Claim verification (checks timer expiration)
- Vault name storage

Contract Address: 0x57af6d9aa18bA14b58568C480fbBE87eaFAf26Ac (Sepolia)


