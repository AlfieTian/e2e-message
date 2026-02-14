# E2E Message

A command-line end-to-end encryption tool. Two parties establish a secure channel by exchanging public keys, using ECDH key exchange and AES-256-GCM encryption with forward secrecy.

[中文文档](README_zh.md)

## Installation

### Download from Release

Go to [GitHub Releases](https://github.com/AlfieTian/e2e-message/releases) to download prebuilt binaries for your platform. Supports Linux, macOS, and Windows on multiple architectures.

### Build from Source

Requires Go 1.21 or later.

```bash
git clone git@github.com:AlfieTian/e2e-message.git
cd e2e-message
go build -o e2e-message
```

## Quick Start

### 1. Launch the Program

Both parties start the program:

```
./e2e-message
```

On startup, your public key is displayed:

```
=== E2E Message - End-to-End Encryption Tool ===

Your public key (share this with your peer):
BPx7kG... (Base64-encoded public key)
```

### 2. Exchange Public Keys

Share your public key with the other party through any channel (chat, email, etc.).

### 3. Import Peer's Public Key

Use the `key` command to import the other party's public key:

```
> key BQx8mH... (peer's public key)
Peer public key imported successfully!
Secure channel established. You can now encrypt and decrypt messages.

=== Security Verification ===
Verify these words match on both sides to ensure no MITM attack:
  apple - dragon - forest - mirror - ocean
```

Both parties must confirm that the verification words are identical to rule out a man-in-the-middle attack.

### 4. Send an Encrypted Message

Use the `e` command to encrypt a message:

```
> e Hello, this is a secret message
0 SGVsbG8gV29ybGQ... (encrypted ciphertext)
```

Send the entire output line (number and ciphertext) to the other party.

### 5. Receive and Decrypt a Message

Paste the received ciphertext directly to auto-decrypt:

```
> 0 SGVsbG8gV29ybGQ...
Hello, this is a secret message
```

You can also use the `d` command to decrypt explicitly:

```
> d 0 SGVsbG8gV29ybGQ...
```

## Command Reference

| Command | Description |
|---------|-------------|
| `key <public-key>` | Import peer's public key and establish a secure channel |
| `e <plaintext>` | Encrypt a message |
| `d <number> <ciphertext>` | Decrypt a message |
| `<number> <ciphertext>` | Auto-decrypt (triggered when input starts with a number) |
| `status` | Show session status, message counts, and verification words |
| `help` | Display help information |
| `quit` / `exit` / `q` | Exit the program |

## Usage Details

### Prompt

The prompt displays the most recently received message number:

```
[#3] >
```

This indicates that the last decrypted message had sequence number 3.

### Message Format

Encrypted output follows the format `number ciphertext`, for example:

```
0 base64encodedciphertext...
1 anotherbase64ciphertext...
2 yetanotherbase64ciphertext...
```

Sequence numbers start from 0 and increment. Both the number and ciphertext are required for decryption.

### Forward Secrecy

Each message is encrypted with an independent key. Even if one message key is compromised, other messages remain secure. The tool supports out-of-order message delivery, tolerating up to 100 skipped messages.

### Verification Words

After establishing a secure channel, both parties will see 5 verification words. Confirm via a trusted channel (phone call, in person, etc.) that both sides see the same words. If they differ, the communication may be under a man-in-the-middle attack -- terminate the session immediately.

### Shortcuts

- Use up/down arrow keys to browse command history
- Press Ctrl+C twice to force quit

## Typical Workflow

```
Alice                                    Bob
─────                                    ───
Start program, get public key A          Start program, get public key B
        ──── public key A ────>
        <──── public key B ────
key <keyB>                               key <keyA>
Confirm verification words match         Confirm verification words match
e Hello
        ──── 0 ciphertext ────>
                                         Paste "0 ciphertext" to decrypt
                                         e Got it
        <──── 0 ciphertext ────
Paste "0 ciphertext" to decrypt
```

## Technical Details

- Key exchange: ECDH (P-256)
- Symmetric encryption: AES-256-GCM
- Key derivation: HKDF-SHA256
- Forward secrecy: HKDF-based ratchet mechanism
- Verification words: Derived from SHA256 hash of the shared key

## Running Tests

```bash
go test -v
```

## License

GNU General Public License v3.0
