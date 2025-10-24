# Seal Chat - End-to-End Encrypted Messaging Client

Seal Chat is an open source Python-based, end-to-end encrypted (E2EE) chat client that allows secure messaging between peers in a lobby system. It implements X25519 key exchange, Ed25519 signatures, and AES-GCM encryption for secure communication. Additionally, it uses Trust On First Use (TOFU) persistent key pinning to prevent man-in-the-middle (MITM) attacks by a malicious server.

---

## Features

- Secure key exchange using ephemeral X25519 keys.
- Authenticated handshakes with Ed25519 signatures.
- Persistent Ed25519 keys for identity verification.
- TOFU persistent key pinning:
  - Stores peer public keys on first contact.
  - Warns if a peer's persistent key changes (MITM detection).
- AES-GCM encryption for all messages.
- HMAC verification for defense in depth.
- Replay protection with nonces and timestamps.
- Console fingerprint display for out-of-band verification.
- Multi-peer lobby support via Socket.IO.

---

## Installation

1. **Clone the repository**:

```bash
git clone https://github.com/yourusername/sealchat.git
cd sealchat
```

2. **Install dependencies**:

```bash
pip install -r requirements.txt
```

**Required Python packages:**

- `requests`
- `python-socketio[client]`
- `cryptography`

---

## Usage

Run the client:

```bash
python client.py
```

You will see:

```
Seal Chat E2EE messaging service
Type "help" to see available commands
>
```

### Commands

| Command | Description |
|---------|-------------|
| `signup` | Create a new user account. |
| `login` | Login to an existing account. |
| `createlobby <name> [password]` | Create a new lobby. |
| `joinlobby <name> [password]` | Join an existing lobby. |
| `send <message>` | Send a secure message to the connected peer. |
| `leave` | Leave the current lobby. |
| `clear` | Clears session data locally. |
| `help` | Show all commands. |

---

## Security Features

### 1. End-to-End Encryption

- X25519 ephemeral key exchange establishes a shared AES key.
- AES-GCM encrypts messages with integrity checks.
- HMAC is used for additional verification.

### 2. Authenticated Handshake

- Each handshake is signed with Ed25519:
  - Persistent keys identify users across sessions.
  - Ephemeral keys protect each session from key reuse attacks.
  
- Handshake signature is hardened using canonical JSON, preventing subtle MITM attacks from reordering or formatting changes.

### 3. TOFU Persistent Key Pinning

- Stores the peer's persistent Ed25519 key locally on first contact.
- Compares received persistent keys in subsequent connections.
- Alerts the user if a key changes, indicating possible MITM.
- Displays a peer fingerprint (SHA256, 16 chars) for optional out-of-band verification.

### 4. Replay Protection

- Uses nonces and timestamps to prevent replay attacks.
- Rejects messages outside a 60-second window.

---

## Directory Structure

```
~/.sealchat/
├── <username>/ed25519_priv.key      # Persistent Ed25519 private key
├── pinned_peers/                     # TOFU pinned peer keys
│   └── <peer_username>_ed25519_pub.key
```

---

## Notes

- The server must include the peer's `persistent_ed25519_pub` in `peer-joined` events for TOFU and fingerprint display to work correctly.
- Currently supports **one active peer per lobby**. For multiple peers, you may need per-peer session state.
- Fingerprints are displayed in console and can be verified out-of-band (e.g., manually or via QR code).

---

## Example Workflow

1. Signup/Login
2. Create or join a lobby
3. Peer joins lobby → TOFU fingerprint displayed
4. Handshake completes → AES key established
5. Send/receive encrypted messages
6. Leave lobby when done

---

## License

MIT License

Copyright (c) 2025 Phobia

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


---

## Contact

Developed by Phobia 
For questions or contributions, open an issue or PR on GitHub.
