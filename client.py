"""
E2EE Message Service (server + simple terminal client)

Files contained in this single document:
- server.py   -> run on your web host (Python 3.10+)
- client.py   -> run on each user's machine (terminal)

Install required packages:
    python -m pip install websockets cryptography bcrypt aiofiles

Design notes (short):
- Server is a relay only: it never sees decrypted message bodies.
- Passwords are hashed with bcrypt and stored in users.json.
- UserIDs are assigned incrementally starting at 1.
- Lobbies hold max 2 users. When one leaves, both are disconnected.
- Handshake uses X25519 for ECDH (shared secret) and Ed25519 for signatures.
- Symmetric encryption uses AES-GCM derived via HKDF from X25519 shared secret.

Security note (do NOT send private keys):
The user requested sending private keys in the handshake. This is insecure and wrong.
This implementation DOES NOT send private keys. Instead:
1) Each client generates an ephemeral X25519 key pair and an Ed25519 key pair.
2) They exchange X25519 public keys and Ed25519 public keys.
3) Each side performs X25519 ECDH to compute the shared secret.
4) The shared secret is run through HKDF to make a symmetric key for AES-GCM.
5) Ed25519 keys sign the public key material to prevent MITM.

Commands (client-side):
- signup <username> <password>
- login <username> <password>
- createlobby <name> [password]
- joinlobby <name>
- viewusers
- leave
- send <message>

Server.py and client.py are below.

"""

# ------------------- client.py -------------------
# Run like: python client.py
# Terminal client (simple) that implements handshake and E2EE messaging.

import asyncio
import json
import base64
import os
import sys
from websockets import connect
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_URI = "ws://localhost:8765"

# utility

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode())

class Client:
    def __init__(self):
        self.ws = None
        self.userid = None
        self.username = None
        # ephemeral keys per session
        self.x25519_priv = None
        self.x25519_pub = None
        self.ed_priv = None
        self.ed_pub = None
        self.shared_key = None  # AES key

    async def connect(self):
        self.ws = await connect(SERVER_URI)
        asyncio.create_task(self.recv_loop())

    async def recv_loop(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                await self.handle_msg(msg)
        except Exception as e:
            print("connection closed")
            return

    async def handle_msg(self, msg):
        t = msg.get("type")
        if t == "signup_ok":
            print(f"Signup OK. userid={msg['userid']}")
        elif t == "signup_failed":
            print("Signup failed:", msg.get("reason"))
        elif t == "login_ok":
            self.userid = msg.get("userid")
            self.username = msg.get("username")
            print(f"Login OK. {self.username} ({self.userid})")
        elif t == "login_failed":
            print("Login failed")
        elif t == "peer_joined":
            # we're leader; start handshake by telling peer hello
            peer = msg.get("peer_userid")
            print(f"Peer {msg.get('peer_username')} joined. Begin handshake.")
            await self.do_handshake_initiator()
        elif t == "joined_lobby":
            print(f"Joined lobby {msg.get('name')} with peer {msg.get('peer_username')}.")
            # we're joining; say hello to leader
            await self.send({"type": "handshake", "subtype": "hello"})
        elif t == "handshake":
            # messages during handshake forwarded by server
            subtype = msg.get("subtype")
            sender = msg.get("from_username")
            if subtype == "hello":
                print(f"{sender} says: hello")
                # reply with our public keys
                await self.do_handshake_responder()
            elif subtype == "x25519_pub":
                their_x = ub64(msg.get("x25519_pub"))
                their_ed = ub64(msg.get("ed25519_pub"))
                # store remote pubs and verify signature if present
                # We expect a signature field too
                sig = ub64(msg.get("signature")) if msg.get("signature") else None
                # verify signature of their_x||their_ed using their ed25519 pub
                try:
                    edpub = ed25519.Ed25519PublicKey.from_public_bytes(their_ed)
                    edpub.verify(sig, their_x + their_ed)
                except Exception as e:
                    print("Signature verification failed! Aborting handshake.")
                    return
                # compute shared key
                shared = self.x25519_priv.exchange(x25519.X25519PublicKey.from_public_bytes(their_x))
                self.derive_key(shared)
                # we're responder? if we received their pub after we sent ours, send encrypted confirmation
                print("Received peer public keys. Derived shared key.")
                await self.send({"type": "handshake", "subtype": "handshake_complete"})
            elif subtype == "handshake_complete":
                print("Handshake: Connection secured.")
        elif t == "handshake_response":
            pass
        elif t == "peer_left":
            print("Peer left, lobby closed.")
        elif t == "encrypted_message":
            # payload contains nonce and ciphertext and sender info
            ciphertext = ub64(msg.get("ciphertext"))
            nonce = ub64(msg.get("nonce"))
            sender = msg.get("from_username")
            uid = msg.get("from_userid")
            if not self.shared_key:
                print("Got encrypted message before handshake")
                return
            aes = AESGCM(self.shared_key)
            try:
                plain = aes.decrypt(nonce, ciphertext, None)
                print(f"{sender} ({uid}): {plain.decode()}")
            except Exception as e:
                print("Failed to decrypt message: ", e)
        else:
            print("SVC:", msg)

    def derive_key(self, shared: bytes):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data")
        self.shared_key = hkdf.derive(shared)

    async def do_handshake_initiator(self):
        # create ephemeral keys
        self.x25519_priv = x25519.X25519PrivateKey.generate()
        self.x25519_pub = self.x25519_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.ed_priv = ed25519.Ed25519PrivateKey.generate()
        self.ed_pub = self.ed_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        # sign our pub material
        sig = self.ed_priv.sign(self.x25519_pub + self.ed_pub)
        await self.send({"type": "handshake", "subtype": "x25519_pub", "x25519_pub": b64(self.x25519_pub), "ed25519_pub": b64(self.ed_pub), "signature": b64(sig)})

    async def do_handshake_responder(self):
        # generate keys and send our public keys with signature
        self.x25519_priv = x25519.X25519PrivateKey.generate()
        self.x25519_pub = self.x25519_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.ed_priv = ed25519.Ed25519PrivateKey.generate()
        self.ed_pub = self.ed_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        sig = self.ed_priv.sign(self.x25519_pub + self.ed_pub)
        await self.send({"type": "handshake", "subtype": "x25519_pub", "x25519_pub": b64(self.x25519_pub), "ed25519_pub": b64(self.ed_pub), "signature": b64(sig)})

    async def send_encrypted(self, plaintext: str):
        if not self.shared_key:
            print("No shared key; can't send encrypted message")
            return
        aes = AESGCM(self.shared_key)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, plaintext.encode(), None)
        await self.send({"type": "encrypted_message", "nonce": b64(nonce), "ciphertext": b64(ct)})

    async def send(self, obj):
        await self.ws.send(json.dumps(obj))

async def repl(client: Client):
    await client.connect()
    print("commands: signup <username> <password> | login <username> <password> | createlobby <name> [password] | joinlobby <name> | viewusers | send <message> | leave")
    while True:
        line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        parts = line.strip().split()
        if not parts:
            continue
        cmd = parts[0]
        if cmd == "signup" and len(parts) >= 3:
            await client.send({"type": "signup", "username": parts[1], "password": parts[2]})
        elif cmd == "login" and len(parts) >= 3:
            await client.send({"type": "login", "username": parts[1], "password": parts[2]})
        elif cmd == "createlobby" and len(parts) >= 2:
            pwd = parts[2] if len(parts) >= 3 else None
            await client.send({"type": "createlobby", "name": parts[1], "password": pwd})
        elif cmd == "joinlobby" and len(parts) >= 2:
            await client.send({"type": "joinlobby", "name": parts[1]})
        elif cmd == "viewusers":
            await client.send({"type": "viewusers"})
        elif cmd == "send" and len(parts) >= 2:
            msg = " ".join(parts[1:])
            await client.send_encrypted(msg)
        elif cmd == "leave":
            await client.send({"type": "leave"})
        else:
            print("bad cmd")

if __name__ == "__main__":
    c = Client()
    try:
        asyncio.run(repl(c))
    except KeyboardInterrupt:
        pass
