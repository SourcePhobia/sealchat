# client_secure.py
import requests
import socketio
import threading
import base64
import json
import sys
import getpass
import os
import time
import hmac
import hashlib

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# ------------------ CONFIG ------------------
SERVER_HTTP = 'https://sealchatserver.onrender.com/'
SERVER_WS = 'https://sealchatserver.onrender.com/'  # socket.io

# ------------------ CLIENT STATE ------------------
sio = socketio.Client(logger=False, engineio_logger=False)
USER = None  # dict with userid, username
CURRENT_LOBBY = None
PEER_INFO = None  # dict with userid, username

# Handshake ephemeral keys
x_priv = None
x_pub_b64 = None
sign_priv_ephemeral = None
sign_pub_ephemeral_b64 = None

# Persistent identity key
sign_priv_persistent = None
sign_pub_persistent_b64 = None
PERSISTENT_KEY_FILE = os.path.expanduser("~/.sealchat/ed25519_priv.key")

# Shared session AES
shared_key = None
aesgcm = None

# Nonce tracking for replay protection
received_nonces = set()

# ------------------ UTILITIES ------------------
def jsonb64(b: bytes):
    return base64.b64encode(b).decode('ascii')

def b64json(s):
    return base64.b64decode(s.encode('ascii'))



def load_or_create_persistent_key():
    global persistent_sign_priv, persistent_sign_pub_b64
    folder = os.path.dirname(PERSISTENT_KEY_FILE)
    os.makedirs(folder, exist_ok=True)  # <-- create folder if missing

    if os.path.exists(PERSISTENT_KEY_FILE):
        with open(PERSISTENT_KEY_FILE, "rb") as f:
            persistent_sign_priv = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
    else:
        persistent_sign_priv = ed25519.Ed25519PrivateKey.generate()
        with open(PERSISTENT_KEY_FILE, "wb") as f:
            f.write(persistent_sign_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(PERSISTENT_KEY_FILE, 0o600)

    persistent_sign_pub_b64 = base64.b64encode(
        persistent_sign_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    ).decode('ascii')


load_or_create_persistent_key()

def gen_ephemeral_keys():
    global x_priv, x_pub_b64, sign_priv_ephemeral, sign_pub_ephemeral_b64
    x_priv = x25519.X25519PrivateKey.generate()
    x_pub_b64 = jsonb64(x_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))
    sign_priv_ephemeral = ed25519.Ed25519PrivateKey.generate()
    sign_pub_ephemeral_b64 = jsonb64(sign_priv_ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

def hkdf_shared_key(their_x_pub_b64):
    global shared_key, aesgcm
    their_pub = x25519.X25519PublicKey.from_public_bytes(b64json(their_x_pub_b64))
    shared = x_priv.exchange(their_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared)
    shared_key = key
    aesgcm = AESGCM(shared_key)
    return key

def sign_handshake(pub_x, pub_sign, nonce, ts):
    msg = (pub_x + pub_sign + nonce + str(ts) + sign_pub_persistent_b64).encode()
    return jsonb64(sign_priv_persistent.sign(msg))

def verify_handshake_signature(peer_persistent_pub_b64, pub_x, pub_sign, nonce, ts, signature_b64):
    peer_pub = ed25519.Ed25519PublicKey.from_public_bytes(b64json(peer_persistent_pub_b64))
    msg = (pub_x + pub_sign + nonce + str(ts) + peer_persistent_pub_b64).encode()
    try:
        peer_pub.verify(b64json(signature_b64), msg)
        return True
    except InvalidSignature:
        return False

def encrypt_message(content):
    global aesgcm
    if not isinstance(content, str):
        content = str(content)  # coerce to string
    payload = {
        "sender": USER['userid'],
        "username": USER['username'],
        "lobby": CURRENT_LOBBY,
        "timestamp": int(time.time()),
        "message": content
    }
    data = json.dumps(payload).encode()
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, data, None)
    # HMAC for defense in depth
    mac = hmac.new(shared_key, ciphertext, hashlib.sha256).digest()
    return {
        "ciphertext": jsonb64(ciphertext),
        "iv": jsonb64(iv),
        "hmac": jsonb64(mac)
    }

def decrypt_message(msg):
    global aesgcm
    ciphertext = b64json(msg['ciphertext'])
    iv = b64json(msg['iv'])
    mac = b64json(msg['hmac'])
    # verify HMAC
    expected_mac = hmac.new(shared_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed")
    data = aesgcm.decrypt(iv, ciphertext, None)
    obj = json.loads(data)
    # enforce string type for critical fields
    for key in ['sender', 'username', 'lobby', 'timestamp', 'message']:
        if key in obj:
            obj[key] = str(obj[key])
    return obj

# ------------------ AUTH / LOBBY ------------------
def signup():
    username = input("username: ").strip()
    password = getpass.getpass("password: ")
    load_or_create_persistent_key()  # make sure key exists
    payload = {
        "username": username,
        "password": password,
        "persistent_ed25519_pub": persistent_sign_pub_b64
    }
    r = requests.post(SERVER_HTTP + '/signup', json=payload)
    print(r.text if r.status_code != 200 else "Signed up successfully")

def login():
    global USER
    username = input("username: ").strip()
    password = getpass.getpass("password: ")
    load_or_create_persistent_key()  # ensure persistent key exists
    payload = {
        "username": username,
        "password": password,
        "persistent_ed25519_pub": persistent_sign_pub_b64
    }
    r = requests.post(SERVER_HTTP + '/login', json=payload)
    if r.status_code == 200:
        USER = r.json()
        print("Logged in as", USER)
        sio.connect(SERVER_WS)  # connect after login
        return True
    print("Login failed:", r.text)
    return False


# ------------------ SOCKET.IO EVENTS ------------------
@sio.event
def connect():
    print("[Socket] Connected")
    if USER:
        sio.emit('register', {'userid': USER['userid'], 'username': USER['username']})

@sio.on('peer-joined')
def on_peer_joined(data):
    global PEER_INFO
    PEER_INFO = data['peer']
    print(f"[System] Peer {PEER_INFO['username']} joined. Starting handshake.")
    gen_ephemeral_keys()
    nonce = base64.b64encode(os.urandom(8)).decode()
    ts = int(time.time())
    payload = {
        'lobby': CURRENT_LOBBY,
        'toUserId': PEER_INFO['userid'],
        'type': 'hello',
        'data': {
            'x25519_pub': x_pub_b64,
            'ed25519_ephemeral_pub': sign_pub_ephemeral_b64,
            'persistent_ed25519_pub': sign_pub_persistent_b64,
            'nonce': nonce,
            'timestamp': ts,
            'signature': sign_handshake(x_pub_b64, sign_pub_ephemeral_b64, nonce, ts)
        }
    }
    sio.emit('signal', payload)

@sio.on('signal')
def on_signal(msg):
    global shared_key, aesgcm
    sender = msg.get('from')
    t = msg.get('type')
    d = msg.get('data', {})
    if t in ('hello', 'leader-pubkeys', 'joiner-pubkeys'):
        # Verify signature
        if not verify_handshake_signature(
            d['persistent_ed25519_pub'],
            d['x25519_pub'],
            d['ed25519_ephemeral_pub'],
            d['nonce'],
            d['timestamp'],
            d['signature']
        ):
            print("[Handshake] Invalid signature. Connection aborted.")
            return
        # Replay protection
        if d['nonce'] in received_nonces or abs(int(time.time()) - d['timestamp']) > 60:
            print("[Handshake] Replay detected. Connection aborted.")
            return
        received_nonces.add(d['nonce'])

        # Compute shared key if joiner or leader
        if not shared_key:
            hkdf_shared_key(d['x25519_pub'])
            print("[Handshake] Shared AES key established. Connection secured.")

# ------------------ MESSAGE EVENTS ------------------
@sio.on('encrypted-message')
def on_encrypted_message(msg):
    try:
        data = decrypt_message(msg)
        print(f"{data['username']} ({data['sender']}) [{data['timestamp']}]: {data['message']}")
    except Exception as e:
        print("Failed to decrypt/verify message:", e)

# ------------------ USER INPUT ------------------
def input_thread():
    global CURRENT_LOBBY, PEER_INFO
    while True:
        raw = input("> ").strip()
        if not raw: continue
        parts = raw.split()
        cmd = parts[0].lower()
        if cmd == 'signup':
            signup()
        elif cmd == 'login':
            login()
        elif cmd == 'createlobby':
            if len(parts) < 2: print("usage: createlobby <name>"); continue
            CURRENT_LOBBY = parts[1]
            sio.emit('create-lobby', {'name': CURRENT_LOBBY}, callback=lambda r: print("create-lobby:", r))
        elif cmd == 'joinlobby':
            if len(parts) < 2: print("usage: joinlobby <name>"); continue
            CURRENT_LOBBY = parts[1]
            sio.emit('join-lobby', {'name': CURRENT_LOBBY}, callback=lambda r: print("join-lobby:", r))
        elif cmd == 'send':
            if not PEER_INFO or not shared_key:
                print("No secure connection yet.")
                continue
            content = " ".join(parts[1:])
            encrypted = encrypt_message(content)
            sio.emit('encrypted-message', {**encrypted, 'lobby': str(CURRENT_LOBBY), 'toUserId': str(PEER_INFO['userid'])})
        elif cmd == 'leave':
            if not CURRENT_LOBBY: continue
            sio.emit('leave-lobby', {'lobby': CURRENT_LOBBY}, callback=lambda r: print("left:", r))
            CURRENT_LOBBY = None
            PEER_INFO = None
        elif cmd == 'help':
            print("Commands: signup, login, createlobby <name>, joinlobby <name>, send <message>, leave, help")
        else:
            print("unknown command")

# ------------------ MAIN ------------------
if __name__ == '__main__':
    print("Secure E2EE messaging client")
    threading.Thread(target=input_thread, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
