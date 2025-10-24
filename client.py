# client.py
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

SERVER_HTTP = 'https://sealchatserver.onrender.com/'
SERVER_WS = 'https://sealchatserver.onrender.com/'

sio = socketio.Client(logger=False, engineio_logger=False)
USER = None 
CURRENT_LOBBY = None
PEER_INFO = None  

x_priv = None
x_pub_b64 = None
sign_priv_ephemeral = None
sign_pub_ephemeral_b64 = None

persistent_sign_priv = None
persistent_sign_pub_b64 = None
PERSISTENT_KEY_FILE = os.path.expanduser("~/.sealchat/ed25519_priv.key")

PINNED_KEYS_DIR = os.path.expanduser("~/.sealchat/pinned_peers")
os.makedirs(PINNED_KEYS_DIR, exist_ok=True)

shared_key = None
aesgcm = None

received_nonces = set()

def jsonb64(b: bytes):
    return base64.b64encode(b).decode('ascii')

def b64json(s):
    return base64.b64decode(s.encode('ascii'))

def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')

def wait_for_server_awake():
    print("Checking if server is awake")
    while True:
        try:
            response = requests.get(SERVER_HTTP, timeout=5)
            if response.status_code == 200:
                print("Server is awake. Connecting now")
                return
        except requests.RequestException:
            pass
        print("Server appears asleep. Waiting for it to wake up")
        time.sleep(5)

def load_or_create_persistent_key(username=None):
    global persistent_sign_priv, persistent_sign_pub_b64

    base_folder = os.path.expanduser("~/.sealchat")
    if username:
        folder = os.path.join(base_folder, username)
    else:
        folder = base_folder

    os.makedirs(folder, exist_ok=True)
    key_path = os.path.join(folder, "ed25519_priv.key")

    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            persistent_sign_priv = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
    else:
        persistent_sign_priv = ed25519.Ed25519PrivateKey.generate()
        with open(key_path, "wb") as f:
            f.write(persistent_sign_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(key_path, 0o600)

    persistent_sign_pub_b64 = base64.b64encode(
        persistent_sign_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    ).decode('ascii')

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

def hash_password(password: str):
    # simple SHA-256 hash, result as hex string
    return hashlib.sha256(password.encode()).hexdigest()

def sign_handshake(pub_x, pub_sign, nonce, ts):
    msg_obj = {
        'x25519_pub': pub_x,
        'ed25519_ephemeral_pub': pub_sign,
        'nonce': nonce,
        'timestamp': ts,
        'persistent_ed25519_pub': persistent_sign_pub_b64
    }
    msg_bytes = canonical_json(msg_obj)
    return jsonb64(persistent_sign_priv.sign(msg_bytes))


def verify_handshake_signature(peer_persistent_pub_b64, pub_x, pub_sign, nonce, ts, signature_b64):
    peer_pub = ed25519.Ed25519PublicKey.from_public_bytes(b64json(peer_persistent_pub_b64))
    msg_obj = {
        'x25519_pub': pub_x,
        'ed25519_ephemeral_pub': pub_sign,
        'nonce': nonce,
        'timestamp': ts,
        'persistent_ed25519_pub': peer_persistent_pub_b64
    }
    msg_bytes = canonical_json(msg_obj)
    try:
        peer_pub.verify(b64json(signature_b64), msg_bytes)
        return True
    except InvalidSignature:
        return False


def encrypt_message(content):
    global aesgcm
    if not isinstance(content, str):
        content = str(content) 
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

def clear_session_data():
    global shared_key, aesgcm, received_nonces, PEER_INFO, USER, CURRENT_LOBBY
    print("Wiping all in-memory session data")
    try:
        if shared_key:
            shared_key = b'\x00' * len(shared_key)
        if aesgcm:
            del aesgcm
            aesgcm = None
        if received_nonces:
            received_nonces.clear()
        if PEER_INFO:
            PEER_INFO.clear()
            PEER_INFO = None
        if USER:
            USER.clear()
            USER = None
        CURRENT_LOBBY = None
    except Exception:
        pass
    print("Session data cleared")


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
    for key in ['sender', 'username', 'lobby', 'timestamp', 'message']:
        if key in obj:
            obj[key] = str(obj[key])
    return obj

def signup():
    username = input("username: ").strip()
    password = getpass.getpass("password: ")
    load_or_create_persistent_key(username) 
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
    load_or_create_persistent_key(username)
    payload = {
        "username": username,
        "password": password,
        "persistent_ed25519_pub": persistent_sign_pub_b64
    }
    r = requests.post(SERVER_HTTP + '/login', json=payload)
    if r.status_code == 200:
        USER = r.json()
        print("Logged in as", USER)
        sio.connect(SERVER_WS)
        return True

    print("Login failed:", r.text)
    return False


@sio.event
def connect():
    print("[Socket] Connected")
    if USER:
        sio.emit('register', {'userid': USER['userid'], 'username': USER['username']})


@sio.on('peer-joined')
def on_peer_joined(data):
    """
    Called when a peer joins the lobby.
    Starts handshake with TOFU key pinning and fingerprint display.
    """
    global PEER_INFO
    PEER_INFO = data['peer']
    peer_username = PEER_INFO['username']
    print(f"Peer '{peer_username}' joined. Preparing handshake")

    pinned_pub = load_pinned_peer_key(peer_username)
    received_pub = PEER_INFO.get('persistent_ed25519_pub')

    if pinned_pub is None and received_pub:
        save_pinned_peer_key(peer_username, received_pub)
        print(f"[Handshake] First-time trust for peer '{peer_username}'. Key pinned.")
        print(f"Peer fingerprint: {pubkey_fingerprint(received_pub)}")
    elif pinned_pub:
        print(f"[Handshake] Stored fingerprint for peer '{peer_username}': {pubkey_fingerprint(pinned_pub)}")
        if received_pub and pinned_pub != received_pub:
            print(f"[Handshake WARNING] Server-reported key mismatch for peer '{peer_username}'!")
            print(f"Stored fingerprint: {pubkey_fingerprint(pinned_pub)}")
            print(f"Server-reported fingerprint: {pubkey_fingerprint(received_pub)}")
            print("Possible MITM. You may want to verify this out-of-band.")

    def delayed_handshake():
        time.sleep(0.1)
        gen_ephemeral_keys()
        nonce = base64.b64encode(os.urandom(12)).decode()
        ts = int(time.time())
        payload = {
            'lobby': CURRENT_LOBBY,
            'toUserId': PEER_INFO['userid'],
            'type': 'hello',
            'data': {
                'x25519_pub': x_pub_b64,
                'ed25519_ephemeral_pub': sign_pub_ephemeral_b64,
                'persistent_ed25519_pub': persistent_sign_pub_b64,
                'nonce': nonce,
                'timestamp': ts,
                'signature': sign_handshake(x_pub_b64, sign_pub_ephemeral_b64, nonce, ts)
            }
        }
        print(f"[Handshake] Sending ephemeral keys to peer '{peer_username}'...")
        sio.emit('signal', payload)

    threading.Thread(target=delayed_handshake, daemon=True).start()



@sio.on('signal')
def on_signal(msg):
    global shared_key, aesgcm
    sender = msg.get('from')
    t = msg.get('type')
    d = msg.get('data', {})

    if t in ('hello', 'leader-pubkeys', 'joiner-pubkeys'):
        if not PEER_INFO:
            print("[Handshake] No peer info yet. Ignoring signal.")
            return

        peer_username = PEER_INFO['username']
        received_pub = d['persistent_ed25519_pub']

        pinned_pub = load_pinned_peer_key(peer_username)

        if pinned_pub is None:
            save_pinned_peer_key(peer_username, received_pub)
            print(f"[Handshake] First-time trust for peer '{peer_username}'. Key pinned.")
        elif pinned_pub != received_pub:
            print(f"[Handshake WARNING] Persistent key mismatch for peer '{peer_username}'!")
            print(f"Stored fingerprint: {pubkey_fingerprint(pinned_pub)}")
            print(f"Received fingerprint: {pubkey_fingerprint(received_pub)}")
            print("Possible MITM. Connection aborted.")
            return

        print(f"[Handshake] Peer '{peer_username}' fingerprint: {pubkey_fingerprint(received_pub)}")

        if not verify_handshake_signature(
            received_pub,
            d['x25519_pub'],
            d['ed25519_ephemeral_pub'],
            d['nonce'],
            d['timestamp'],
            d['signature']
        ):
            print("[Handshake] Invalid signature. Connection aborted.")
            return

        if d['nonce'] in received_nonces or abs(int(time.time()) - d['timestamp']) > 60:
            print("[Handshake] Replay detected. Connection aborted.")
            return
        received_nonces.add(d['nonce'])

        if not shared_key:
            hkdf_shared_key(d['x25519_pub'])
            print("[Handshake] Shared AES key established. Connection secured.")


@sio.on('encrypted-message')
def on_encrypted_message(msg):
    try:
        data = decrypt_message(msg)
        print(f"{data['username']} ({data['sender']}) [{data['timestamp']}]: {data['message']}")
    except Exception as e:
        print("Failed to decrypt/verify message:", e)

def input_thread():
    global CURRENT_LOBBY, PEER_INFO
    while True:
        try:
            raw = input("> ").strip()
        except EOFError:
            break
        if not raw:
            continue
        parts = raw.split()
        cmd = parts[0].lower()
        if cmd == 'signup':
            signup()
        elif cmd == 'login':
            login()
        elif cmd == 'clear':
            clear_session_data()
        elif cmd == 'createlobby':
            if len(parts) < 2:
                print("usage: createlobby <name> [password]")
                continue
            CURRENT_LOBBY = parts[1]
            lobby_password = parts[2] if len(parts) > 2 else ""
            lobby_password = hash_password(lobby_password)
            if not sio.connected:
                print("Not connected to server yet. Try again in a moment.")
                continue
            sio.emit('create-lobby', {'name': CURRENT_LOBBY, 'password': lobby_password},
                     callback=lambda r: print("create-lobby:", r))

        elif cmd == 'joinlobby':
            if len(parts) < 2:
                print("usage: joinlobby <name> [password]")
                continue
            CURRENT_LOBBY = parts[1]
            lobby_password = parts[2] if len(parts) > 2 else ""
            lobby_password = hash_password(lobby_password)
            sio.emit('join-lobby', {'name': CURRENT_LOBBY, 'password': lobby_password},
                    callback=lambda r: print("join-lobby:", r))

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
            print("Commands: signup, login, createlobby <name> [password], joinlobby <name> [password], send <message>, leave, clear, help")
        else:
            print("unknown command")
            
if __name__ == "__main__":
    print("Seal Chat E2EE messaging service")
    print('Type "help" to see available commands')


    wait_for_server_awake()
    
    threading.Thread(target=input_thread, daemon=True).start()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nShutting down and wiping session data")

        try:
            if 'shared_key' in globals() and shared_key:
                shared_key = b'\x00' * len(shared_key)
            if 'aesgcm' in globals():
                del aesgcm
            if 'received_nonces' in globals():
                received_nonces.clear()
            if 'PEER_INFO' in globals():
                PEER_INFO.clear()
            if 'USER' in globals():
                USER.clear()
        except Exception:
            pass

        time.sleep(0.3)
        os._exit(0)
