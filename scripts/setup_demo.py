"""Setup demo user and data on the live server."""
import paramiko, json, hashlib, os, time, struct, base64, ssl, hmac as hmac_mod, secrets, shlex
import urllib.request
from urllib.parse import urlsplit
from nacl.signing import SigningKey
from nacl.public import PrivateKey as X25519PrivateKey
import nacl.bindings
import argon2.low_level
from ulid import ULID

SERVER = os.environ.get("SEZAM_DEMO_SERVER", "").rstrip("/")
SSH_HOST = os.environ.get("SEZAM_SSH_HOST", "")
try:
    SSH_PORT = int(os.environ.get("SEZAM_SSH_PORT", "22"))
except ValueError as exc:
    raise RuntimeError("SEZAM_SSH_PORT must be an integer") from exc
if not 1 <= SSH_PORT <= 65535:
    raise RuntimeError("SEZAM_SSH_PORT must be between 1 and 65535")
DB_CONTAINER_NAME = os.environ.get("SEZAM_DB_CONTAINER_NAME", "sezam-db")
if not DB_CONTAINER_NAME:
    raise RuntimeError("SEZAM_DB_CONTAINER_NAME must not be empty")
parsed_server = urlsplit(SERVER)
if (
    parsed_server.scheme not in {"http", "https"}
    or not parsed_server.hostname
    or parsed_server.username
    or parsed_server.password
    or parsed_server.query
    or parsed_server.fragment
    or parsed_server.path not in {"", "/"}
):
    raise RuntimeError("SEZAM_DEMO_SERVER must explicitly name a plain HTTP(S) origin")
if not SSH_HOST:
    raise RuntimeError("SEZAM_SSH_HOST must explicitly name the demo database target")
if os.environ.get("SEZAM_DEMO_ALLOW_DESTRUCTIVE") != f"{SERVER}|{SSH_HOST}":
    raise RuntimeError(
        "SEZAM_DEMO_ALLOW_DESTRUCTIVE must confirm SEZAM_DEMO_SERVER|SEZAM_SSH_HOST"
    )
ctx = ssl.create_default_context()

def api(method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token: headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(SERVER + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
        return json.loads(r.read())

# Server Argon2 params
meta = api("GET", "/api/meta")
wp = meta["argon2_web_params"]
print(f"Server params: {wp}")

USERNAME = os.environ.get("SEZAM_DEMO_USERNAME", "demo")
PASSWORD = os.environ["SEZAM_DEMO_PASSWORD"]
SSH_USER = os.environ.get("SEZAM_SSH_USER", "root")
SSH_PASSWORD = os.environ.get("SEZAM_SSH_PASSWORD")

# Generate keypairs
sk = SigningKey.generate()
signing_pk = bytes(sk.verify_key)
signing_sk = bytes(sk)
ek = X25519PrivateKey.generate()
encryption_pk = bytes(ek.public_key)
encryption_sk = bytes(ek)
fp = hashlib.sha256(signing_pk + encryption_pk).hexdigest()

# Derive KEK with server params
salt = os.urandom(16)
auth_salt = os.urandom(16)
kek_raw = argon2.low_level.hash_secret_raw(
    PASSWORD.encode(), salt=salt,
    time_cost=wp["time_cost"], memory_cost=wp["memory_cost"],
    parallelism=wp["parallelism"], hash_len=64, type=argon2.low_level.Type.ID,
)
kek = kek_raw[:32]
auth_proof = kek_raw[32:64]

# Encrypt keypair
keypair_data = signing_sk + encryption_sk
nonce = os.urandom(24)
ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(keypair_data, None, nonce, kek)
encrypted_keypair = nonce + ct

# Auth proof hash
verify_salt = os.urandom(32)
aph = hmac_mod.new(verify_salt, auth_proof, hashlib.sha256).hexdigest()

# Insert user
ssh = paramiko.SSHClient()
ssh.load_system_host_keys()
if known_hosts := os.environ.get("SEZAM_SSH_KNOWN_HOSTS"):
    ssh.load_host_keys(os.path.expanduser(known_hosts))
ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
ssh.connect(SSH_HOST, port=SSH_PORT, username=SSH_USER, password=SSH_PASSWORD,
            timeout=15, look_for_keys=True, allow_agent=True)

def _hex_text(value: str) -> str:
    """Embed text as a hex literal so no caller-supplied byte reaches SQL syntax."""
    return f"CONVERT(X'{value.encode('utf-8').hex()}' USING utf8mb4)"


uid = str(ULID())
# The wipe and the insert run as one transaction; the mariadb client aborts on
# the first error, so a failed INSERT never leaves the server without users.
sql = (
    "SET autocommit=0;\nSTART TRANSACTION;\n"
    "DELETE FROM vault_objects;\nDELETE FROM users;\n"
    "INSERT INTO users (id,username,signing_pk,encryption_pk,key_fingerprint,"
    "status,is_admin,encrypted_keypair,argon2_salt,auth_salt,verify_salt,"
    "auth_proof_hash,recovery_locked,created_at) VALUES ("
    + ",".join([
        _hex_text(uid), _hex_text(USERNAME),
        f"X'{signing_pk.hex()}'", f"X'{encryption_pk.hex()}'", _hex_text(fp),
        _hex_text("active"), "1", f"X'{encrypted_keypair.hex()}'",
        f"X'{salt.hex()}'", f"X'{auth_salt.hex()}'", f"X'{verify_salt.hex()}'",
        _hex_text(aph), "0", str(int(time.time() * 1000)),
    ])
    + ");\nCOMMIT;\n"
)

stdin, stdout, stderr = ssh.exec_command(
    "docker exec -i "
    + shlex.quote(DB_CONTAINER_NAME)
    + " sh -c 'exec mariadb -usezam -p\"$MARIADB_PASSWORD\" sezam'",
    timeout=30,
)
stdin.write(sql)
stdin.channel.shutdown_write()
if stdout.channel.recv_exit_status() != 0:
    raise RuntimeError(stderr.read().decode().strip() or "Demo database setup failed")
time.sleep(5)
print("User created")
ssh.close()

# Auth
ch = api("POST", "/api/auth/challenge", {"username": USERNAME})
time.sleep(0.5)
sig = sk.sign(bytes.fromhex(ch["challenge"])).signature
auth = api("POST", "/api/auth/verify", {
    "username": USERNAME, "challenge": ch["challenge"], "signature": sig.hex()
})
token = auth["token"]
print(f"Auth OK, admin={auth['is_admin']}")

# Push data
dek_id = str(ULID())
dek_raw_bytes = os.urandom(32)
dn = os.urandom(24)
wrapped = dn + nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(dek_raw_bytes, None, dn, kek)

def sign_and_push(oid, otype, payload, parent=None, ver=1):
    pb64 = base64.b64encode(payload).decode()
    ph = hashlib.sha256(payload).hexdigest()
    idb = oid.encode()[:26].ljust(26, b'\x00')
    otb = otype.encode()
    prb = parent.encode()[:26].ljust(26, b'\x00') if parent else b'\x00'*26
    canon = idb + bytes([len(otb)]) + otb + prb + b'\x00'*26 + b'\x00' + struct.pack(">I", ver) + bytes.fromhex(ph)
    s = sk.sign(canon).signature
    return api("POST", "/api/sync", {"objects": [{
        "id": oid, "object_type": otype, "payload": pb64,
        "parent_ref": parent, "version": ver, "is_deleted": 0,
        "payload_hash": ph, "signature": s.hex(),
    }]}, token=token)

def make_aad(blob_kind, dek_id_str, obj_id_str, version=1):
    """Build 59-byte AAD matching web client's buildAAD()."""
    aad = bytearray(59)
    aad[0] = 1  # ALG_XCHACHA20POLY1305
    aad[1] = 1  # SCHEMA_VERSION
    aad[2] = blob_kind
    did = dek_id_str.encode()[:26].ljust(26, b'\x00')
    oid = obj_id_str.encode()[:26].ljust(26, b'\x00')
    aad[3:29] = did
    aad[29:55] = oid
    struct.pack_into(">I", aad, 55, version)
    return bytes(aad)

def make_envelope(plaintext_bytes, blob_kind, dek_id_str, obj_id_str, key, version=1, pad=True):
    """Encrypt into envelope format matching web's encryptEnvelope/wrapDEK."""
    aad = make_aad(blob_kind, dek_id_str, obj_id_str, version)
    nonce = os.urandom(24)
    if pad:
        # Pad: u16be(pad_len) + random_padding + data, min 32, power of 2,
        # padding capped at 0xFFFF by the u16 prefix.
        target = 32
        while target < 2 + len(plaintext_bytes):
            target *= 2
        pad_len = min(target - 2 - len(plaintext_bytes), 0xFFFF)
        padded = struct.pack(">H", pad_len) + os.urandom(pad_len) + plaintext_bytes
    else:
        padded = plaintext_bytes
    ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(padded, aad, nonce, key)
    # Envelope: alg(1) + schema(1) + kind(1) + dekId(26) + nonce(24) + ciphertext
    did = dek_id_str.encode()[:26].ljust(26, b'\x00')
    header = bytes([1, 1, blob_kind]) + did + nonce
    return header + ct

def enc(data_bytes):
    """Encrypt data with root DEK in envelope format (blob_kind depends on usage)."""
    oid = str(ULID())
    return make_envelope(data_bytes, 1, dek_id, oid, dek_raw_bytes, pad=True)

# Wrap DEK with KEK using envelope format (blob_kind=6)
wrapped = make_envelope(dek_raw_bytes, 6, dek_id, dek_id, kek, pad=False)

sign_and_push(dek_id, "dek", wrapped)
root_id = str(ULID())
root_env = make_envelope(json.dumps({"name":"Vault","tier":1}).encode(), 1, dek_id, root_id, dek_raw_bytes, pad=True)
sign_and_push(root_id, "node", root_env)

folders = {}
for name in ["Servery", "Databuzy", "Email", "Klienti"]:
    fid = str(ULID())
    node_env = make_envelope(json.dumps({"name":name,"tier":1}).encode(), 1, dek_id, fid, dek_raw_bytes, pad=True)
    sign_and_push(fid, "node", node_env, parent=root_id)
    folders[name] = fid

entries = [
    ("Servery", "Demo SSH server", [
        {"key":"host","value":"203.0.113.10","sensitive":False},
        {"key":"username","value":"root","sensitive":False},
        {"key":"password","value":secrets.token_urlsafe(24),"sensitive":True},
        {"key":"port","value":"22","sensitive":False},
    ]),
    ("Servery", "Demo droplet", [
        {"key":"host","value":"198.51.100.16","sensitive":False},
        {"key":"username","value":"root","sensitive":False},
        {"key":"password","value":secrets.token_urlsafe(24),"sensitive":True},
    ]),
    ("Databuzy", "MariaDB Production", [
        {"key":"host","value":"db.example.internal:3306","sensitive":False},
        {"key":"username","value":"sezam","sensitive":False},
        {"key":"password","value":secrets.token_urlsafe(24),"sensitive":True},
        {"key":"database","value":"sezam","sensitive":False},
    ]),
    ("Databuzy", "Redis Cache", [
        {"key":"host","value":"redis.internal:6379","sensitive":False},
        {"key":"password","value":secrets.token_urlsafe(24),"sensitive":True},
    ]),
    ("Email", "Gmail", [
        {"key":"email","value":"demo@example.com","sensitive":False},
        {"key":"password","value":secrets.token_urlsafe(24),"sensitive":True},
    ]),
    ("Email", "Firma SMTP", [
        {"key":"server","value":"smtp.example.com","sensitive":False},
        {"key":"username","value":"demo@example.com","sensitive":False},
        {"key":"password","value":secrets.token_urlsafe(24),"sensitive":True},
        {"key":"port","value":"587","sensitive":False},
    ]),
    ("Klienti", "Auto-Moto s.r.o.", [
        {"key":"kontakt","value":"Janko Mrkvicka","sensitive":False},
        {"key":"telefon","value":"+421 900 123 456","sensitive":False},
        {"key":"api_key","value":"ak_live_xYz123AbC","sensitive":True},
    ]),
]

for folder, name, fields in entries:
    eid = str(ULID())
    edata = json.dumps({"name": name, "fields": fields}).encode()
    entry_envelope = make_envelope(edata, 3, dek_id, eid, dek_raw_bytes, pad=True)  # blob_kind=3 ENTRY_DATA
    sign_and_push(eid, "entry", entry_envelope, parent=folders[folder])

print(f"Pushed {len(entries)} entries in {len(folders)} folders")
print(f"\n{'='*50}")
print(f"  Web: {SERVER}")
print(f"  Username: {USERNAME}")
print("  Password: supplied via SEZAM_DEMO_PASSWORD")
print(f"{'='*50}")
