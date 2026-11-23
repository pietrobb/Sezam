# Sezam — Technická dokumentácia

**Plná technická referencia pre bezpečnostných audítorov, kryptografov a developerov**
**Verzia:** 1.0
**Posledná aktualizácia:** 2026-03-19
**Referencuje:** SEZAM_SPEC_v15_FINAL.md (Version 1.0 FROZEN)

---

## Obsah

1. [Kryptografické primitíva](#1-kryptografické-primitíva)
2. [Ciphertext Envelope Format](#2-ciphertext-envelope-format)
3. [AAD Construction](#3-aad-construction)
4. [KEK/DEK hierarchia](#4-kekdek-hierarchia)
5. [Envelope Encryption (multi-user)](#5-envelope-encryption-multi-user)
6. [Autentifikačný protokol](#6-autentifikačný-protokol)
7. [Sync protokol](#7-sync-protokol)
8. [Rollback Protection](#8-rollback-protection)
9. [Threat Model](#9-threat-model)
10. [Key Rotation](#10-key-rotation)
11. [Shamir Secret Sharing](#11-shamir-secret-sharing)
12. [Memory Safety](#12-memory-safety)
13. [Web Security](#13-web-security)
14. [Dátový model](#14-dátový-model)
15. [API referencia](#15-api-referencia)
16. [Recovery scenáre](#16-recovery-scenáre)
17. [SSH agent pre AI](#17-ssh-agent-pre-ai)
18. [Threat model AI brokera (L1/L2/L3)](#18-threat-model-ai-brokera-l1l2l3)

---

## 1. Kryptografické primitíva

### 1.1 Prehľad

| Primitív | Použitie | Knižnica |
|----------|----------|----------|
| Argon2id | KDF: master password --> KEK | `argon2-cffi` (desktop), `argon2-browser` WASM (web) |
| XChaCha20-Poly1305-IETF | AEAD šifrovanie obsahu (entries, metadata, DEK wrapping) | `pynacl`/`pysodium` (desktop), `libsodium-wrappers` (web) |
| NaCl crypto_box | Authenticated key wrapping pre obálky (envelopes) | `pynacl` / `libsodium-wrappers` |
| Ed25519 | Podpisová schéma: server auth, audit log, sync integrita | `pynacl` / `libsodium-wrappers` |
| X25519 | Diffie-Hellman key agreement pre envelope encryption | `pynacl` / `libsodium-wrappers` |
| SHA-256 | Fingerprints, payload_hash, state_hash | `hashlib` (Python), `SubtleCrypto` (web) |
| HMAC-SHA256 | auth_proof_hash, fake salt generation, IP/UA anonymizácia | `hmac` (Python) |

### 1.2 Argon2id

**Funkcia:** Key Derivation Function (KDF) — transformuje master password na 256-bit Root KEK.

**Parametre:**

| Parameter | Default hodnota | Mobilný fallback | Hard floor (web) |
|-----------|----------------|-------------------|------------------|
| `time` (iterácie) | 3 | 2 | 2 |
| `memory` (KB) | 262144 (256 MB) | 131072 (128 MB) | 65536 (64 MB) |
| `parallelism` | 4 | 4 | 4 |
| `hash_length` | 32 (256 bit) | 32 | 32 |
| `salt_length` | 16 (128 bit) | 16 | 16 |
| `type` | Argon2id | Argon2id | Argon2id |

**Vstup KDF = UTF-8(NFC(heslo)) (lockout review M8).** To isté viditeľné heslo môže prísť ako rôzne kódové body: „é“ ako U+00E9 alebo ako „e“ + U+0301, podľa klávesnice, OS alebo vloženia zo schránky. Desktop (`kdf.canonical_password`), web (`canonicalPassword`) aj mobil (`password_forms.dart`, balík `unorm_dart`) preto heslo pred Argon2id normalizujú na NFC. Nové heslo (vytvorenie trezoru, registrácia, zmena hesla, org recovery) sa odvodzuje len z NFC. Existujúce heslo sa overuje najprv v NFC. Trezor alebo účet vytvorený pred normalizáciou sa otvorí aj heslom presne tak, ako bolo napísané, alebo jeho NFD formou (`password_forms`). Pri lokálnom overení (keypair, `.sezam-key`, zmena hesla) sa skúšajú lokálne. Na `/api/auth/recover` ide ďalšia forma len po 401, nie po 429/423 ani pri výpadku. Web s keypairom v IndexedDB skúsi najprv všetky formy lokálne na tejto cache (`openLoginKeypairAnyForm`, review 688edcb V3). Účet spred normalizácie tak cache otvorí napísanou formou a NFC proof na `/recover` nejde. Predtým každé také prihlásenie pridalo jeden zlý pokus a po desiatich zámok mena (423) ukončil každé ďalšie prihlásenie. Na server sa ide, až keď cache neotvorí žiadna forma (heslo zmenené inde), s tými istými odvodeniami. Bez cache ide NFC a po 401 ďalšia forma; úspech počítadlá vynuluje. Účet sa na NFC automaticky nemigruje: znamenalo by to rotáciu KEK (prebalenie všetkých DEK, nová epocha na všetkých zariadeniach) a web pri bežnom prihlásení nemá recovery kľúč na prebalenie org recovery blobu. Auth proof nahrávaný s keypairom sa odvodzuje z formy, ktorá ten keypair otvára. ASCII heslo má jedinú formu, Argon2id sa preto spustí iba raz.

**Riadiace znaky v hesle (review 688edcb, nízke).** Desktop nové heslo s riadiacim znakom (U+0000–U+001F, U+007F, napr. koncové `\r` z Windows súboru, tabulátor, nový riadok) odmietne (`crud.require_usable_password`: vytvorenie trezoru, zmena hesla, org recovery), lebo v prehliadači ani na mobile sa nedá napísať. CLI z rúry (`sezam … < súbor`) odreže z riadku len jeden koniec riadku (`\r\n` alebo `\n`); predtým `rstrip("\r\n")` zjedol aj `\r`, ktoré patrilo k heslu. Heslo končiace `\r` (napr. vložené na mobile) sa tak zadá ako `heslo\r` + koniec riadku.

**Prečo Argon2id (nie bcrypt/scrypt):**

| KDF | Problémy |
|-----|----------|
| bcrypt | Fixed 4 KB memory — GPU-friendly. Maximálne 72 bajtov vstup. Bez paralelizmu. |
| scrypt | Neflexibilná konfigurácia. Slabá odolnosť voči side-channel útokom (Argon2i časť v Argon2id to rieši). Žiadny štandard (RFC draft). |
| **Argon2id** | **Víťaz Password Hashing Competition (2015).** Konfigurovateľná pamäť (až GB). Data-independent prvých M/2 priechodov (side-channel ochrana). Data-dependent zvyšných priechodov (GPU/ASIC odolnosť). RFC 9106. |

**Proces:**

```python
import argon2

salt = os.urandom(16)  # unikátny per-user, uložený verejne

kek = argon2.low_level.hash_secret_raw(
    secret=password.encode('utf-8'),
    salt=salt,
    time_cost=3,
    memory_cost=262144,  # 256 MB
    parallelism=4,
    hash_len=32,
    type=argon2.Type.ID
)
# kek je 32-bajtový bytearray = Root KEK
```

**Dva oddelené salts:**

| Salt | Účel | Verejný? |
|------|------|----------|
| `argon2_salt` | KDF pre KEK (encryption) | Áno (klient ho potrebuje pred unlock) |
| `auth_salt` | KDF pre auth_proof (password-based recovery) | Áno (klient ho získa cez GET /api/meta) |

**auth_proof flow:**
```
auth_proof = Argon2id(password, auth_salt)    -- klient
auth_proof_hash = HMAC-SHA256(verify_salt, auth_proof)  -- server
```

Klient nikdy neposiela `auth_proof_hash`, len `auth_proof`. Server dopočíta hash pomocou `verify_salt` (server-side only secret). `auth_proof` je už 32-bajt high-entropy Argon2id output — druhý Argon2id by bol zbytočne drahý a DoS vektor.

**Benchmark a upgrade:**
- Pri prvom spustení sa Argon2id benchmarkne na danom HW (target: ~1s).
- Pri každej unlock operácii sa porovnajú parametre s aktuálnym štandardom.
- Ak sú parametre zastarané, GUI ponúkne upgrade --> re-derive KEK, re-wrap DEK-y.

### 1.3 XChaCha20-Poly1305-IETF

**Funkcia:** Authenticated Encryption with Associated Data (AEAD) pre všetok vault obsah.

**Parametre:**

| Parameter | Hodnota |
|-----------|---------|
| Kľúč | 256 bit (32 B) |
| Nonce | 192 bit (24 B) — náhodný, `os.urandom(24)` |
| Tag | 128 bit (16 B) — Poly1305 MAC |
| AAD | 59 B fixed (viď sekcia 3) |

**Prečo XChaCha20-Poly1305 (nie AES-GCM):**

| Kritérium | AES-256-GCM | XChaCha20-Poly1305 |
|-----------|-------------|---------------------|
| Nonce | 96 bit (12 B) — kolízia po 2^32 správ s rovnakým kľúčom | **192 bit (24 B) — kolízia po ~2^96 správ, bezpečný random nonce** |
| Random nonce | NEBEZPEČNÉ pri veľkom objeme | **BEZPEČNÉ — XChaCha20 navrhnutý pre random nonce** |
| HW akcelerácia | AES-NI (x86) | Softvérový, ale stále rýchly (~3 GB/s na modernom CPU) |
| Nonce reuse | Katastrofálne (key recovery) | Katastrofálne (rovnako) |
| Knižnica | Vyžaduje OpenSSL binding | **Natívne v libsodium** |

**Rozhodujúci faktor:** 24-bajtový random nonce. V systéme kde každý entry môže mať desiatky verzií a DEK-y sa rotujú, 12-bajtový AES-GCM nonce vytvára reálne riziko kolízie. XChaCha20 s 24B nonce toto riziko eliminuje.

**Použitie v Sezame:**

```python
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt
)

nonce = os.urandom(24)
aad = build_aad(alg, schema_version, blob_kind, dek_id, object_id, version)

ciphertext_with_tag = crypto_aead_xchacha20poly1305_ietf_encrypt(
    message=padded_plaintext,
    aad=aad,
    nonce=nonce,
    key=dek
)
# ciphertext_with_tag = ciphertext || poly1305_tag (16B)
# Libsodium tag je na konci, nie separátny
```

### 1.4 Ed25519

**Funkcia:** Digitálne podpisy — server autentifikácia, audit log, sync integrita.

| Parameter | Hodnota |
|-----------|---------|
| Privátny kľúč | 64 B (seed 32B + expandovaný) |
| Verejný kľúč | 32 B (kompresovaný Edwards bod) |
| Podpis | 64 B |
| Bezpečnostná úroveň | ~128-bit (ekvivalent RSA-3072) |

**Prečo Ed25519 (nie RSA):**

| Kritérium | RSA-2048 | Ed25519 |
|-----------|----------|---------|
| Veľkosť kľúča | 256 B pub, 1-2 KB priv | **32 B pub, 64 B priv** |
| Veľkosť podpisu | 256 B | **64 B** |
| Rýchlosť podpisu | ~ms | **~us** |
| Rýchlosť overenia | ~ms | **~us** |
| Determinizmus | Vyžaduje PKCS#1 padding | **Deterministický (RFC 8032)** |

**Použitie:**
- `signing_sk` — privátny kľúč (šifrovaný KEK-om, AEAD blob_kind=7)
- `signing_pk` — verejný kľúč (na serveri, plain text)
- Challenge-response auth (sekcia 6)
- Audit log podpisy (každý záznam)
- Sync object signatures (každý pushnutý objekt)
- JWT server key (`alg=EdDSA, crv=Ed25519`)

### 1.5 X25519

**Funkcia:** Diffie-Hellman key agreement pre envelope encryption (obálkové šifrovanie DEK-ov).

| Parameter | Hodnota |
|-----------|---------|
| Privátny kľúč | 32 B (Curve25519 scalar) |
| Verejný kľúč | 32 B (Curve25519 point) |
| Shared secret | 32 B |

**Prečo oddelený od Ed25519:**

X25519 je Diffie-Hellman key agreement — nedá sa ním podpisovať. Ed25519 je podpisová schéma — nedá sa ňou šifrovať. Libsodium podporuje konverziu `crypto_sign_ed25519_sk_to_curve25519()`, ale pre bezpečnosť a čistotu návrhu udržujeme **oddelené páry** — žiadny cross-protocol risk.

**Použitie:**
- `encryption_sk` — privátny kľúč (šifrovaný KEK-om, AEAD blob_kind=7)
- `encryption_pk` — verejný kľúč (na serveri, plain text)
- NaCl `crypto_box` pre DEK obálky

### 1.6 NaCl crypto_box

**Funkcia:** Authenticated encryption pre obálky (DEK wrapping pre multi-user prístup).

```
crypto_box(message, nonce, recipient_pk, sender_sk)
  = X25519(sender_sk, recipient_pk) --> shared_secret
  --> XSalsa20-Poly1305(message, nonce, shared_secret)
```

**Prečo `crypto_box` (nie `crypto_box_seal`):**

| | crypto_box | crypto_box_seal |
|---|-----------|-----------------|
| Autentifikácia | **Áno** — príjemca vie, kto obálku vytvoril | Anonymná — príjemca nevie odosielateľa |
| Použitie v Sezame | **Obálky** — admin je vždy odosielateľ, autenticita je dôležitá | Nepoužívame |

**AAD nie je potrebné pre obálky** — obálka je viazaná na príjemcu cez jeho pubkey (X25519 DH). `created_by` stĺpec v `access_envelopes` určuje odosielateľa pre dešifrovanie.

### 1.7 SHA-256

**Funkcia:** Kryptografický hash — fingerprints, integrity checks.

**Použitie:**

| Kontext | Vstup | Výstup |
|---------|-------|--------|
| Key fingerprint | `signing_pk \|\| encryption_pk` (64 B) | 256-bit hash (64 hex znakov) |
| `payload_hash` | `payload` blob (celý šifrovaný objekt) | Bitwise integrity, nie semantic dedup |
| `state_hash` | Sorted concat všetkých `object_id \|\| version \|\| SHA-256(payload)` | Rollback detection |
| Audit `encrypted_details` hash | `SHA-256(encrypted_details)` | Vstup do signed_data kanonizácie |
| Challenge hash | `SHA-256(challenge \|\| username)` | `spent_challenges` identifikátor |
| Token hash | `SHA-256(token)` | Uloženie invitation/provisioning tokenov |

**payload_hash sémantika:** `SHA-256(payload)` je **bitwise integrity check**. Dva rôzne encryptie rovnakého plaintextu majú rôzny hash (kvôli random nonce). Toto je zámer — umožňuje idempotentný retry (rovnaký blob = rovnaký hash).

### 1.8 HMAC-SHA256

**Použitie:**

| Kontext | Key | Message | Účel |
|---------|-----|---------|------|
| `auth_proof_hash` | `verify_salt` (32 B, server-only) | `auth_proof` (32 B, Argon2id output) | Password-based recovery overenie |
| Fake salt | `server_secret` | `username` | User enumeration ochrana na `/api/meta` |
| IP/UA anonymizácia | `server_secret` | IP adresa / User-Agent | Privacy v `share_views` |

**Prečo HMAC-SHA256 pre auth_proof_hash:**
`auth_proof` je už 32-bajtový high-entropy Argon2id output. Druhý Argon2id by bol:
1. Zbytočne drahý (každý recovery request = 256 MB + 1s na serveri)
2. DoS vektor (útočník posiela falošné requesty, server alokuje 256 MB na každý)

HMAC-SHA256 je dostatočný — vstup má plnú entropiu.

---

## 2. Ciphertext Envelope Format

### 2.1 Štruktúra

Každý šifrovaný blob v Sezame má štandardizovaný formát:

```
Offset  Dĺžka  Pole            Popis
─────────────────────────────────────────────────────────
  0      1     alg             1 = xchacha20poly1305_ietf
  1      1     schema_version  Verzia formátu (aktuálne 1)
  2      1     blob_kind       Typ obsahu (1-7)
  3      26    dek_id          ULID referencujúci DEK použitý na šifrovanie
  29     24    nonce           os.urandom(24)
  53     var   ciphertext      Šifrovaný obsah
  -16    16    tag             Poly1305 MAC (posledných 16B ciphertext blobu)
─────────────────────────────────────────────────────────
Header: 53 bajtov (plain text, ale autentifikovaný cez AAD)
```

### 2.2 blob_kind hodnoty

| Hodnota | Názov | Obsah plaintextu |
|---------|-------|------------------|
| 1 | `node_meta` | `{name, tier, sync_flag, created_at, modified_at}` |
| 2 | `entry_meta` | `{name, tier, created_at, modified_at}` |
| 3 | `entry_data` | `{fields: [{key, value, sensitive, sort_order, field_type}]}` |
| 4 | `history_snapshot` | Snapshot entry v čase zmeny |
| 5 | `audit_details` | `{target_path, context}` — šifrované Audit DEK-om |
| 6 | `dek_wrap` | DEK zabalený iným DEK-om (dek_archive chain) |
| 7 | `keypair_wrap` | `signing_sk + encryption_sk` zabalený KEK-om |

### 2.3 Padding

Pred šifrovaním sa plaintext padduje:

```python
def pad(data: bytes) -> bytes:
    min_padded = max(len(data) + 2, 32)  # minimum 32 bajtov
    # Zaokrúhlenie na najbližšiu mocninu 2
    target = 1
    while target < min_padded:
        target <<= 1
    padding_len = target - len(data) - 2
    padding_bytes = os.urandom(padding_len)  # RANDOM, nie zero!
    return struct.pack('>H', padding_len) + padding_bytes + data
```

```
Padded plaintext formát:
┌──────────────────┬──────────────────┬──────────────────┐
│ padding_len (2B) │ random padding   │ actual_data      │
│ u16 big-endian   │ (os.urandom)     │                  │
└──────────────────┴──────────────────┴──────────────────┘
```

**Prečo padding:**
- Maskuje veľkosť plaintextu (útočník nevie rozlíšiť krátke heslo od dlhého SSH kľúča)
- Random bytes (nie nuly) — zabraňuje pattern detection
- Opt-out s varovaním — niektorým deploymentom je veľkosť blobov dôležitá

### 2.4 Hex príklad

Kompletný envelope pre node_meta blob:

```
HEADER (53 bytes):
01                          alg = xchacha20poly1305_ietf
01                          schema_version = 1
01                          blob_kind = node_meta
01HXYZ123456789ABCDEFGHIJ   dek_id (26B ULID)
a7b3c4d5e6f7...             nonce (24B random)

AEAD OUTPUT (variable):
8f2a3b4c5d6e7f...           ciphertext (padded plaintext)
...
1a2b3c4d5e6f7a8b9c0d1e2f   tag (16B Poly1305 MAC)
```

Dešifrovanie:
```python
# Parsovanie headeru
alg = envelope[0]                    # 1
schema_version = envelope[1]          # 1
blob_kind = envelope[2]               # 1 (node_meta)
dek_id = envelope[3:29]              # 26B ULID
nonce = envelope[29:53]              # 24B

# AAD construction (object_id a version z DB, NIE z envelope)
aad = bytes([alg, schema_version, blob_kind]) + dek_id + object_id + struct.pack('>I', version)
# aad je 59 bajtov

# Dešifrovanie
ciphertext_with_tag = envelope[53:]
padded_plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
    ciphertext_with_tag, aad, nonce, dek
)

# Unpadding
padding_len = struct.unpack('>H', padded_plaintext[:2])[0]
actual_data = padded_plaintext[2 + padding_len:]
# actual_data = JSON bytes
```

---

## 3. AAD Construction

### 3.1 Formát

AAD (Additional Authenticated Data) je 59-bajtový fixed-length reťazec:

```
Offset  Dĺžka  Pole            Typ      Hodnota
─────────────────────────────────────────────────
  0      1     alg             u8       1 (xchacha20poly1305_ietf)
  1      1     schema_version  u8       1
  2      1     blob_kind       u8       1-7
  3      26    dek_id          bytes    ULID použitého DEK-u
  29     26    object_id       bytes    ULID záznamu (z DB, nie z envelope!)
  55     4     version         u32be    Per-object version counter
─────────────────────────────────────────────────
Total: 59 bytes (fixed length = žiadna ambiguita pri konkatenácii)
```

### 3.2 Implementácia

```python
def build_aad(alg: int, schema_version: int, blob_kind: int,
              dek_id: bytes, object_id: bytes, version: int) -> bytes:
    """
    Postaví AAD pre AEAD šifrovanie.
    Všetky polia sú fixed-length -> žiadna ambiguita.
    """
    assert len(dek_id) == 26, "dek_id musí byť 26B ULID"
    assert len(object_id) == 26, "object_id musí byť 26B ULID"
    assert 1 <= blob_kind <= 7, "blob_kind mimo rozsahu"

    return (
        bytes([alg, schema_version, blob_kind])  # 3B
        + dek_id                                  # 26B
        + object_id                               # 26B
        + struct.pack('>I', version)              # 4B
    )  # Total: 59B
```

### 3.3 Čo každé pole chráni

| Pole | Zabraňuje |
|------|-----------|
| `alg` | Downgrade útok na slabší algoritmus |
| `schema_version` | Zmiešanie formátov medzi verziami |
| `blob_kind` | **Swap útok** — prehodenie node_meta blobu za entry_data blob. Bez blob_kind by útočník mohol zameniť blob typu 1 za blob typu 3 a dešifrovanie by uspelo (rovnaký DEK). S AAD: zmena blob_kind zneplatní tag. |
| `dek_id` | Priradenie blobu k inému DEK-u (cross-folder swap) |
| `object_id` | Priradenie blobu k inému záznamu (entry/node identity theft). **Dôležité:** object_id sa berie z **primárneho kľúča záznamu v lokálnej SQLite tabuľke**, nie z envelope headeru (kde nie je uložený). Implementátor musí object_id vždy poskytnúť z DB kontextu. |
| `version` | Rollback na staršiu verziu záznamu. Ak útočník nahradí nový blob starším, AAD version nesedí s DB version --> tag verification FAILS. |

### 3.4 Špeciálne prípady AAD

**Share blob AAD:**
```
alg(1B) || schema_version(1B) || blob_kind=3(1B) || raw_share_id(32B) || u32be(1)
```
Share používa `raw_share_id` (256-bit binary pred base64url encoding) namiesto `dek_id + object_id`. Version je vždy 1 (write-once).

**dek_archive AAD:**
```
alg(1B) || schema_version(1B) || blob_kind=6(1B) || dek_id(26B) || archive_id(26B) || u32be(version)
```
`dek_id` = nový DEK (replaced_by), `archive_id` = ID záznamu v dek_archive tabuľke. Viaže starý DEK k novému — útočník nemôže zameniť chain.

---

## 4. KEK/DEK hierarchia

### 4.1 Kompletný flow

```
Master Password (UTF-8)
        |
        v
   Argon2id(password, argon2_salt, time=3, mem=256MB, par=4)
        |
        v
   Root KEK (256-bit)
        |
        +-- AEAD_decrypt(encrypted_dek, KEK) --> Root DEK (scope='root')
        |       |
        |       +-- šifruje encrypted_meta root uzla
        |       +-- šifruje encrypted_meta top-level uzlov (foldery priamo pod root)
        |
        +-- AEAD_decrypt(encrypted_dek, KEK) --> Folder DEK "servers" (scope='folder')
        |       |
        |       +-- šifruje encrypted_meta a encrypted_data entries v servers/
        |       +-- šifruje encrypted_meta child-uzlov v servers/
        |
        +-- AEAD_decrypt(encrypted_dek, KEK) --> Folder DEK "financial" (scope='folder')
        |       |
        |       +-- šifruje encrypted_meta a encrypted_data entries v financial/
        |
        +-- AEAD_decrypt(encrypted_dek, KEK) --> Tier2 DEK (scope='tier2')
        |       |
        |       +-- šifruje entries s tier=2 (MCP agent nemá tento DEK)
        |
        +-- AEAD_decrypt(encrypted_dek, KEK) --> Audit DEK (scope='audit')
        |       |
        |       +-- šifruje audit log detaily (ODDELENÝ od content DEK-ov)
        |       +-- verzovaný NEZÁVISLE od master password lifecycle
        |
        +-- AEAD_decrypt(encrypted_keypair, KEK) --> signing_sk + encryption_sk
                |
                +-- Ed25519 signing_sk pre auth + audit podpisy
                +-- X25519 encryption_sk pre crypto_box dešifrovanie obálok
```

### 4.2 Pravidlá

1. **Root KEK** odomkne DEK-y. **Nikdy nešifruje dáta priamo.**
2. **Root DEK** (`scope='root'`) šifruje `encrypted_meta` root uzla a top-level folderov.
3. **Granularita DEK: per-folder.** `encrypted_meta` uzla je šifrovaný DEK-om jeho rodičovského folderu. Web user dešifruje len uzly, ku ktorým má obálku.
4. **Tier 2 entries** majú **samostatný DEK** — MCP agent k nemu fyzicky nemá prístup.
5. **Audit DEK** je náhodne vygenerovaný, zabalený KEK-om, **verzovaný nezávisle**. Zmena master hesla nemá vplyv na audit chain.
6. `deks.encrypted_dek` je **VŽDY NOT NULL** (KEK-wrapped). Obálky (`access_envelopes`) sú **DODATOČNÉ** prístupové cesty pre kolegov, nie náhrada KEK wrapu.

### 4.3 DEK wrapping

```python
# Generovanie nového DEK
dek_raw = os.urandom(32)  # 256-bit náhodný kľúč
dek_id = generate_ulid()

# Zabalenie KEK-om (AEAD)
nonce = os.urandom(24)
aad = build_aad(alg=1, schema_version=1, blob_kind=6, dek_id=dek_id, object_id=dek_id, version=1)
encrypted_dek = crypto_aead_xchacha20poly1305_ietf_encrypt(
    message=pad(dek_raw),
    aad=aad,
    nonce=nonce,
    key=kek
)
# Uloženie do deks tabuľky
```

### 4.4 DEK archive (chain wrapping)

Pri re-key operácii sa starý DEK archivuje a zabalí NOVÝM DEK-om (nie KEK-om):

```
Časová os:
  DEK_v1 (pôvodný) --> DEK_v2 (po prvý re-key) --> DEK_v3 (po druhý re-key)

Chain:
  dek_archive: DEK_v1 zabalený DEK_v2 (AEAD, blob_kind=6)
  dek_archive: DEK_v2 zabalený DEK_v3 (AEAD, blob_kind=6)
  deks:        DEK_v3 zabalený KEK-om (aktuálne aktívny)

Dešifrovanie historických entries:
  KEK --> DEK_v3 --> DEK_v2 (z archive) --> DEK_v1 (z archive) --> staré dáta
```

**Bezpečnostná vlastnosť:** Ktokoľvek s prístupom k aktuálnemu DEK (cez obálku) vie spätne dešifrovať celý chain. Revokovaný user nemá obálku pre nový DEK --> nemá prístup k chain-u.

**GC pravidlo:** `dek_archive` záznam sa maže LEN ak sa mažú aj VŠETKY príslušné `entry_history` záznamy. Nikdy nemažeš dek_archive bez mazania history.

### 4.5 Generácia trezoru medzi procesmi (review a159e97 H10)

GUI alebo `mcp-serve` ostávajú odomknuté s tým, čo načítali pri odomknutí: KEK, keypair, `user_id`,
`key_epoch` a server. Keď to iný proces zmení (zmena hesla, `connect`/rebind, recovery, prevzatie
epochy, iný server), starý proces predtým ďalej balil DEK pod mŕtvy KEK, podpisoval audit pod
neexistujúce id alebo synchronizoval so starým serverom.

`vault_meta.vault_generation` dostane nové ULID v tej istej transakcii pri každej skutočnej zmene
kľúčov `kek_dek_id`, `argon2_salt`, `argon2_params`, `encrypted_keypair`, `signing_pk`,
`encryption_pk`, `user_id`, `key_epoch`, `server_url` (`VaultDB.set_meta`, `GENERATION_KEYS`
v `src/sezam/vault/db.py`). Proces si generáciu pripne pri otvorení a odomknutí a prijme len ňu
a tie, ktoré sám zapísal. Generácia nie je počítadlo, takže zmena, ktorú vlastná transakcia vrátila
(rollback), nikdy nesplynie so zmenou iného procesu. Pri inej generácii (`VaultChangedElsewhere`;
podtriedy `KeyChangedElsewhere` a `IdentityChangedElsewhere`) proces nezabalí DEK
(`DEKManager._wrapping_kek_id`), nezapíše audit (`Vault._require_current_identity`),
nespustí pull/push/full resync (`SyncClient._require_current_kek`) a nezmení ani tieto kľúče.
Pomôže zamknúť a odomknúť. Test: `tests/test_vault_generation.py`. Web a mobil majú na trezor jeden
proces.

---

## 5. Envelope Encryption (multi-user)

### 5.1 Pridelenie prístupu

```python
# Admin zdieľa priečinok "clients" s Jankom

# 1. Admin dešifruje folder DEK
folder_dek = decrypt_dek(dek_id="01HXYZ...", kek=admin_kek)

# 2. Admin vytvorí obálku pre Janka
envelope_id = generate_ulid()
nonce = os.urandom(24)

# crypto_box: authenticated encryption
#   sender = admin (encryption_sk)
#   recipient = Janko (encryption_pk)
encrypted_dek_for_janko = crypto_box(
    message=folder_dek,
    nonce=nonce,
    pk=janko_encryption_pk,    # Jankov verejný šifrovací kľúč
    sk=admin_encryption_sk     # Adminov privátny šifrovací kľúč
)

# 3. Uloženie obálky
INSERT INTO access_envelopes (
    id=envelope_id,
    dek_id="01HXYZ...",
    user_id=janko_user_id,
    created_by=admin_user_id,      # potrebné pre crypto_box dešifrovanie
    access_level='write',          # 'read' alebo 'write'
    encrypted_dek=nonce + encrypted_dek_for_janko  # nonce prepended
)
```

**Desktop:** `sezam grant-access <user_id> <priečinok> [--write]` alebo Tím → *Share Folder…*
(`grant_member` v `src/sezam/vault/revocation.py`). Člen musí byť schválený (`active`), obálka
sa zapečatí pre jeho šifrovací kľúč pripnutý (TOFU) spolu s podpisovým kľúčom a odíde hneď
pushom. Zdieľa sa len vlastný DEK priečinka (`folder`/`root`), nikdy osobný, tier-2 ani auditný
a ani DEK, ktorý si podpriečinok len požičal od rodiča. Obálku, ktorú server odmietne, desktop
lokálne stiahne; pri výpadku siete ostane a odíde s ďalším pushom.

**Odtlačok člena pri prvom zdieľaní (review 688edcb, nízke).** Pripnutý kľúč je pri prvom kontakte
len to, čo povedal server. Kým admin odtlačok člena nepotvrdí, nič sa nezapečatí
(`MemberKeyUnconfirmed`): CLI ho vypíše a pýta sa (alebo porovná `--fingerprint <hex>`, medzery
a veľkosť písmen nevadia), GUI ukáže dialóg *Confirm Member Key*. Člen svoj odtlačok vidí cez
`sezam fingerprint` (web: hlavička, rovnaký SHA-256(signing_pk ‖ encryption_pk)). Potvrdené
odtlačky sú v `vault_meta.confirmed_member_keys`; potvrdená zmena kľúča (`confirm_tofu_key_change`)
sa tam zapíše tiež, takže ďalšie zdieľanie sa už nepýta. Iný odtlačok (rotácia) sa pýta znova.
Nepotvrdený kľúč, ktorý zdieľanie práve pripol, sa zabudne (`SyncClient.unpin_member_key`; review 7c10379):
server, ktorý pri prvom zdieľaní podstrčil vlastný kľúč, ho inak nechal pripnutý a skutočný kľúč
člena potom zhodil každý pull tohto zariadenia ako zmenu kľúča. Stavový test:
`test_sync_state_machine_swapped_member_key` (pravidlo `server_swaps_a_member_key`).

### 5.2 Dešifrovanie obálky (Jankova strana)

```python
# Janko otvára priečinok "clients"
envelope = get_envelope(dek_id="01HXYZ...", user_id=janko_user_id)

# crypto_box_open: dešifrovanie + overenie autenticity
nonce = envelope.encrypted_dek[:24]
ciphertext = envelope.encrypted_dek[24:]

folder_dek = crypto_box_open(
    ciphertext=ciphertext,
    nonce=nonce,
    pk=admin_encryption_pk,        # Adminov verejný kľúč (z created_by)
    sk=janko_encryption_sk         # Jankov privátny kľúč
)
# folder_dek je teraz dostupný pre dešifrovanie entries v "clients"
```

### 5.3 Revokácia prístupu — povinný re-key

Celá operácia je jedna SQLite transakcia:

```sql
BEGIN TRANSACTION;

-- 1. Vygeneruj nový DEK
INSERT INTO deks (id='01NEW...', node_id=..., scope='folder',
                  encrypted_dek=AEAD(nový_dek, kek), version=1);

-- 2. Pre každý entry: dešifruj starým DEK, zašifruj novým DEK
UPDATE entries SET
    encrypted_data = AEAD_encrypt(plaintext, nový_dek, ...),
    encrypted_meta = AEAD_encrypt(meta, nový_dek, ...),
    dek_id = '01NEW...',
    version = version + 1
WHERE dek_id = '01OLD...';

-- 3. Archivuj starý DEK (zabalený NOVÝM DEK-om, nie KEK-om!)
INSERT INTO dek_archive (id=..., replaced_by='01NEW...',
    encrypted_dek=AEAD(starý_dek, nový_dek, blob_kind=6), ...);

-- 4. Vytvor NOVÉ obálky pre zostávajúcich userov
INSERT INTO access_envelopes (...)
    VALUES (...);  -- crypto_box(nový_dek, recipient_pk, admin_sk) pre každého okrem Janka

-- 5. Vymaž Jankovu starú obálku (tombstone)
UPDATE access_envelopes SET is_deleted=1
    WHERE dek_id = '01OLD...' AND user_id = janko_id;

COMMIT;
```

**Re-key je VŽDY admin-only operácia** (len admin má KEK --> oba DEK-y).

**Komu re-key dá nový kľúč (review 7c10379 H2).** Nový DEK sa zapečatí len držiteľovi obálky, ktorú vytvoril tento účet (`created_by` je overený podpisovateľ obálky), alebo členovi, ktorého fingerprint tento admin potvrdil mimo servera (`confirmed_member_keys`). Platí to pre re-key aj pre jeho rebase (`reseal_key_row` v `sync_common.py`). Predtým dostal nový kľúč každý držiteľ obálky pod starým kľúčom, aj účet „Eve“, ktorý vyrobil server a ktorý si obálku podpísal sám. Člen, ktorému prístup dal iný admin a ktorého fingerprint tu nie je potvrdený, po re-key prístup stratí (varovanie v logu); obnoví ho nové zdieľanie s potvrdením fingerprintu.

**Poradie pri odobratí člena** (`sezam revoke-user`, tím v desktop GUI, `src/sezam/vault/revocation.py`):
1. `DELETE /api/users/:id` — server člena odstaví hneď (nečaká na re-key).
2. Lokálny re-key (vyššie) a push ako atomický batch.
3. Ak push zlyhá (sieť, konflikt), re-key ostane v `pending_rekey_batch` a odíde s ďalším `sezam push`; príkaz skončí chybou s touto informáciou.
4. Naraz môže čakať len jeden re-key batch. Ak čaká re-key predchádzajúceho člena, ďalší odobratý člen sa zaradí do `queued_revocations` (review 688edcb #8b). Jeho priečinky sa pre-kľúčujú hneď, keď predchádzajúci batch dorazí na server: v tom istom príkaze, alebo pri ďalšom `sezam push` (`finish_queued_revocations`). Člen odíde z fronty, až keď server jeho batch prijme. Predtým sa takýto člen na serveri odobral, ale jeho priečinky sa nikdy nepre-kľúčovali, hoci hláška tvrdila opak. Teraz hláška povie, že priečinky ešte nie sú pre-kľúčované. Člen vo fronte je odobratý aj pre všetky cesty, ktoré pečatia kľúč (re-key iného člena, rebase, `abandon-rekey`, opätovné pridelenie na nástupcu kľúča, `reseal_key_row` cez `queued_for_removal`): nový kľúč nedostane, nech server o ňom tvrdí čokoľvek. Commit c494af0 túto výnimku pre re-key zrušil a spoliehal sa na to, že server obálku pre odobratého člena odmietne (review a159e97; test `tests/test_review8_rekey_skips_queued_revocation.py`). Keď dve zariadenia toho istého účtu prekľúčovali ten istý priečinok, starý kľúč balia dva archívy; `successor_of` predtým vrátil prvý riadok `dek_archive` v poradí pullu, takže zariadenia sa nezhodli a opätovné pridelenie na nástupcu mohlo skončiť na kľúči, ktorý žiadny priečinok nepoužíva. Teraz vyhrá nástupca, ktorého reťaz vedie ku kľúču, ktorý priečinok používa, potom najnižšie id (test `tests/test_review8_two_rekeys_one_successor.py`).

Web drží re-key v šifrovanom journale v IndexedDB (`pending_rekey:<admin>:<člen>`), nie medzi bežnými neodoslanými zmenami. Tlačidlo Retry v paneli konfliktov ho pošle najprv ako jeden atomický batch (`atomic_batch: true`) a ostatné zmeny až potom. Odobratie potom dokončí (`DELETE /api/users/:id`, 404 = už odobratý inde). Keď server batch odmietne (409, objekt sa medzitým zmenil), web ho ako desktop postaví znova zo stavu servera (`finishWebRevocation`, review 688edcb M5) a pošle raz. Predtým Retry posielal ten istý batch donekonečna. Sieťová chyba batch nemení. Ak server odmietne aj nový batch, nepošle sa nič ďalšie a journal ostane.

Zmena hesla na inom zariadení (review 688edcb, web #4): záznamy zapečatené starým KEK sa pri prihlásení odložia pod `stale_kek:<čas>:<pôvodné id>`. Keypair zo servera nahradí ten v cache prehliadača až potom (review d615826 H7). Predtým sa uložil hneď. Prihlásenie prerušené medzi tým nechalo cache, ktorú nové heslo otvorí, takže ďalšie prihlásenie zmenu hesla nespoznalo, staré záznamy neodložilo a ich kontrolný bod zablokoval prehliadač natrvalo (test `tests/test_review6_web_interrupted_first_login.py`). To isté platí pre prihlásenie so súborom `.sezam-key` (review 7c10379, R7-H): záloha exportovaná po zmene hesla predtým nahradila cache hneď a nič neodložila, takže neodoslané zmeny zapečatené starým heslom zablokovali toto aj každé ďalšie prihlásenie („Invalid encrypted dirty state“). Teraz sa najprv odložia a až potom záloha nahradí cache (test `tests/test_review7_web_backup_import_old_kek.py`). Pri každom prihlásení sa potom odložené záznamy prečítajú znova:
- **Odložený re-key journal:** odobratie sa dokončí bez starého hesla. Člen je v id záznamu a batch sa postaví zo stavu servera. Starý batch sa neposiela, lebo jeho DEK sú zabalené starým KEK. Kým sa to nepodarí (napr. chýba admin), záznam ostane a prihlásenie to oznámi. Ďalšie prihlásenie môže prísť aj o niekoľko dní, preto sa každé odobratie najprv znova potvrdí (`sync.set_aside_revocation_confirm`, s menom člena z `/api/users`). Zrušenie odobratie zahodí a člen ostane; odobrať ho možno znova v správe používateľov (review e4cd15a, nízke). Predtým sa odobratie dokončilo bez opýtania.
- **Odložené neodoslané zmeny:** pruh ponúkne obnovu predchádzajúcim heslom. Záznam nesie verejný `kdf` (salt a parametre Argon2), s ktorým bol KEK odvodený. Nový DEK medzi zmenami sa prebalí aktuálnym KEK a znova podpíše. Zmena toho istého objektu z aktuálnej relácie má prednosť. Zmeny potom odídu cez Retry, kolízie sa ukážu ako bežné konflikty. Záznam bez `kdf` (zo staršej verzie) už neotvorí žiadne heslo a pruh to povie. Zahodenie vyžaduje potvrdenie. Záznamy sa obnovujú od najnovšieho (`restoreAllSetAsideWebChanges`), takže objekt z novšieho záznamu je už vo fronte a starší ho neprepíše; záznam, ktorý heslo neotvorí, zdrží len staršie záznamy, novšie sa obnovia. Každý záznam sa zahadzuje samostatne (review 4acfdde R11; predtým obnova od najstaršieho vrátila staršiu verziu úpravy, jedno zabudnuté heslo zastavilo všetky novšie a zahodenie zmazalo všetko).

Testy: `tests/test_web_set_aside_records_272.py`.

**Zastaraná karta (review 8595ec1 #5).** Karta otvorená pred zmenou hesla (v inej karte toho istého prehliadača, alebo prihlásením v nej, ktoré prevzalo zmenu z iného zariadenia) má v pamäti starý KEK. Keď niečo uložila, zapečatila ním celý front, hoci cache už otvára nové heslo: ďalšie prihlásenie nič neodložilo a padalo na „Invalid encrypted dirty state“ natrvalo, staré heslo bolo „wrong password“. Teraz:
- `saveWebDirtyState` najprv overí, že KEK karty otvára keypair v cache (`webKekIsCurrent`). Ak nie, front karty uloží bokom pod `stale_kek:` (so starým `kdf`, pruh ho obnoví predchádzajúcim heslom), kartu zamkne (`sync.stale_tab`) a nič neodošle.
- Živý front, ktorý KEK karty neotvorí, sa neprepíše, ale odloží.
- Každé prihlásenie (nielen po zmene kľúča) odloží front a re-key journaly, ktoré jeho KEK neotvorí; checkpoint len pri zmene kľúča. Pull pri nečitateľnom fronte urobí to isté namiesto chyby.
- Karta, ktorá uloží keypair do cache, to oznámi ostatným (`BroadcastChannel('sezam-keypair')`); karta toho účtu, ktorej KEK ho neotvorí, sa hneď zamkne (`onWebKeypairChanged`).

Test `tests/test_review10_web_stale_tab.py` (4 testy, na 8595ec1 zlyhajú; prvý presne na „Invalid encrypted dirty state“).

### 5.4 Public key autentickosť — TOFU

Trust On First Use:

1. Pri pridávaní kolegu admin overí fingerprint v GUI (osobne/telefonicky).
2. Klient ukladá `{user_id: (signing_pk, encryption_pk, fingerprint)}` lokálne v `known_keys`.
3. Pri pull overuje, že server kľúče sa nezmenili. Ak sa zmenili --> GUI varovanie (MITM detection).
4. Cache eliminuje závislosť na serveri pre crypto_box dešifrovanie obálok.

**Fingerprint:** `SHA-256(signing_pk || encryption_pk)` — 256-bit, zobrazený ako:
- Vizuálny: identicon/wavatar — drastická vizuálna zmena pri MITM
- Slovný: 4 BIP39-style slová (44 bitov, 1:17.6 bilióna kolízia) — pre TOFU onboarding
- Plný hex: 64 znakov — pre plnú verifikáciu

### 5.5 Podpísaný tímový denník (team log)

Kto je členom, kto smie do ktorého priečinka zapisovať a ktorý kľúč priečinka je aktuálny, už
neurčuje server (`/api/users`, `is_admin`, `write_acl`, poradie kľúčov), ale podpísaný denník
organizácie. Návrh a formát: `docs/DESIGN_TEAM_LOG.md`.

- **Záznamy:** `genesis`, `member.add`/`member.role`/`member.remove`/`member.keys`, `access.set`
  (read/write/žiadny), `folder.key` (generácia N+1 s odkazom na predchádzajúci `dek_id`). Každý
  záznam podpíše admin (Ed25519) a odkazuje na hash predchádzajúceho. Server pridá záznam len na
  aktuálnu hlavu (CAS na `prev`), overí ho tým istým jadrom (`src/sezam/teamlog.py`) a z prehratia
  odvodí `write_acl`, `is_admin` a `status`.
- **Jadro a vektory:** Python `src/sezam/teamlog.py`, web `web/static/js/teamlog.js`, mobil
  `mobile/lib/services/team_log.dart`. Všetky tri prechádzajú tými istými rozhodovacími vektormi
  (`tests/team_log_vectors.py` → JSON; `may_write`, `key_recipients`, `current_key`,
  `key_generation`, `item_refusal`, `move_refusal`, …).
- **Klienti:** denník si držia lokálne, pri každom pulle ho stiahnu od pripnutej hlavy. Kratší,
  rozvetvený alebo iný (iná genesis) denník pull preruší a hlava je v šifrovanom sync checkpointe.
  Pripojenie, zdieľanie, odobratie a re-key pridajú záznamy v tom istom atomickom pushi ako obálky.
  Re-key zapečatí nový kľúč presne členom, ktorým denník dáva prístup k priečinku, a na ich úrovni.
  Aktuálny kľúč priečinka je len najvyššia generácia v denníku. Starší sa len číta, neznámy sa
  nepoužije.
- **Migrácia existujúcej organizácie:** `sezam team-log init` (admin): genesis tohto admina,
  `member.add` pre každý schválený účet s potvrdeným odtlačkom, `folder.key` gen 0 a `access.set` podľa
  dnešných obálok, všetko v jednom pridaní. Členovia potvrdia odtlačok zakladateľa
  (`sezam team-log confirm-founder`). Neskôr pridaný člen: `sezam team-log add-member`.
  Stav: `sezam team-log status`.
- **Jeden admin na organizáciu (TL7):** server odmietne pridanie, po ktorom by mal denník dvoch
  aktívnych adminov. Rolu možno odovzdať (`member.role` nový admin aj starý → `member`, v jednom
  pridaní). Zakladateľ je jediný admin.
- **Osobný koreň (TL7):** osobný priečinok člena je uzol najvyššej úrovne (`parent_ref` NULL)
  zapečatený jeho vlastným kľúčom s `personal: true` v meta, nie podpriečinok koreňa organizácie.
  Server ho od člena prijme (`own_seal`); klienti ho za koreň účtu nikdy nevezmú a jeho autora
  nerátajú za admina. Kľúče v jeho strome idú bez `parent_ref`. Strom má jeden kľúč: podpriečinok
  berie kľúč rodiča (desktop, web aj mobil). Vlastný kľúč podpriečinka zo staršieho desktopu, ktorý
  server nemá, desktop pri odomknutí zloží do stromu (`fold_personal_tree_keys`: prepečatí položky,
  mená podpriečinkov a históriu kľúčom rodiča), inak by položky v ňom boli na ostatných zariadeniach
  nečitateľné.
- **Podpriečinok tímového priečinka (R15, #429):** pod tímovým priečinkom klienti aj server odmietnu,
  čo zapečatí kľúč, ktorý denník nepozná. Nový podpriečinok preto berie kľúč rodiča (desktop, web aj
  mobil) a prvé zdieľanie priečinka zapíše `folder.key` gen 0 aj pre podpriečinky s vlastným kľúčom,
  ktoré admin pozná (`unlogged_folder_keys`). Podpriečinok, ktorý iné zariadenie admina urobilo
  s vlastným kľúčom skôr, než stiahlo zdieľanie, to zariadenie pri ďalšom pushi zloží do kľúča
  rodiča ako presun do tímového priečinka (`fold_unlogged_folder_keys`: prepečatí položky, mená
  podpriečinkov a históriu); inak by každá položka v ňom ostala navždy neodoslaná. Starý kľúč sa do
  denníka nezapisuje: zariadenie, ktoré drží len zastaranú väzbu priečinka na kľúč, ktorým už nič
  nie je zapečatené, by tak z priečinka urobilo tímový pod mŕtvym kľúčom. Test
  `test_sync_state_machine_team_log_subfolder_made_before_the_grant_was_pulled`.
- **Tier-2 v zdieľanom priečinku (TL7):** tier-2 položka má vlastný kľúč mimo denníka, preto do
  tímového priečinka nepatrí: desktop ju tam nevytvorí, nezmení na tier 2, neupraví ani nepresunie
  (chyba s odkazom na samostatný priečinok — osobný koreň alebo nový tímový priečinok); presun von do
  osobného koreňa je povolený. Podrobne `docs/DESIGN_TEAM_LOG.md` §10.

---

## 6. Autentifikačný protokol

### 6.1 Challenge-Response (Ed25519)

```
Klient                                  Server
======                                  ======

1. POST /api/auth/challenge
   {username: "peter"}
   ─────────────────────────────────>

                                        2. Generuj challenge:
                                           challenge = os.urandom(32) + timestamp_u64be
                                           Ulož hash do spent_challenges

   <─────────────────────────────────
                                        3. Response:
                                           {challenge: base64(challenge)}

4. Klient odmietne challenge inej dĺžky ako 40 B, potom
   signature = Ed25519_sign(
       signing_sk,
       "sezam-auth-challenge-signature-v1" ‖ challenge
   )
   (doménový prefix: server nemôže dať klientovi podpísať ľubovoľné
   bajty, napr. sync objekt alebo AI politiku, pod zámienkou prihlásenia)

5. POST /api/auth/verify
   {username: "peter",
    challenge: base64(challenge),
    signature: base64(signature)}
   ─────────────────────────────────>

                                        6. Overenie:
                                           a) Ed25519_verify(signing_pk, prefix ‖ challenge, signature)
                                              (holá challenge len pre staršie klienty
                                               do 2027-05-01, potom 426 „aktualizuj
                                               aplikáciu“, nie 401; každé prijatie
                                               aj odmietnutie zapíše WARNING s ID kľúča;
                                               SEZAM_LEGACY_BARE_SIGNATURE_UNTIL mení dátum)
                                           b) timestamp < 30s starý (replay protection)
                                           c) SHA-256(challenge||username) NOT IN spent_challenges
                                           d) Označ challenge ako "spent"
                                           e) users.status == 'active'

   <─────────────────────────────────
                                        7. Response:
                                           {token: JWT(EdDSA, 1h expiry),
                                            refresh_token: ...}
```

### 6.2 JWT

| Parameter | Hodnota |
|-----------|---------|
| Algorithm | `EdDSA` (`crv=Ed25519`) |
| Server signing key | Ed25519 pár generovaný pri prvom štarte, v config/env |
| Expiry | 1h (access), refresh cez podpísaný challenge |
| Invalidácia | `revoked_tokens` tabuľka |
| Rotácia | Manuálna (admin restart). Staré JWT s predchádzajúcim kľúčom sú automaticky neplatné. |
| Viazanie na DB | Podpisový kľúč = HMAC-SHA256(kľúč z `jwt_key.bin`, `"sezam jwt key of database\0"` ‖ `server_instance.instance_id`), náhodné id databázy vzniká v `create_schema` (review 7c10379). Zmazaná alebo nová DB pri ponechanom súbore tak odmietne všetky JWT starej DB vrátane odvolaných (predtým znova platili). Obnova DB zo zálohy id zachová: JWT odvolané po zálohe platia do expirácie (najviac 1 h). Po nasadení sa každé zariadenie raz prihlási znova (401 `token_invalid`). |

### 6.3 Onboarding JWT

Pri registrácii (`POST /api/users/register`):
- Server vydá **onboarding JWT** (15 min TTL, scope: len `PUT /api/me/keypair`)
- Nemôže byť použitý na sync, share ani iné operácie
- Po uploade keypair je spotrebovaný

**Medzery okolo mena (lockout review N3).** Server berie `username` bez medzier na začiatku a konci (typ `Username` v `schemas.py`, aj `/api/meta?username=`) pri bootstrape, registrácii, challenge/verify, recover aj provisioningu. „ alice“ je teda účet „alice“, nevznikne druhý účet a prihlásenie nezlyhá na falošnom salte. Meno zložené len z medzier dostane 422. Klienti posielajú orezané meno: desktop pri zadaní v CLI aj pri čítaní mena zo staršieho trezoru (`_get_username`, reseed), web pri prihlásení aj onboardingu, mobil v každej verejnej metóde `AuthService` (`normalizeUsername`). Účty uložené s medzerami z obdobia pred touto opravou server pri migrácii schémy raz premenuje (`trim_stored_usernames`).

**Jeden tvar mena na všetkých klientoch (review 688edcb N3).** Každý jazyk orezáva inak (Python nechá BOM, JS/Dart ho zrežú; MariaDB `[[:space:]]` nevidí NBSP) a nikto nenormalizoval Unicode. Server (`schemas.normalize_username`), desktop (`sezam.usernames`), web (`normalizeUsername` v `app.js`) aj mobil (`normalizeUsername` v `auth_service.dart`) preto počítajú to isté: NFC a orezanie zjednotenia všetkých bielych znakov (`\s`, BOM, NEL, `\x1c`–`\x1f`, zero-width space) na okrajoch. NBSP vo vnútri mena ostáva. NFD „Šimon“ je teda ten istý účet ako NFC „Šimon“ (registrácia druhého dostane 409) a podpis reseed pokrýva rovnaké bajty na klientovi aj serveri. Migrácia filtruje mená v Pythone, nie cez SQL REGEXP. Ak je normalizované meno už obsadené, starý účet dostane `meno-2` (`-3`, …), aby bol dosiahnuteľný; log zapíše, pod akým menom sa jeho používateľ odteraz prihlasuje. Staré meno si účet pamätá v `users.renamed_from` (review e4cd15a, nízke): zariadenie, ktoré sa prihlási starým menom a podpíše challenge kľúčom premenovaného účtu, dostane na `/api/auth/verify` token premenovaného účtu a v odpovedi pole `username` s aktuálnym menom. Desktop ho uloží do `vault_meta`, mobil do `SharedPreferences`, web ho drží v relácii. Staré meno tak neotvorí nič iné ako účet, ktorého kľúč podpísal; prihlásenie kľúčom účtu, ktorému meno teraz patrí, ide na ten účet ako doteraz. Predtým každé prihlásenie zariadenia so starým menom skončilo 401, kým ho používateľ ručne nezmenil. Ak iné zariadenie premenovaného účtu medzitým rotovalo identity kľúč (review 526419e N8), podpis certifikovaným vyradeným kľúčom účtu dostane 409 s `detail = {"error": "Identity key rotated", "username": <aktuálne meno>}` (predtým 401). Desktop aj mobil meno uložia ešte pred prevzatím nového keypairu heslom, takže `/api/meta` a `/api/auth/recover` idú na premenovaný účet, nie na účet, ktorému staré meno teraz patrí. Cudzí kľúč pod starým menom dostane naďalej 401 bez mena.

### 6.4 Rate limiting

| Endpoint | Limit |
|----------|-------|
| `/api/auth/challenge` | 10/min per IP |
| `/api/auth/recover` | 10 zlých proofov/h per adresa (IPv4 adresa, IPv6 /64; akékoľvek meno): ďalšie zlé proofy dostanú 429, správny proof z tej adresy prejde (jedna NAT/proxy nevymkne celú firmu, review 688edcb V2). 10 zlých per username --> `recovery_locked=1`; zamknuté meno overí z každej siete (adresa/64 ako vyššie) najviac jeden proof za `SEZAM_RECOVERY_LOCKED_PROBE_SECONDS` (300 s), medzitým 429 + `Retry-After` bez overenia (aj pre správny proof; hláška odkáže na odomknutie adminom). Okno je per (meno, sieť) v `recovery_probe_slots`: útočník, ktorý si okno zoberie hneď, ako sa otvorí, drží len svoje, nie okno vlastníka z inej siete (capability review run 83; predtým jedno spoločné okno umožnilo jednou adresou natrvalo odmietať správne heslo). Navyše zo všetkých nedôveryhodných sietí spolu overí zamknuté meno najviac `SEZAM_RECOVERY_LOCKED_PROBES_PER_WINDOW` (3) proofov za okno (`recovery_name_rations`, ďalšie 429 bez overenia), takže hádanie nerastie s počtom sietí útočníka (capability review run 85: IPv6 /48 = 65 536 sietí). Menej útočiacich sietí ako 3 vlastníka z novej siete neodmietne; útočník s ≥3 sieťami, ktorý každé okno hneď zaplní, ho z cudzej siete odmieta (429 s odkazom na admina) – akýkoľvek strop overených pokusov sa dá zaplniť, preto vtedy prejde len vlastníkova sieť alebo jednorazový kód od admina. **Odomknutie adminom (review e4cd15a S2):** `POST /api/users/:id/unlock-recovery` (`sezam unlock-recovery <user-id>`; osamelý admin aj sám pre seba zo zariadenia, ktoré je ešte prihlásené) vynuluje počítadlá a vráti jednorazový kód (80 bitov, platný 24 h, v DB len SHA-256 v `users.recovery_unlock_hash`/`recovery_unlock_until`). `/recover` s `unlock_code` preskočí zdieľaný prídel zamknutého mena, okno vlastnej siete zostáva (uniknutý kód nedá neobmedzené hádanie); úspešná obnova kód zmaže. Desktop: `sezam connect URL --unlock-code KÓD`. Predtým odomknutie len vynulovalo počítadlá a útočník (10 pokusov z jednej adresy alebo 3 siete) meno hneď znova zamkol, takže vlastník z novej siete sa nedostal dnu a hláška 429 posielala osamelého admina „za adminom“. Archív kľúčového materiálu (`/api/me/key-material-archive`) overí pri zamknutom mene jeden proof za okno namiesto 423 (predtým cudzie hádanie cez `/recover` blokovalo vlastníkovi aj purge archívu pod uniknutým heslom). Vlastníkove siete (najviac 16, `users.recovery_trusted_nets`, HMAC adresy s počtom dní, keď bola sieť videná; plný zoznam zahodí najprv sieť nevidenú 180 dní, potom tú s najmenej dňami – predtým posledných 8, takže deň mobilných dát s novou /64 každých pár hodín vytlačil domácu aj firemnú sieť, review e4cd15a, nízke) čakať nemusia, kým samy nehádajú: sieť registrácie (`/api/users/register`) a bootstrapu, každého podpísaného prihlásenia zariadenia (`/api/auth/verify`) a každej úspešnej obnovy (capability review run 88; predtým len úspešná obnova, takže vlastník, ktorý sa prihlasoval len zariadením, nemal žiadnu). Podpísané prihlásenie dokazuje len identity kľúč, ktorý má aj jeho zlodej: sieť, ktorá pri zamknutom mene pošle 3 zlé proofy bez správneho medzi nimi, dôveru stratí (review 526419e N4: predtým už prvý, takže jediný preklep vlastníka doma počas útoku vzal domácej sieti dôveru a prídel útočníka ho potom odmietal aj doma; správny proof počítadlo vynuluje), a podpísané prihlásenie pri zamknutom mene žiadnu sieť nepridá (review e4cd15a, nízke). Správny proof zámok zruší; správny proof k ešte neschválenému účtu vráti 401 a nič nezapočíta (web čaká na schválenie cez challenge/verify, nie cez `/recover`). Desktop (CLI aj GUI) pri 423/429 ohlási zámok a neponúkne pozvánku („nemáš účet“) |
| Share PIN | 3 pokusy / 15 min / IP. 10 celkovo --> `is_locked=1` |
| Challenge timestamp | Max 30s starý |

---

## 7. Sync protokol

### 7.1 Model

Offline-first, explicitný push/pull. Lokálny vault je primárny. Delta sync (len zmenené objekty). Server-assigned `commit_seq` (monotónny counter).

**Desktop klient — moduly (review 6, R6-H).** `SyncClient` (`src/sezam/vault/sync_client.py`: prihlásenie, zmena kľúčov, org recovery, overovanie podpisov a TOFU, `_request`) skladá metódy z mixinov: `sync_push.py` (zber a odoslanie zmien), `sync_rekey.py` (dávky re-key po odobratí člena: uzavretie, rebase, prepečatenie), `sync_pull.py` (stiahnutie, overenie, poradie a väzba kľúčov), `sync_apply.py` (zápis jednotlivých stiahnutých objektov), `sync_resync.py` (full resync) a `sync_state.py` (checkpoint, kontrola rollbacku, base verzie). Konštanty, pomocné funkcie a výnimky sú v `sync_common.py`; `sync_client.py` ich re-exportuje (`__all__`), takže importy volajúcich sa nemenia. Rozdelenie je presun bez zmeny správania; `tests/test_review6_sync_client_split.py` stráži, že sa žiadny modul znovu nerozrastie nad 1 300 riadkov a že každá metóda je definovaná práve raz.

**Chybové kódy servera (review 6, R6-H).** Odmietnutia, podľa ktorých sa klient rozhoduje, nesú stály kód: odpoveď je `{"detail": ..., "code": ...}` (`server/app/errors.py`, výnimka `ApiError`; `detail` ostáva pre web a mobil bez zmeny). Kódy: `history_changed` (obnova zo zálohy, treba full resync), `stale_key_epoch`, `key_change_misses_deks`, `wrong_current_password`, `key_change_needs_proof` (zmena kľúčov bez aktuálneho hesla alebo admin key reset), `identity_rotation_needs_new_keys`, `atomic_batch_conflict`, `identity_key_rotated`, `token_invalid`, `token_revoked`; odmietnutý objekt v push odpovedi nesie `code` (`revoked_envelope`; `team_log_envelope` = obálka, ktorú tímový denník tomu účtu nedáva — desktop ju raz stiahne a nahlási, neposiela ju znova). Desktop klient dostane každú chybovú odpoveď ako `ServerError` (`status`, `code`, `detail`; text ostáva „Server error <status>: …“) a rozhoduje cez `server_error(exc, status, code)`, ktorá prejde aj reťazec `raise … from` — nie podľa slov v texte výnimky. Zoznam kódov je zrkadlený v `sync_common.py`; `tests/test_review6_server_error_codes.py` stráži zhodu oboch zoznamov a že desktop sa zariadi podľa kódu aj pri inom znení správ.

### 7.2 Push

```
POST /api/sync
{
    atomic_batch: false,     // true pre re-key operácie
    objects: [
        {
            id: "01HXYZ...",
            object_type: "entry",
            parent_ref: "01HPARENT...",
            target_user_id: null,
            version: 3,
            payload: base64(envelope_blob),
            payload_hash: SHA-256(payload),
            is_deleted: 0,
            signature: base64(ed25519_signature)
        },
        ...
    ]
}
```

**Client signature canonical form:**

```
signed_data = concat(
    id(26B)                          // ULID raw bytes
    || u8(len(object_type)) || object_type  // length-prefixed string
    || parent_ref_or_zero(26B)       // 26B of 0x00 if NULL
    || target_user_id_or_zero(26B)   // 26B of 0x00 if NULL
    || u8(is_deleted)                // 0 alebo 1
    || u32be(version)                // big-endian 4B
    || payload_hash(32B)             // SHA-256(payload)
)

signature = Ed25519_sign(signing_sk, signed_data)
```

**Podpis viaže server-visible metadata** — topológia a ACL sú chránené podpisom. Server ich nemôže podmeniť bez zneplatnenia podpisu.

**Súbežné úpravy (`base_version`, stavový test SM1):** server prijme zmenu priečinka alebo záznamu, len ak bola urobená nad kópiou, ktorú práve drží. Objekt nesie nepodpísané `base_version` = verzia servera, s ktorou bolo zariadenie naposledy v zhode; nesedí → konflikt. Predtým platilo „vyššia verzia vyhráva“ a každá lokálna úprava zvýši verziu o 1, takže zariadenie s dvoma offline úpravami (verzia +2) potichu prepísalo úpravu iného zariadenia (verzia +1). Klient bez `base_version` (staršia verzia) má pôvodné pravidlo. Desktop drží základ v `object_base_version` (triggery pri každom „čistom“ riadku; explicitne pri prijatí pushu, `conflicts resolve --keep local`, re-key rebase a ponechaných objektoch pri full resync). Odoslané verzie si pamätá v `object_sent_version`: keď sa odpoveď na push stratí a server už drží vlastný zápis zariadenia, nie je to konflikt — push aj pull naň stavajú ďalej. Keď iné zariadenie toho istého účtu urobilo re-key toho istého člena a tento batch sa zahodí (`abandon_pending_rekey`), úprava urobená po vlastnom re-key ide hore na jeho re-key pod jeho kľúčom, bez konfliktu. Mobil a web `base_version` zatiaľ neposielajú (platí pre ne pôvodné pravidlo).

**Ďalšie nálezy stavového testu (`tests/test_sync_state_machine.py`):**
- **SM2:** stiahnutý tombstone záznamu nesie svoj obsah aj do lokálneho riadku. Predtým si zariadenie v koši nechalo svoju staršiu kópiu, takže obnova z koša na ňom vrátila záznam spred poslednej úpravy iného zariadenia.
- **SM3:** `conflicts resolve --keep server` pri zmazanom priečinku, v ktorom je na tomto zariadení neodoslaná práca, priečinok vráti (`_revive_folders_of_unsent`), ako to robí pull. Predtým server prácu pod zmazaným priečinkom odmietal pri každom pushi bez konfliktu.
- **SM4:** full resync, ktorý ponechá neodoslanú zmenu objektu, čo sa na serveri medzitým zmenil (iný základ ako kópia servera), ju zapíše ako konflikt so serverovou kópiou. Predtým ostala ako obyčajná neodoslaná zmena, ktorú server navždy odmietal a žiadny pull konflikt neukázal.
- **SM5:** full resync zahodí len neodoslané zmazanie objektu, ktorý server mal a už nemá (GC). Záznam vytvorený a zmazaný offline (napr. spolu s priečinkom) server nikdy nemal; predtým ho resync zahodil a z koša zmizol na všetkých zariadeniach. Teraz ide ako tombstone a v koši ostane.
- **Review 7c10379 H1:** full resync nezníži verziu DEK a obalenie, ktoré KEK tohto účtu otvorí, nikdy nevymení za také, ktoré neotvorí (`_own_dek_wraps` / `_restore_own_dek_wraps` v `sync_resync.py`). Predtým resync nastavil všetky DEK na verziu 0 a prevzal hocijakú kópiu servera. Server, ktorý si nechal obalenia spred zmeny hesla (starý KEK, stará verzia, vtedy platne podpísané), ich poslal po falošnom rollbacku alebo 410 a trezor sa už neotvoril ani novým, ani starým heslom. Vlastný DEK, ktorý server vynechal, hoci ním je zapečatené, čo ostalo, sa ponechá. Ak server drží nižšiu verziu, push mu pošle lokálnu kópiu.
- **Review 7c10379 R7-G (stavový test, kľúč, ktorý zariadenie nemalo):** to isté klamstvo o DEK priečinka, ktorý zariadenie ešte nedržalo: prevzalo starú kópiu, ktorú jeho KEK neotvorí, checkpoint prešiel za aktuálnu kópiu a žiadny delta pull ju už nepriniesol — záznamy priečinka sa tam natrvalo neotvorili. DEK podpísaný týmto účtom (podpis overený), ktorý KEK zariadenia pri jeho `key_epoch` neotvorí, sa teraz zapíše do `vault_meta.stale_own_dek_wraps`; pull potom odmietne s odkazom na `sezam pull --full-resync` a `sezam status` stav ukáže (`stale_own_wraps`). Full resync s poctivým serverom kópiu nahradí a značku zruší. Test `test_sync_state_machine_full_resync_lies_about_a_new_key`.
- **Review 7c10379 R7-G (stavový test, zmena hesla po klamlivom full resyncu):** iné zariadenie zmenilo heslo, server potom tomuto odpovedal na full resync kópiami DEK spred zmeny; zariadenie si nechalo svoje (prebalené prevzatím, v starej verzii). Jeho vlastná zmena hesla ich prebalila na verziu, ktorú server už drží, a push padal pri každom pokuse na holom 409 `Atomic batch conflict` — pull pred opakovaním za checkpoint nič nepriniesol. Keď server po tomto pulle hlási pri každom odmietnutom DEK verziu aspoň takú, akú zmena posiela, push teraz odmietne s odkazom na `sezam pull --full-resync` (žurnál zmeny kópie servera prebalí, SM40). Test `test_sync_state_machine_password_change_after_a_lying_full_resync`.
- **Review 7c10379 H8:** re-key batch, ktorý server prijal so stratenou odpoveďou a ktorého kópie priniesol pull späť (od 956656b sú čisté), push uzavrie ako odoslaný hneď na začiatku (`close_rekey_if_landed`). Predtým každý push padal na „Atomic re-key batch is missing N local object(s)“.

**Limity jednej požiadavky** (`server/app/models/schemas.py`): najviac 1000 objektov, 1 MiB dekódovaného payloadu na objekt a 16 MiB na celú požiadavku. Nad limitom server odmietne celú požiadavku (422/413). Review 526419e #1: klienti preto push delia:
- **Bežný push** (desktop `SyncClient._push_once`, mobil `SyncService.push`) ide v po sebe idúcich dávkach (≤1000 objektov, ≤15 MiB, poradie zachované); každá prijatá dávka sa hneď označí ako odoslaná. Web posiela po jednom objekte.
- **Objekt nad 1 MiB** sa nepošle, ostane lokálne a vráti sa ako konflikt s chybou „exceeds the server's 1 MiB limit per object“; zvyšok trezoru sa synchronizuje ďalej. Nový taký záznam sa už neuloží (`require_syncable_entry` na desktope, `requireSyncablePayload` na mobile, `assertSyncObjectFits` na webe). Review d150605 S2 (web): takú zmenu zaradenú staršou verziou Retry preskočí (`oversizedQueuedObjects`), ostatné odošle a potom ju pomenuje (`sync.queued_too_large`); lišta konfliktov ju ukáže a ponúkne „Zahodiť príliš veľké zmeny“ (najprv šifrovaný export). Tombstone záznamu nad limit nesie len názov a štítky, takže sa záznam dá zmazať. Review d150605 N5 (desktop): rovnako push pošle tombstone záznamu nad limit (uloženého pred `require_syncable_entry`) s prázdnymi poľami zapečatenými vo verzii jeho meta (`_emptied_tombstone_data`); lokálny riadok si obsah ponechá, takže obnova z koša na tomto zariadení ho má celý. Predtým sa zmazanie odmietalo ako záznam sám a iné zariadenia si staršiu kópiu nechali navždy. Review d150605 S3 (web): re-key journal, ktorý server nikdy neprijme (chyby veľkosti nesú `syncUnitTooLarge`), `finishWebRevocation` raz postaví nanovo zo stavu servera; ak ani ten nevojde, journal zahodí (nič z neho na server neprišlo), člena NEodoberie a povie to (`admin.rekey_too_large`). Retry pritom odošle ostatné zmeny a journal už neblokuje ďalšie odobratia.
- **Atomická dávka** (re-key člena, zmena hesla, rotácia identity, Shamir obnova) sa server-side aplikuje celá alebo vôbec. Review d150605 #3: posun epochy nesie všetky vlastné DEK-y (každý tier-2 záznam má vlastný a nemažú sa), takže nad 1000 DEK sa zmena hesla nedala urobiť a Shamir obnova prešla lokálne, no každý ďalší push padal. Dávka nad limit jednej požiadavky sa preto pošle po častiach: najprv `POST /api/sync/stage {batch_id, start, objects}` (tabuľka `sync_staged_objects`, nič sa neaplikuje; nový batch zahodí starší, neukončené časti GC zmaže po dni), potom `POST /api/sync` so zvyškom a `staged_batch_id` + `staged_count`; server v jednej transakcii načíta a zmaže časti a aplikuje celú dávku (pri odmietnutí sa rollbackne aj zmazanie). Desktop `SyncClient._push_once`, web `postAtomicSyncBatch`. Odmietnutá vopred (`SyncUnitTooLarge`, aj v `org_recovery` pred snapshotom; web pred zápisom journalu) je len zmena nad 100 000 objektov / 255 MiB.
- **Re-key s objektom nad 1 MiB** (review d150605 S1; záznam uložený pred kontrolou veľkosti): desktop ho odmietne už pred vytvorením dávky (`_require_one_sync_unit` → `SyncUnitTooLarge`); člen ostane vo fronte `queued_revocations` s dôvodom a `finish_queued_revocations` pokračuje ďalšími členmi (`QueuedRekeysBlocked.too_large`, `sezam push` aj GUI ho vypíšu). Staršia taká dávka v `pending_rekey_batch` sa neposiela, zvyšok pushu odíde a výsledok nesie `rekey_too_large` s cestou von: `sezam abandon-rekey`, skrátiť/rozdeliť záznam, `sezam push`.
- Connect (CLI aj GUI) hlási „Data boli synchronizovane“ len vtedy, keď push prešiel bez konfliktov.

**Označenie ako odoslané** (review 526419e #2): prijatý objekt sa označí ako odoslaný len vo verzii, ktorá sa naozaj poslala (`is_dirty = 0 … WHERE id = ? AND version = ? AND is_deleted = ?` na desktope aj mobile; web vyradí z fronty len rovnakú verziu). Úprava uložená počas pushu ostane neodoslaná a odíde pri ďalšom. Review d150605 S4: web (`isSameSyncVersion`) porovná aj payload — úprava uložená počas pushu dostane rovnakú verziu, lebo strom sa ešte neposunul; prijatý push ju nevyradí z fronty ani nezmaže jej konflikt.

### 7.3 Server push processing

Pre každý objekt (v transakcii):

```
a) write_acl check:
   - Admin (is_admin=1): EXEMPT
   - Iný user: skontroluj write_acl(user_id, parent_ref)
   - Entry/node bez write_acl: REJECT 403
   - Výnimka: vlastný strom priamo pod top-level uzlom (osobný strom) write_acl
     nepotrebuje; jeho prvý priečinok (node) priamo pod koreňom smie člen
     založiť, záznam (entry) priamo pod koreňom nie (review d615826,
     tests/test_review6_web_member_personal_folder.py — web osobný priečinok
     člena tímu server predtým odmietol)
   - Ten prvý priečinok (nový aj presunutý pod koreň) musí mať meta
     zapečatené DEK-om autora (na serveri alebo v tom istom pushi; hlavička
     blobu nesie id DEK). DEK z toho istého pushu sa počíta, len ak prejde
     kontrolou osobného DEK: bez parent_ref/target_user_id/access_level,
     nie shared, a jeho id je nové alebo už autorovo (capability run 172:
     odmietnutý DEK objekt s id zdieľaného DEK koreňa predtým stačil a
     neatomický push priečinok uložil). Review 7c10379 H4: predtým člen len na čítanie
     založil pod koreňom priečinky zapečatené zdieľaným kľúčom koreňa a v
     nich podvrhnuté záznamy, ktoré kolegovia videli ako firemné
     (tests/test_review7_member_root_write_h4.py). Svoj osobný priečinok
     smie zmazať.
   - Klienti to isté overujú pri pulle aj full resyncu (už uložené podvrhy
     a server, ktorý klame): desktop `vault/sync_writers.py`, web
     `unauthorizedWrites` v app.js, mobil `services/write_authority.dart`.
     Priečinok alebo záznam priamo pod top-level uzlom aplikujú len od
     seba, od účtu s podpisom na objekte, ktorý server berie len od admina
     (top-level uzol, kľúč priečinka, envelope, archív kľúča, audit), od
     člena s write envelope na kľúč toho top-level uzla, alebo - len
     priečinok - od autora s meta zapečateným jeho vlastným kľúčom (osobný
     priečinok; v ňom všetko len kľúčmi majiteľa). Nič pod vynechaným
     priečinkom sa neaplikuje. Rozhoduje overený podpisovateľ, nie
     nepodpísaný owner_id. Hranica: server v spolku s členom môže prijať
     členov podpis na admin objekte; podpísaný zoznam adminov neexistuje
     (#335, podpisovatelia vyrobení serverom). Testy
     tests/test_review7_forged_root_folder_{desktop,web,phone}_h4.py.
   - Podvrhy, ktoré už aplikoval starší klient (capability run 174): web a
     mobil posudzujú celý lokálny stav pri každom pulle/načítaní (riadky
     spred mobilnej DB v7 bez signer_id podľa owner_id). Desktop posudzoval
     len objekty z pullu, delta pull ich znova nepošle a prune full resyncu
     nechal každé id, ktoré má server. Full resync teraz lokálne riadky
     vynechaných id zmaže (aj z keep_local) a desktop bez značky
     `unauthorized_writes_audited` pri prvom pulle raz stiahne celý stav
     servera a podvrhy z lokálnych tabuliek odstráni (po delta pulle; pri
     chybe to skúsi ďalší pull); nové vaulty a pull od nuly značku
     nastavia. Hranica: server, ktorý podvrh v tom stave zamlčí, ho
     nechá na desktope do najbližšieho full resyncu (ten zmaže všetko, čo
     server nemá).

b) Ed25519 signature verification:
   - Reconstruct signed_data
   - Ed25519_verify(user.signing_pk, signed_data, signature)
   - Invalid: REJECT 400

c) Version resolution:
   - server.version < client.version: ACCEPT
     - Priradiť commit_seq = next_global_seq++
   - server.version == client.version AND payload_hash matches: ACCEPT (idempotentný retry)
   - server.version == client.version AND payload_hash differs: REJECT 409 Conflict
   - server.version > client.version: REJECT 409 Conflict

d) Atomic batch:
   - Ak atomic_batch=true: všetky objekty v JEDNEJ DB transakcii
   - Partial success pri re-key = nekonzistentný stav -> all-or-nothing
   - Klient posiela v atomickom batchi len objekty re-key/rotácie; ostatné
     dirty objekty idú bežným pushom až po ňom (ich konflikt batch nezablokuje).
   - Zmena hesla / rotácia identity nesie v atomickom batchi vlastné DEK bez
     priečinka (root, audit, tier-2, personal) a DEK priečinkov, ktoré server
     má (`pushed_dek_versions`) alebo ktorých priečinok už bol so serverom
     v kroku (`object_base_version`). DEK priečinka, ktorý server nikdy nemal,
     ide prebalený bežným pushom spolu s priečinkom (review d615826 E8: priečinok
     člena tímu pod jeho vlastným top-level rootom server od neadmina odmieta
     – „invalid personal DEK metadata“ – a s ním predtým celú zmenu hesla
     pri každom pushi, takže nová epocha nikdy nedorazila).
   - 409 na re-key batchi (iné zariadenie medzitým zmenilo jeho objekt): klient
     spraví pull, serverové kópie ešte pod odobratým DEK prezapečatí novým DEK
     o verziu vyššie (obsah servera vyhráva), zmazané/presunuté prevezme,
     objekty a obálky pribudnuté pod starým DEK pridá do batchu a pošle ho znova.
     Neznámy kľúč v re-keyovanom priečinku = chyba, batch ostáva čakať.
   - Lokálna úprava takého objektu (pred re-key aj po ňom; batch si pamätá
     `rekeyed_versions`, ktoré vytvoril len re-key) sa nezahodí: odloží sa do
     `held_edits` a po prijatí batchu sa vráti ako bežný konflikt (M1) —
     tieň = kópia, ktorú server práve prijal, lokálna úprava na rovnakej verzii,
     takže ju push nepošle cez úpravu iného zariadenia, kým používateľ nevyberie.
   - Ďalší re-key priečinka s otvoreným konfliktom (review e4cd15a #3) sa
     odmietne (`RekeyBlockedByConflicts`), lebo by konfliktný riadok
     prezapečatil o verziu vyššie a pushol cez úpravu iného zariadenia.
     Odobratý člen ostane vo fronte (`queued_revocations`); `sezam push` ho
     len ohlási a re-key spraví až push po `sezam conflicts resolve`.
   - Dve zariadenia toho istého admina re-keyujú toho istého člena (review
     526419e V3): po pulle sú priečinky na DEK druhého zariadenia a na nový
     DEK tohto batchu už nič neukazuje (`rekey_abandon.superseded_rekey`).
     Od stavového testu SM58 stačí jeden taký nový DEK: telefón re-keyoval
     len prvý z dvoch priečinkov (druhý grant nevidel), batch notebooku niesol
     položky prvého priečinka pod vlastným novým kľúčom a server ho odmietal
     pri každom syncu. Po zahodení ide člen znova do fronty a nový re-key
     pokryje len to, čo ešte môže otvoriť.
     Rebase vtedy batch zahodí (`abandon_pending_rekey`): novšie serverové
     kópie vyhrajú, vlastná úprava sa vráti ako konflikt, ostatné objekty
     zapečatené novým DEK sa prezapečatia kľúčom ich priečinka a idú bežným
     pushom; nové DEK, archívy a obálky batchu sa zmažú. Položky zmazané
     počas čakajúceho re-key (tombstony, zapečatené o verziu nižšie) sa
     otvárajú spoločnou funkciou `vault.sealed.open_sealed` — tú istú používa
     kôš aj riešenie konfliktov (review d150605 #2).
     Zdieľanie pridelené počas čakajúceho re-key (obálka na novom DEK batchu,
     ktorá v batchi nie je) sa nezmaže potichu: zapečatí sa znova pre
     pripnutý kľúč člena (`known_keys`) pod DEK, ktorý priečinok používa po
     návrate, a znova zaradený re-key ho prenesie na ďalší kľúč (review
     d615826; test `tests/test_review6_abandon_rekey_keeps_grants.py`). Bez
     pripnutého kľúča sa zapíše varovanie, aby sa priečinok zdieľal znova.
   - Ručný východ z ľubovoľného zaseknutého re-key batchu: `sezam abandon-rekey`.
     Priečinky sa vrátia na starý DEK (aj s obálkami, ktoré re-key zmazal), a
     ak člen ešte niečo otvorí, zaradí sa do `queued_revocations` — najbližší
     `sezam push` ho re-keyuje znova z aktuálneho stavu.
   - Re-key a zmena hesla nejdú spolu (review 526419e V4): spoločný push
     server odmietal 409 navždy. `change_password` pripojeného trezoru počas
     čakajúceho re-key batchu odmietne; re-key počas neodoslanej zmeny hesla
     (`key_change_unpushed`) čaká vo `queued_revocations` a `sezam push` ho
     urobí, keď zmena hesla dorazí. Shamir obnova (`org_recovery`) čakajúci
     batch zahodí a člena zaradí do frontu — východ cez
     `abandon-pending-change` by chcel zabudnuté heslo.
   - Front sa nezasekne na prvom (review 526419e S4): člen, ktorého priečinky
     majú otvorený konflikt, ostane vo fronte a ďalší členovia sa re-keyujú
     (`QueuedRekeysBlocked` nesie hotových aj čakajúcich). Desktop GUI má v
     karte Users tlačidlo „Finish Re-keys“, ktoré robí to isté ako `sezam push`
     (`push_with_queued_revocations`) a pri čakajúcich konfliktoch sa spýta,
     ktorú kópiu ponechať (`resolve_conflict`), a front dokončí.
```

**Čakajúce stavy (review 526419e SYS, `vault/pending_states.py`).** Pravidlo: každý stav, ktorý trezor drží pre server, má výpis, východ a zahodenie bez zabudnutého tajomstva. `sezam status` ich vypíše v poradí, v akom sa riešia, s príkazmi `resolve` a `drop`:

| Stav | Kde | resolve | drop |
|---|---|---|---|
| kľúč účtu v kópii spred zmeny hesla (review 7c10379 R7-G) — pull stojí | `stale_own_dek_wraps` | `sezam pull --full-resync` (prevezme aktuálne kópie servera) | — |
| server sa vrátil (obnova zo zálohy; review 7c10379 Y6) — pull aj push stoja | `server_rollback_head` | `sezam pull --full-resync` (čo server stratil, sa ponechá a pošle znova) | — |
| neodoslaná zmena hesla/kľúča | `key_epoch > last_pushed_key_epoch` alebo `pending_key_rotation` | `sezam push` | `sezam abandon-pending-change` (heslo, ktoré má server) |
| zmena hesla staršej verzie bez dôkazu hesla servera (spred 688edcb K1; review 4acfdde R11) | žurnál bez `current_auth_proof` aj `recovery_secret` | `sezam finish-pending-change` (heslo, ktoré má server; nové heslo ostane) | `sezam abandon-pending-change` (nové heslo zahodí) |
| reset hesla cez org recovery | `pending_key_rotation.recovery_secret` | `sezam push` (podpis recovery kľúčom) | ak server odmietne: `sezam allow-key-reset` od iného admina; jediný admin bez denníka: `sezam team-log init` a `sezam push` (denník pomenuje recovery kľúč trezoru; review 4acfdde R11) |
| re-key po odobratí člena (aj zadržané úpravy) | `pending_rekey_batch` | `sezam push` | `sezam abandon-rekey` |
| front odobratých členov | `queued_revocations` | `sezam push` | `sezam abandon-rekey --queued` |
| konflikty | `sync_conflicts` | `sezam conflicts resolve ID --keep local` | `… --keep server` |
| neregistrovaný recovery kľúč | `org_recovery_server_pending` | `sezam push` v termináli | `sezam org-recovery-setup --replace` |
| recovery blob starého hesla na serveri | `org_recovery_rewrap_pending` | `sezam push` | `sezam org-recovery-setup --replace` |
| nedokončený reseed servera | `pending_server_reseed` | `sezam server reseed URL` | — |
| admin účet bez kľúčov po bootstrape | `pending_bootstrap_keypair_upload` | `sezam connect URL` | — |

Kľúče `vault_meta` týchto stavov číta a zapisuje len `pending_states.py` (ST4). Čo ktorý stav odmieta, je v jednej tabuľke `pending_states.BLOCKS` (operácia, stav, podmienka, hláška s cestou von, typ chyby; v rámci operácie podľa priority) a volajúci sa pýtajú `blocker(db, operácia)` / `refuse_if_blocked(...)`:

| Operácia | Odmietne ju (v poradí) |
|---|---|
| full resync | zmena hesla/kľúča bez `old_kek` v žurnále; re-key batch (okrem re-seal obálok rotácie identity so žurnálom, ktorý ich prezapečatí, SM57) |
| zmena hesla / rotácia identity | neodoslaný žurnál pripojeného trezoru (688edcb K2); re-key batch (526419e V4) |
| nový grant za neplatnú obálku | re-key batch |
| re-key po odobratí člena | re-key batch; neodoslaná zmena hesla pripojeného trezoru (`RekeyWaitsForKeyChange`) |
| riešenie konfliktu | položka v re-key batchi |
| `sezam abandon-rekey` | žiadny batch; batch rotácie identity (→ `abandon-pending-change`) |
| `sezam abandon-rekey --queued` | prázdna fronta |
| `sezam abandon-pending-change` | žiadna neodoslaná zmena |

Prístupová obálka (grant) má vlastný stav odoslania: `envelope_sync_state` drží id obálok, ktoré server má (z prijatého pushu alebo z pullu), a push posiela každú ostatnú. Predtým išla obálka len kým bol jej priečinok `is_dirty`; delený push (K1) a grant počas pushu (K2 porovnáva len verziu uzla) priečinok označili čistý skôr, než obálka došla, a člen priečinok nikdy nedostal (capability review vetvy #284, `tests/test_envelope_push_state.py`). Pri prvom použití staršieho trezoru sa obálky iných účtov označia ako uložené na serveri a vlastné idú ešte raz (server zhodnú obálku prijme ako idempotentný retry), takže dorazí aj grant, ktorý stratila staršia verzia. Neodoslané obálky `sezam status` započíta medzi neodoslané zmeny.

`tests/test_pending_states_status.py` postaví každú kombináciu, ktorá môže vzniknúť (23; zmena hesla a re-key spolu nevzniknú, V4), a overí, že výpis obsahuje práve tieto stavy, že ich vypísané `drop` príkazy v poradí výpisu všetky odstránia a že nasledujúci push prejde bez konfliktu. `tests/test_pending_states_blocks.py` postaví každý stav (offline aj pripojený) a overí pre každú operáciu, že ju odmietne práve stav z tabuľky `BLOCKS` s jej hláškou a typom chyby, že každé pravidlo tabuľky rozhodne aspoň jeden prípad a že `sezam status` pre každý stav vypíše cestu von.

**Response:**
```json
{
    "accepted": [
        {"id": "01HXYZ...", "commit_seq": 42}
    ],
    "conflicts": [
        {"id": "01HOTHER...", "server_version": 5, "server_payload_hash": "a3b7..."}
    ]
}
```

### 7.4 Pull

```
GET /api/sync?since_commit_seq=41
```

Server vráti objekty kde `commit_seq > 41`. Klient pre každý objekt:

```
a) Overí client_signature cez autorov signing_pk
   -> neplatný podpis = objekt ODMIETNUTÝ (fabricated by server)

b) server.version > local.version -> akceptuj (novšie)

c) server.version == local.version AND payload_hash differs
   -> CHYBA: equivocation (GUI varovanie)

d) server.version < local.version -> ignoruj (stale)

e) Tombstones: overí client_signature (podpis zahŕňa u8(is_deleted=1))
   -> platný podpis + autor mal write_acl -> označ lokálne is_deleted
   -> BEZ platného podpisu = ODMIETNUTÝ (server nemôže fabricovať tombstones)
```

### 7.5 Idempotentný retry

Klient pri retry posiela **presne ten istý blob** (z push cache), NIE re-encrypt. Re-encrypt by zmenil nonce --> iný ciphertext --> iný payload_hash --> server vráti 409.

Push cache = in-memory alebo SQLite temp, vymaže sa po úspešnom ack.

### 7.6 Conflict resolution

```
Odporúčaný merge:
  1. Stiahni serverovú verziu
  2. Dešifruj obe (lokálna + serverová)
  3. Porovnaj na úrovni JEDNOTLIVÝCH POLÍ (nie celého blobu)
  4. Rôzne polia zmenené: auto-merge (novšie pole z každej verzie)
  5. Rovnaké pole zmenené: manuálna voľba (GUI diff)

Orphaned entries (strata prístupu počas offline):
  - Klient po pull zistí, že pre dirty entries už nemá DEK obálku
  - GUI: "Nemáte prístup k X záznamom. Vašich X zmien bolo exportovaných."
  - Export dirty entries v dešifrovanej forme (klient ich má v RAM)
  - Lokálne zmazanie
```

### 7.7 Tombstone GC

| Parameter | Hodnota |
|-----------|---------|
| Tombstone retention | 90 dní od `modified_at` |
| GC | Server + klient |
| `gc_floor_seq` | Najvyšší `commit_seq` tombstonu, ktorý GC zmazal (aj v odpovedi pullu) |
| Long-offline klient | `since_commit_seq < gc_floor_seq` --> 410 Gone --> full resync |
| Hodiny GC | `commit_counter.gc_clock_ms`: hodiny servera, ale medzi behmi GC sa posunú najviac o čas, ktorý ozaj uplynul (monotónne hodiny procesu, po reštarte najviac 1 deň); späť nejdú. Review d150605 N7: hodiny servera posunuté o viac ako 90 dní dopredu predtým spravili expirovaným každý tombstone a jeden beh GC zmazal všetky. Dlhý výpadok servera hodiny GC oneskorí, čo tombstony len drží dlhšie |

**Checkpoint webu po GC (review d150605 #4).** Web po každom načítaní stránky stiahne celý trezor a porovná ho s checkpointom. Keď GC zmazal tombstone, ktorý checkpoint pokrýval, a nič iné sa nezmenilo, každé prihlásenie padalo na `STATE MISMATCH` (alebo `ROLLBACK DETECTED`, ak tombstone mal najvyššiu sekvenciu). Checkpoint preto drží aj `live_state_hash` (hash bez tombstonov). Rollback sa meria voči `head_commit_seq` (počítadlo, ktoré neklesá). Pull, ktorému chýbajú len tombstony pod `gc_floor_seq`, prejde, ak živé objekty sedia presne; skrytý živý objekt je stále rollback. Po plnom pulle web pokračuje deltami od `max(max_commit_seq, gc_floor_seq)`, inak by ďalší pull dostal 410. Desktop to predtým nerobil: full resync (a prvý pull nového zariadenia), ktorého najnovšie commity boli zozbierané tombstony, uložil `last_known_commit_seq = max_commit_seq` pod `gc_floor_seq`, a každý ďalší pull potom natrvalo končil na 410 (review a159e97, stavový test). Teraz uloží `max(max_commit_seq, gc_floor_seq)`; kotva tokenu commitu ostáva na `max_commit_seq`. Test: `tests/test_review8_full_snapshot_below_gc_floor.py`.

**Súbežné pully na desktope (review d150605 N8).** Desktopová aplikácia, príkaz CLI a MCP server ťahajú ten istý trezor. Keď jeden stiahol deltu a druhý medzitým stiahol ďalej a uložil checkpoint, prvý porovnal svoju staršiu dávku s novším checkpointom a ohlásil „Sync rollback detected“. Pull preto zapisuje v `BEGIN IMMEDIATE` a najprv overí, či sa `last_known_commit_seq` od stiahnutia nezmenil; ak áno, dávku zahodí a raz stiahne znova od nového stavu.

**Referenčná integrita (review d150605 #1).** Server neprijme živý uzol ani záznam, ktorého rodič chýba alebo je zmazaný, ani od admina (chyba „parent folder is deleted or missing“: priečinok obnov z koša alebo položku presuň). Desktop preto posiela dirty uzly v poradí rodič pred dieťaťom. GC nezmaže tombstone priečinka, pod ktorým ešte niečo visí (živá položka zo staršieho servera alebo tombstone, ktorý zostáva). Ak server zo staršej verzie už taký priečinok zmazal, pull aj full resync osirelé položky zavesia pod koreň (záznam si ponechá DEK z hlavičky) namiesto pádu na `FOREIGN KEY constraint failed`. Keď iné zariadenie zmazalo priečinok, v ktorom toto zariadenie má neodoslanú prácu (nový alebo upravený záznam či podpriečinok), pull aj full resync ten priečinok (a zmazané priečinky nad ním) vrátia: meta sa zapečatí o verziu vyššie než tombstone, priečinok je dirty a odíde pred položkou. Inak by ju server odmietal pri každom pushi a nikdy by neodišla (capability review 100).

**Obálky odobratých členov (review d150605 S5).** GC tombstony obálok (`object_type = 'envelope'`) nemaže. Keď ich zmazal, zastarané admin zariadenie poslalo obálku odobratého člena znova, server ju prijal ako nový objekt a vrátil mu `write_acl`. Server navyše neprijme živú obálku pre používateľa so `status = 'revoked'` (chyba „envelope for a revoked user“). Desktop si takú obálku po tejto chybe označí ako vybavenú (`envelope_sync_state`) a neposiela ju pri každom pushi; lokálne ostáva, lebo re-key podľa nej hľadá priečinky člena.

**Replay obálky odobratého člena (review d615826 H2).** Obálka má dve verzie: živú a podpísaný tombstone. Desktop predtým živú verziu uložil znova vždy, keď ju server poslal, takže server mohol vrátiť starú podpísanú obálku odobratého člena (a zároveň ho vyhlásiť za aktívneho) a grant again (SM62) mu zapečatil nový kľúč priečinka. Id obálky, ktorej tombstone zariadenie stiahlo alebo ktorej odobratie server prijal pri pushi, je v `withdrawn_envelopes` a jej živá verzia sa už neprijme. Grant again pečatí znova len obálky, ktoré zariadenie samo vytvorilo; obálky prvýkrát stiahnuté zo servera sú v `pulled_envelopes` a znova ich zapečatí zariadenie, ktoré ich vytvorilo. `created_by` stiahnutej obálky je účet, ktorého kľúčom sa overil podpis, nie nepodpísané `owner_id` (`tests/test_review6_envelope_replay.py`). Člena však mohlo odobrať iné zariadenie alebo iný admin: notebook Bobovi zdieľal, telefón ho odobral a priečinok pre-kľúčoval, server notebooku tombstone nikdy neukázal (vrátil starú podpísanú obálku) a Boba vyhlásil za aktívneho; notebook mu nový kľúč zapečatil, lebo o odobratí rozhodoval len nepodpísaný stav zo servera (capability review, beh 139). Grant again teraz pečatí znova len obálku vytvorenú neskôr ako každý re-key na ceste k aktuálnemu kľúču: id nového DEK podpisuje jeho re-key a ULID nesie čas vzniku. Obálka staršia alebo rovnako stará patrila re-key, ktorý ju mohol ponechať alebo odobrať; grant zo SM62 vznikol až po zostavení re-key. Stav člena zo servera je už len ďalší dôvod nepečatiť. Samotný čas však nerozlíši re-key, ktorý grant videl a odobral, od re-key, ktorý ho nikdy nevidel: telefón Carol zdieľal a poslal, notebook (bez pullu) potom odobral Boba a pre-kľúčoval len z lokálnych obálok, a Carol ostala na vyradenom kľúči (capability review, beh 140). Re-key, ktorý odoberá člena (desktop `rekey_after_revocation`, web `buildWebRekeyBatch`), preto do 16 náhodných znakov id archívu (`dek_archive`) zapíše dve značky z kľúčovaného BLAKE2b pod novým DEK: „re-key odobratia“ (8 znakov) a „odobral tohto člena“ (8 znakov; `dek.removal_archive_id`, web `removalArchiveId`, rovnaké bajty). Id archívu je asociované dáta jeho AEAD pod novým DEK, ktorý server ani odobratý člen nemá: značku nevie vyrobiť ani zmeniť, a archív bez nej skryje aj nástupcu. Grant again na každom kroku reťaze: archív so značkou zadrží len člena, ktorého menuje, bez ohľadu na vek grantu; archív bez značky (staršie re-key) rozhoduje časom ako vyššie. Značka preto musí byť úplná: re-key odoberá len člena, ktorého menuje. Web predtým zapečatil nový kľúč len držiteľom, ktorých server vypísal ako `active`, a ostatných odobral bez mena, takže pred novým kľúčom ich na inom zariadení chránil už len nepodpísaný stav zo servera (capability review, beh 141). Ako desktop teraz web zapečatí nový kľúč každému držiteľovi okrem odoberaného; keď je iný držiteľ neaktívny, re-key odmietne a žiada najprv odobrať jeho (`sezam revoke-user ID`; jeho vlastný re-key ho pomenuje). Test `tests/test_review6_web_rekey_names_withdrawn.py`. Hranica: pri archívoch bez značky platí hranica hodín (zariadenie, ktorého hodiny pri re-key meškajú viac, než uplynulo od grantu, by grant znova zapečatilo) a zostáva aj medzera z behu 140 (grant starší než re-key, ktorý ho nevidel, sa znova nezapečatí).

Full resync flow:
1. GUI varovanie („X nesynchronizovaných zmien")
2. Ponúkni export dirty objektov
3. Stiahni celý vault, over `client_signature` na každom objekte
4. Nahraď lokálny stav

Mobil (Android): dirty objekty sa pred resyncom uložia ako šifrovaný JSON (`sezam_unsent_*.json`) a po resyncu sa hneď vrátia na serverovú kópiu ako nové dirty zmeny. Nové priečinky a záznamy sa vytvoria znova, upravený záznam prepíše serverový, len ak ho medzitým nikto nezmenil. „Nikto nezmenil" sa určuje podľa serverovej verzie, na ktorej úprava vznikla (sync redesign S1: `base_version` + `base_hash`, rovnaká identita, akou server overuje push): prepis nastane iba pri zhode so živou verziou a iba keď živý riadok nemá vlastné neodoslané úpravy (pri importe z Nastavení po ďalšej offline úprave by sa inak novšia úprava prepísala). Číslo verzie ani `commit_seq` na to nestačia: každá offline úprava zvýši verziu a zápis prijatý po tombstone GC môže dostať rovnaké číslo s iným obsahom. Ak server medzitým drží inú verziu, úprava ostane na svojej pôvodnej verzii a serverová kópia sa odloží ako konflikt (rovnaký stav, aký zanechá pull) — používateľ rozhodne ako na desktope a webe. Kópia „(unsent copy)" vznikne len pri živom riadku s vlastnými neodoslanými úpravami a pri riadkoch bez základnej verzie (nikdy nesynchronizované, staršie exporty). Mazania, zdieľanie a zmeny kľúčov sa neprehrávajú. Zálohu si používateľ uloží cez systémový výber súboru (Downloads, cloud) a v Nastaveniach ju vie znova importovať; to, čo už v trezore je, sa druhýkrát nepridá.

### 7.8 ETag

`GET /api/sync` vracia `ETag` z `MAX(commit_seq)`. Klient posiela `If-None-Match` --> `304 Not Modified` ak sa nič nezmenilo.

### 7.9 Write ACL

```sql
-- Server-side enforcement
-- Content-blind pre obsah, ale nie pre write permissions

write_acl(user_id, node_id):
  - Admin: EXEMPT (is_admin=1)
  - Iný user: musí mať záznam v write_acl

-- Automatická aktualizácia:
  - Server prijme envelope s access_level='write':
    --> INSERT write_acl(target_user_id, parent_ref)
  - Server prijme envelope s access_level='read':
    --> ŽIADNY write_acl záznam
  - Tombstone envelope alebo user revokácia:
    --> DELETE write_acl
```

**Known limitation (bez denníka):** `access_level` je server-enforced, nie kryptograficky vynútený. Read-only user má DEK (potrebuje ho na čítanie). Kompromitovaný server by mohol pridať write_acl.

**Desktopový člen bez denníka (review 8595ec1, nízke):** desktop berie kľúč iného účtu len cez denník (`DESIGN_TEAM_LOG.md` §9) a obálky spred denníka nikdy neotváral (web áno). Člen dostal holé „Decryption failed“. Teraz `unlock_dek` taký kľúč odmietne `TeamKeyRefused` s cestou von a `sezam status` vypíše `shared_before_team_log` (počet priečinkov). Cesta von: admin `sezam team-log init` (zakladanie prenesie jeho obálky ako `folder.key` + `access.set`), člen `sezam team-log confirm-founder FINGERPRINT` a `sezam pull`; admin nemusí zdieľať znova. Nová dôvera v server (TOFU obálky bez denníka) zámerne nepribudla. Test `tests/test_review10_desktop_shared_without_log.py`.

**S tímovým denníkom (§5.5):** keď má organizácia denník, `write_acl` a `is_admin` sú len odvodené z jeho prehratia. O zápise v tímovom priečinku rozhoduje denník, na serveri aj na každom klientovi (tá istá funkcia `item_refusal`/`move_refusal`):
- Živý priečinok alebo položka platí, len ak ich overený podpisovateľ smie v priečinku zapisovať (`may_write`: admin podľa denníka alebo `access = write`) a sú zapečatené aktuálnou generáciou kľúča priečinka. Osobný kľúč autora je prípustný len s právom zápisu.
- Tombstone a presun von z tímového priečinka sú odstránením, takže potrebujú právo zápisu v priečinku, ktorý objekt opúšťa.
- Server kontroluje denník pred `write_acl`. Admin, ktorého denník nemenuje (len JWT/`is_admin` na serveri), nemá výnimku.
- Klient zmenu, ktorú server prijal, ale denník nedovoľuje, neaplikuje a nechá si svoju kópiu (desktop `sync_writers.py`, web `app.js`, mobil `write_authority.dart`).

Kompromitovaný server tak už nemôže potichu pridať právo zápisu. Môže len prestať posielať nové záznamy (`docs/DESIGN_TEAM_LOG.md` §8).

---

## 8. Rollback Protection

### 8.1 Sync checkpoint

Klient lokálne udržuje šifrovaný checkpoint v `vault_meta`:

```json
{
    "last_sync_seq": 42,
    "state_hash": "a3b7c2d9e4f1...",
    "timestamp": 1710764400000
}
```

### 8.2 state_hash computation

```python
def compute_state_hash(objects: list) -> str:
    """
    SHA-256 over sorted concatenation of all objects.
    Každý element je 62B fixed:
      object_id(26B) + u32be(version)(4B) + SHA-256(payload)(32B)
    """
    elements = []
    for obj in objects:
        element = (
            obj.id_bytes          # 26B ULID raw
            + struct.pack('>I', obj.version)  # 4B u32be
            + sha256(obj.payload)  # 32B SHA-256
        )  # 62B fixed per element
        elements.append(element)

    # Sort lexikograficky podľa object_id bytes (ULID je naturally sortable)
    elements.sort()

    return sha256(b''.join(elements)).hex()
```

### 8.3 Detekcie

| Útok | Detekcia |
|------|----------|
| Rollback (nižší commit_seq) | `last_sync_seq` porovnanie |
| Tiché zmeny payloadu | `payload_hash` mismatch |
| Equivocation (rovnaká version, iný payload) | `state_hash` mismatch + per-object check |
| Tombstone forgery | `client_signature` overenie (server nemá signing_sk) |

**Obnova DB servera zo zálohy (review d150605 #5).** Server obnovený zo staršej zálohy znova pridelí sekvenčné čísla, ktoré už zariadenia prešli. Desktop, ktorý raz videl `head_commit_seq` pod svojím checkpointom, si to zapamätá (`vault_meta.server_rollback_head`). Každý ďalší delta pull potom odmietne a odkáže na `sezam pull --full-resync`, aj keď server medzitým prerástol checkpoint. Inak by pull preskočil, čo sa na serveri zapísalo znova. Rovnaký odkaz dostane chyba `Audit DAG missing parent`. Full resync si nechá a znova pošle aj záznamy, ktoré server prijal a stratil: desktop si pri pushi aj pulle pamätá `commit_seq` každého potvrdeného priečinka a záznamu (`object_server_seq`). Objekt, ktorý na serveri chýba a bol potvrdený nad `gc_floor_seq`, bol stratený, nie zmazaný GC. Mobil číta `head_commit_seq` a rollback hlási ako `FullResyncRequiredException`. Jeho full resync (review d615826 H6) predtým stále porovnal odpoveď so starým checkpointom a padol na „ROLLBACK DETECTED“, takže sa po obnove servera nikdy nedokončil; a zmazal, čo obnovený server stratil. Teraz kontrolu checkpointu vynechá a ponechá, ako desktop, vlastné živé priečinky, záznamy a kľúče (uložený podpis overený vlastným kľúčom), ktoré server nemá, hoci ich potvrdil nad `gc_floor_seq`, alebo ich má v staršej verzii, keď sa server vrátil (`rowsTheServerLost`); bez rodiča na serveri ani medzi ponechanými sa nič neponechá. Ponechané riadky sú neodoslané (mimo checkpointu) a odídu s ďalším pushom. Testy: `tests/test_review6_phone_resync_after_restore.py` (skutočný server, obnova zo zálohy, desktop potom záznamy telefónu vidí), `mobile/test/full_resync_keeps_lost_h6_test.dart`. Záloha spred zmeny hesla, ktorú telefón už prevzal, vráti serveru nižší `key_epoch` a staré kľúče. Mobil každý pull odmietol („rolled-back key_epoch“), slepá ulička. Teraz, ako desktop (SM12), hlási `KeyEpochStaleException` a pýta heslo, ktoré má server (`adoptPasswordChangedElsewhere`; jej záverečný pull smie hlásiť full resync, zmena je už prevzatá). Nižšiu epochu prevezme, len keď telefón drží presne keypair servera (`key_material_hash`); KEK z prihlásenia pred obnovou ho nedrží. `sync()` pri `KeyEpochStaleException` z pushu s KEK zo serverovej soli najprv pullne (prevezme epochu) a až potom pošle neodoslané zmeny, inak ich push s vyššou epochou server odmietal donekonečna. Test: `tests/test_review6_phone_lowered_key_epoch.py` (offline úprava po obnove dorazí; nový desktop s heslom servera ju prečíta).

**Mobil: vyššiu `key_epoch` len so zhodným `key_material_hash` (review 7c10379 H9).** Príznak `kekMatchesServer` z prihlásenia heslom platil celú reláciu, aj keď heslo potom zmenilo iné zariadenie. Server pri zmene odvolal token, opätovné prihlásenie na 401 (`_signInAgain`) uspelo s tým istým kľúčom identity a pull prevzal vyššiu epochu so starým KEK; telefón potom pushol kľúč nového osobného priečinka zabalený starým KEK, ktorý iné zariadenia neotvoria. Pull teraz epochu (vyššiu aj nižšiu) prevezme len vtedy, keď telefón drží presne keypair servera (`_holdsServerKeyMaterial`: SHA-256 uloženého `sezam_encrypted_keypair` = `key_material_hash` z `/api/sync`); inak `KeyEpochStaleException` a telefón pýta heslo, ktoré má server (`adoptPasswordChangedElsewhere` uloží nový keypair). Test `tests/test_review7_phone_epoch_key_material_h9.py` (+ `mobile/test/phone_epoch_needs_key_material_test.dart`; desktop otvorí kľúč, ktorý telefón pushol) zlyhá na kóde pred opravou. Stavový stroj mobil nemodeluje (#335).

**Mobil: full resync po obnove servera ponechá aj kľúč ponechaného priečinka (review 7c10379 H9).** Prevzatie staršieho hesla obnoveného servera prebalí vlastné DEK na mieste (`planLocalDekRekey`); potvrdený riadok si ponechá podpis starého obalu. Full resync (`rowsTheServerLost`) potom kľúč nepovažoval za vlastný a zahodil ho, priečinok ponechal a poslal ho serveru späť bez kľúča, ktorý nikto nemal. Vlastný je teraz aj DEK, ktorý otvorí KEK trezora (taký obal vyrobí len tento účet, `_ownRewrappedKey`); ponechaný riadok s neplatným podpisom sa pred pushom podpíše znova (`_signedForPush`). Test `tests/test_review7_phone_resync_keeps_rekeyed_key_h9.py` (+ `mobile/test/phone_resync_keeps_rekeyed_key_test.dart`) zlyhá na kóde pred opravou.

**Mobil: full resync na serveri so starším heslom (review 7c10379, stredné).** Server obnovený zo zálohy spred zmeny hesla, ktorú telefón prevzal, má nižšiu `key_epoch`; pull full resyncu preto hlási `KeyEpochStaleException`. Obrazovka trezoru to ukázala ako „Full resync failed“ a ďalší sync znova žiadal full resync: slepá ulička. Full resync aplikácie (`fullResyncTakingPasswordOver` v `sync_recovery.dart`) teraz vypýta heslo servera, prevezme ho (`adoptPasswordChangedElsewhere`) a full resync spustí znova; zrušenie alebo odmietnuté heslo ho ukončí. Test `tests/test_review7_phone_full_resync_asks_password.py` (+ `mobile/test/phone_full_resync_asks_password_test.dart`) zlyhá so správaním pôvodnej obrazovky.

**Mobil: QR provisioning na lokálny trezor (review 7c10379, stredné).** Telefón, ktorý mal offline vlastný trezor, pri QR provisioningu prebalil svoje DEK na mieste pod KEK účtu a ponechal si vlastný root; jeho push dal účtu druhý root. `provisionFromQR` teraz telefón, ktorý nemá keypair účtu a jeho DEK KEK účtu neotvorí, pripojí ako pripojenie heslom (`_moveDeviceToAccount`): lokálny trezor odloží, stiahne trezor účtu a priečinky a položky zapíše znova pod root účtu; zlyhanie vráti telefón do pôvodného stavu. Prebalenie na mieste ostáva len pre telefón s keypairom účtu (heslo zmenené inde). Test `tests/test_review7_phone_qr_provision_local_vault.py` (+ `mobile/test/phone_qr_provision_local_vault_test.dart`) zlyhá na kóde pred opravou (dva roots).

**Mobil: rollback podľa tokenu commitu (review 7c10379, stredné).** Telefón poznal rollback len podľa hlavy servera pod checkpointom. Server obnovený zo zálohy, ktorý iné zariadenie medzitým pushlo za checkpoint telefónu, pridelil tie isté `commit_seq` iným zmenám; delta pull ich preskočil a to, čo telefón poslal po zálohe, sa na server už nevrátilo. Šifrovaný checkpoint teraz drží aj `commit_token` (`max_token` posledného pullu); pull posiela `check_seq`/`check_token` a iný `check_token` v odpovedi znamená zmenenú históriu: `FullResyncRequiredException` a full resync s `rolledBack` (ponechá a znova pošle stratené). Push posiela ten istý check; `409 history_changed` (kód z `errors.py`) tiež žiada full resync. Prebalenie checkpointu pri zmene KEK token zachová. Test `tests/test_review7_phone_commit_token_rollback.py` (+ `mobile/test/phone_commit_token_rollback_test.dart`) zlyhá na kóde pred opravou.

**Mobil po rotácii identity inde (review d615826).** Rotácia zvýši `token_epoch`, takže token telefónu prestal platiť a každý sync padal na 401 bez nového prihlásenia; telefón sa o rotácii nedozvedel. `sync()` sa pri 401 raz znova prihlási (podpisovým kľúčom trezoru), čo rotáciu ohlási ako `KeyEpochStaleException`. Po prevzatí s heslom mali neodoslané riadky podpis vyradeného kľúča a server ich pri každom pushi odmietol („invalid signature“). `rekeyLocalVault` ich v tej istej transakcii znova podpíše kľúčom účtu (payload a verzia ostanú). Test: `tests/test_review6_phone_identity_rotation_offline.py` (offline úprava dorazí, nový desktop ju prečíta).

**Zámok SyncService (review d615826, mobil).** Aplikácia synchronizuje po odomknutí, pri pull-to-refresh aj po zmenách; prekrývajúce sa synchronizácie striedali push a pull na jednom checkpointe. `sync`, `push`, `pull`, `fullResync` a `rekeyLocalVault` teraz bežia po jednom (`_exclusive`, fronta Future); volanie zvnútra držaného zámku (sync → push) beží hneď (hodnota zóny). Visiaca požiadavka zdrží ďalšie najviac o timeout HTTP (30 s). Test: `tests/test_review6_phone_overlapping_syncs.py` (prvý push odpovie neskoro, druhý sync nepošle nič, kým prvý neskončí; bez konfliktov).

**Zámok synchronizácie na webe (review 7c10379, R7-H).** Stránka sťahuje po prihlásení, po každom uložení aj pri Retry a nič tieto pully neoddeľovalo. Pull, ktorému server odpovedal pred pushom uloženia, ale skončil až po pulle toho uloženia, porovnal staršie seq servera s novším checkpointom: stránka pri bežnom uložení ohlásila ROLLBACK DETECTED a ponúkla prijať „obnovený“ server. Pull tiež zapísal späť frontu neodoslaných zmien, ktorú prečítal skôr, než sa do nej offline zaradila úprava (jej push zlyhal): úprava zmizla z fronty aj po obnovení stránky. Pully a úpravy fronty čítaním a zápisom (`retryAllWebDirtyObjects`, `discardWebConflictedChanges`, `restoreSetAsideWebChanges`) teraz bežia samy (`withWebSyncLock`). Pushe frontu menia len na mieste a môžu sa prekrývať navzájom (review 526419e #2), nie s pullom (`withWebSyncShared`). Kroky pullu (koreňový priečinok, migrácia osobných priečinkov, opečatenie pod nástupcom) volajú funkcie `…Locked`, ktoré predpokladajú držaný zámok. Test: `tests/test_review7_web_overlapping_pulls.py` (skutočné `app.js` a server; pull zadržaný na odpovedi alebo po prečítaní fronty, medzitým uloženie). Na starom kóde padá na ROLLBACK DETECTED a na prázdnej fronte. Stavový stroj také prekrytie v jednej karte nemodeluje: jeho kroky sú celé akcie.

**Re-key a keypair v jednej transakcii (review d615826, mobil).** Prevzatie zmeny hesla, prihlásenie s heslom zmeneným inde a nové napojenie zariadenia presunuli DEK pod nový KEK v jednej DB transakcii a až potom zapísali nový keypair a salt do Keychainu. Telefón zabitý medzi tým držal kľúče, ktoré žiadny uložený salt neodvodí, a neotvorilo ho ani jedno heslo. Stav keypairu (`pending_keypair_migration`) teraz ide do tej istej transakcie ako presun DEK (ako pri importe `.sezam-key`) a každé odomknutie ho dokončí. Offline nevie telefón, či je salt ešte serverov, preto sync raz znova požiada o aktuálne heslo. Test: `tests/test_review6_phone_adopt_killed.py` (zápis do Keychainu zlyhá ako zabitie; nové heslo potom otvorí všetko).

**Exporty mimo zálohy (review d615826, mobil).** Export `.sezam-key` (zabalený keypair a salt, stačí na offline hádanie hesla) a export neodoslaných zmien išli do Documents, ktoré iOS zálohuje do iCloud/iTunes. Teraz idú do `Application Support/exports` (`DatabaseService.exportDirectory()`), na iOS vylúčeného zo zálohy ako trezor; ak vylúčenie zlyhá, export sa nezapíše. Staršie exporty z Documents sa pri prvom použití presunú tam (nič neprepíšu). Test: `mobile/test/exports_not_backed_up_test.dart`.

**Token commitu (stavový test SM7).** Samotný `head_commit_seq` rollback neodhalí, keď iné zariadenie (alebo to isté) po obnove pushne skôr, než zariadenie pulluje: hlava dorastie na checkpoint alebo nad neho, pull vráti 304 alebo preskočí znova pridelené čísla. Server preto každej push transakcii pridelí náhodný token (`commit_log(last_seq, first_seq, token)`, push ho vráti ako `commit_token`). GC tieto riadky nemaže (jeden na push): aj zariadenie s kotvou pod `gc_floor_seq` musí rozlíšiť GC od straty commitov. Desktop drží kotvu `(seq, token)` posledného commitu, ktorý videl (pull `max_token` alebo vlastný push), a posiela ju ako `?check_seq=&check_token=` pri pulle a `check_seq`/`check_token` pri pushi. Pull vráti `check_token` servera pre to číslo: iný token je rollback (rovnako ako hlava pod checkpointom) a server s iným tokenom neodpovie 304. Push s inou kotvou server odmietne celý (409 „Server history changed“) ešte pred zápisom, aby na stratenej histórii nepristálo nič, čo na ňu nadväzuje (napr. audit záznam s rodičom, ktorý server stratil); desktop to hlási ako rollback. Commity spred zavedenia tokenu token nemajú a nekontrolujú sa. Web a mobil polia zatiaľ ignorujú. Token čísla sa hľadá jedným skokom po primárnom kľúči (`last_seq > seq-1 ORDER BY last_seq LIMIT 1`, potom `first_seq <= seq`); pôvodné `first_seq <= seq AND last_seq > seq-1` čítalo riadok každého neskoršieho pushu, a to pod globálnym zámkom pushu (review 7c10379, test `tests/test_review7_commit_token_seek.py`).

**Audit záznamy pri full resyncu (stavový test SM6).** Audit je len na pridávanie: full resync si nechá lokálne audit záznamy, ktoré server nemá, a vlastné, ktoré server už raz prijal a stratil, pošle znova. Predtým ich zahodil; novší záznam, ktorý ich menuje ako rodiča (poslaný po obnove servera), potom zlyhal na `Audit DAG ... references missing parent(s)` pri každom full resyncu a novom zariadení.

**Oživenie po GC nie je equivocation (stavový test SM8).** GC zabudne zmazanie, a tak zariadenie, ktoré malo neodoslanú úpravu, objekt pošle znova vo verzii, ktorá sa môže rovnať verzii zozbieraného tombstonu (alebo byť nižšia). Server by ju proti tombstonu odmietol; keď ju posiela, tombstone už nemá. Desktop preto živú kópiu cez vlastný odoslaný tombstone, ktorého `object_server_seq` je najviac `gc_floor_seq` z pullu, prevezme ako oživenie. Predtým ju hlásil ako equivocation a záznam ostal zmazaný len u toho, kto ho zmazal.

**Zmena hesla, ktorú obnovený server nevezme (stavový test SM9).** Posun epochy dokazuje heslo, ktoré zariadenie naposledy poslalo. Server obnovený zo zálohy spred tejto zmeny ho už nemá a push odmietne (403 „Wrong current account password“) pri každom syncu znova, bez slova o ceste von. Chyba teraz k odpovedi servera pridá odkaz na `sezam abandon-pending-change` s heslom, ktoré má server teraz; potom sa heslo dá zmeniť znova. Odmietnutia sa naďalej rátajú do zámku obnovy (ochrana pred ukradnutým keypairom); správny dôkaz vlastníka zámok neblokuje.

**Relácia ukončená zmenou kľúčov inde (stavový test SM10).** Zmena hesla alebo rotácia identity posunie `token_epoch`, takže otvorené relácie ostatných zariadení účtu skončia. Ich ďalšia požiadavka predtým skončila holým `401 Token revoked` pri každom opakovaní. Klient sa teraz pri 401 „Token revoked“ / „expired token“ raz znova prihlási a požiadavku zopakuje (server ju odmietol skôr, než niečo urobil). Nové prihlásenie alebo kontrola epochy potom povie, čo sa zmenilo (`KeyEpochStale` → prevziať zmenu aktuálnym heslom). Ak opätovné prihlásenie zlyhá, ďalšia požiadavka s autorizáciou sa najprv prihlási, nejde bez tokenu.

**Prevzatie rotovanej identity a kruh podpisových kľúčov (stavový test SM11).** `adopt_rotated_key_material` pri novom keypairi znova podpíše neodoslané audit záznamy novým kľúčom. Klient si však držal kruh podpisových kľúčov vlastného účtu načítaný predtým (len starý kľúč) a tie záznamy pri každom pushi relácie odmietol ako falošné („Invalid audit signature“). Prevzatie teraz kruh zahodí a načíta ho znova.

**Zmena kľúčov, ktorú obnovený server stratil (stavový test SM12).** Server obnovený zo zálohy spred prijatej zmeny hesla má DEK zabalené pod KEK hesla, ktoré má teraz. Zariadenie predtým pokračovalo a nové DEK balilo pod svoj novší KEK, ktorý by žiadne iné zariadenie neotvorilo. `key_epoch` servera pod `last_pushed_key_epoch` teraz vyvolá `KeyEpochStale` (aj pri full resync); cesta von je `adopt_rotated_key_material` s heslom, ktoré má server teraz.

**Stratená úprava rovnakej verzie po obnove servera (stavový test SM13).** Zariadenie poslalo verziu N, server ju prijal a potom bol obnovený zo zálohy; iné zariadenie medzitým zapísalo vlastnú verziu N (napr. zmazanie) bez znalosti tej prvej. Full resync predtým vzal kópiu servera a úpravu bez slova zahodil. `object_sent_version` si teraz drží riadok práve potvrdenej verzie s `payload_hash`; rovnaká verzia s iným hashom na serveri dokazuje stratený zápis, full resync ho ponechá a zapíše konflikt, o ktorom rozhodne používateľ.

**Rotácia identity, ktorú obnovený server stratil (stavový test SM14).** Server obnovený zo zálohy spred prijatej rotácie pozná len kľúč spred nej. Každé prihlásenie zariadenia potom skončilo holým 401 a zariadeniu s ešte platnou reláciou full resync odmietol záznamy servera („invalid signature“), lebo ich overoval len novým lokálnym kľúčom. Teraz 401 pri prihlásení zariadenia, ktoré už poslalo zmenu kľúčov, a aktuálny kľúč účtu na serveri, ktorý nie je lokálny ani ním autorizovaný čakajúcou rotáciou, vyvolajú `KeyEpochStale`: cesta von je `adopt_rotated_key_material` s heslom, ktoré má server (cez `/auth/recover`, bez prihlásenia). Full resync potom znova podpíše neodoslané vlastné audit záznamy (aj tie, ktoré server stratil) kľúčom, ktorý server pozná.

**Zmena hesla nad kľúčmi priečinkov, ktoré zariadenie ešte nestiahlo (stavový test SM15).** Zmena hesla, upgrade KDF aj rotácia identity prebalia každý kľúč priečinka na jeho ďalšiu verziu a server ich berie len všetky naraz. Zariadenie, ktoré prevzalo rotáciu z iného zariadenia (`adopt_rotated_key_material` necháva lokálne verzie kľúčov) alebo nestiahlo nový priečinok, postavilo dávku na starých verziách: server ju odmietol s 409 („Atomic batch conflict“ alebo „Key epoch advance must include every active DEK“) pri každom pushi a zmena nikdy nedorazila. `sezam change-password`, `sezam rotate-identity` aj GUI upgrade KDF teraz pred zmenou volajú `SyncClient.prepare_key_change()` (prihlásenie + pull); keď zlyhá, nič sa nezmení.

**Rovnaký audit záznam s iným podpisom (stavový test SM16).** Keď obnovený server stratil rotáciu identity, zariadenie, ktoré vzalo starý kľúč späť, znova podpísalo záznamy, ktoré server stratil, a poslalo ich. Iné zariadenie držalo kópiu podpísanú strateným kľúčom a jeho full resync sa na nej zastavil („Conflicting append-only audit record“) natrvalo. Pull teraz prevezme záznam, ktorý sa líši len podpisom, ak ten podpis overí kľúč účtu; obsah append-only záznamu sa nemení.

**Viac vlastných zápisov, ktoré obnovený server stratil (stavový test SM17).** SM13 chytil len cudziu kópiu s rovnakou verziou. Keď zariadenie zapísalo objekt viackrát (verzia o 2 a viac vyššia) a iné zariadenie po obnove zapísalo nad zálohou nižšiu verziu, full resync ju považoval za kópiu, ktorú zariadenie už prekonalo, a ďalší push ju bez konfliktu prepísal. Nová tabuľka `object_sent_base` drží ku každej odoslanej verzii verziu cudzej kópie, z ktorej zápis vychádza; `object_sent_version` si nad vlastným potvrdeným zápisom drží celý reťazec vlastných zápisov od nej. Kópia servera nad touto verziou, ktorá nie je vlastným zápisom, je konflikt.

**Hranica archivovaného kľúča zo stratenej rotácie (stavový test SM18).** Hranica (`archived_key_bounds`, review 688edcb V4) sa pripína na najnižší `retired_seq`. Zariadenie si ju pripne pri vlastnej rotácii; keď ju obnovený server stratil, starý kľúč bol znova kľúčom účtu a objekty ním podpísané po obnove boli pri každom full resync odmietnuté ako falošné. Full resync po zistenom rollbacku (`server_rollback_head`) teraz pripnuté hranice vlastného účtu zahodí a naučí sa ich znova zo servera. Útočník so serverom tým nič nezíska: po rollbacku zariadenie aj tak preberá kľúčový materiál účtu zo servera s heslom (SM14). Od cieľa #443 sa hranice nepripínajú vôbec: vyradený kľúč platí len pre verzie zo zoznamov key vouchers (sekcia 10.2, krok 3).

**Vyradený kľúč po obnove servera (capability review, behy 294 a 300).** Obnova zo zálohy spred rotácie identity vráti do `users` kľúč K0, ktorý denník (`member.keys`) už vyradil; prihlásiť sa ním vie zariadenie, ktoré rotovalo (drží K0 v žurnáli rotácie), aj stratené či ukradnuté zariadenie, kvôli ktorému sa rotovalo (drží len K0). Relácia s takým kľúčom (`dependencies._authenticate_user`, `team_log.key_retired`) nesmie pushovať okrem samotnej rotácie na kľúče denníka, zapisovať do denníka ani pozývať (403 `identity_key_retired`). Objekty (`GET /api/sync`, push a stage rotácie) smie čítať len relácia, ktorej prihlásenie podpísal aj aktuálny kľúč denníka: `/api/auth/verify` prijme `current_key_signature` (Ed25519 nad `sezam-current-key-proof-v1 || challenge`) a token nesie claim `kcur`. Desktop ho posiela pri prihlásení starým kľúčom zo žurnálu (`sync_common.auth_verify_body`). Bez dôkazu dostane relácia rozsah `key_retired`, ktorý vidí len denník a verejné kľúče (`get_team_log_reader`). Rotácia identity DEK priečinkov nemení, len ich prebalí, takže predtým zariadenie s K0 rozšifrovalo aj položky zapísané inými členmi po obnove. Klienti (desktop, web, mobil) navyše overujú podpisy proti denníku, nie proti kľúču, ktorý server vyhlási za aktuálny (`signing_key_retired` / `TeamLog.signingKeyRetired`). Testy: `tests/test_review9_retired_key_after_restore.py` (vrátane `mobile/test/phone_retired_key_test.dart`); nové prípady behu 300 zlyhajú na 4a16a93.

**Zmena kľúčov nad serverom, ktorý sa vrátil (stavový test SM19).** `prepare_key_change` (SM15) pred zmenou hesla, upgradom KDF alebo rotáciou identity stiahne zmeny zo servera. Keď pull zistil rollback (server obnovený zo zálohy), len varoval a zmena sa postavila na verziách kľúčov priečinkov, ktoré server stratil: server ju pri každom pushi odmietol s 409 `Atomic batch conflict` a full resync, ktorý by pomohol, je pri čakajúcej zmene zakázaný. Teraz sa zmena pri zistenom rollbacku (varovanie pullu alebo `server_rollback_head`) nezačne a chyba pomenuje `sezam pull --full-resync`; po ňom zmena prejde.

**Dva zápisy s rovnakou verziou po GC tombstonov (stavový test SM20).** Notebook offline premenoval priečinok; telefón ho zmazal (verzia 2), odoslal, potom ho obnovil a premenoval, tiež offline. GC zmazal tombstone, takže premenovanie z notebooku sa vrátilo ako nový objekt – tiež vo verzii 2. Telefón poslal zmenu s `base_version` 2 (svoj vlastný tombstone); server porovnal len číslo, vzal ju ako zmenu premenovania z notebooku a prepísal ho bez konfliktu. Push teraz posiela aj `base_payload_hash` – hash kópie, na ktorej zmena stojí (tabuľka `object_base_hash`: vlastný prijatý zápis, alebo stiahnutá kópia, pri ktorej je riadok čistý). Server zmenu prijme len nad touto kópiou, inak vráti konflikt. Bez hashu (starší klient, web, mobil, alebo základ z vyriešeného konfliktu) platí porovnanie verzie ako doteraz.

**Dva tombstony s rovnakou verziou po GC (stavový test SM21).** Notebook premenoval a zmazal priečinok (verzia 3) a odoslal; telefón ho offline premenoval inak a tiež zmazal, tiež vo verzii 3. GC zmazal tombstone z notebooku, takže server vzal tombstone z telefónu ako nový objekt. Notebook ho stiahol, videl svoju verziu 3 s iným obsahom, nahlásil equivocation a nechal si svoju kópiu – zariadenia natrvalo držali rôzne tombstony a posledný zápis telefónu bol len na telefóne. Kópia nad vlastným tombstonom, ktorý GC zmazal (`commit_seq` ≤ `gc_floor_seq`), ho teraz nahradí, či je zmazaná alebo nie (SM8 pokrýval len živé kópie). Hash základu (`object_base_hash`) sa pri stiahnutí zapíše len vtedy, keď riadok naozaj nesie stiahnutý obsah.

**Ponechaná zmena pod vlastnými zápismi zariadenia (stavový test SM22).** Telefón dvakrát upravil záznam a odoslal (verzie 2 a 3), notebook ich stiahol; server sa potom obnovil zo zálohy s verziou 1. Telefón záznam zmazal, spravil full resync a v konflikte si ponechal svoje zmazanie – prebalené na verziu servera + 1 = 2. Full resync notebooku poslal jeho kópiu, verziu 3, znova – vlastný zápis telefónu. Push telefónu bol odmietnutý, prestaval sa na tento vlastný zápis a znova poslal verziu 2, pri každej synchronizácii: nikdy sa neustálil. Ponechaná zmena (`resolve_conflict(..., "local")`) teraz dostane verziu nad serverovou aj nad každou verziou, ktorú zariadenie už poslalo (`object_sent_version`).

**Odobratie člena zo zariadenia, ktoré nevidelo zdieľanie (stavový test SM23).** Notebook zdieľal priečinok s Bobom; telefón (ten istý admin účet) to ešte nestiahol a Boba odobral. Re-key hľadá priečinky člena cez obálky, ktoré zariadenie drží, takže na telefóne nepreklúčoval nič – a notebook sa nikdy nedozvedel, že má: Bobova obálka ostala živá a nové položky išli ďalej pod kľúčom, ktorý Bob má. Zariadenie, ktoré obálku zapečatilo (`created_by` = tento účet), teraz pri každom `finish_queued_into` (CLI push, GUI, `push_with_queued_revocations`) zaradí do frontu re-key každého odobratého člena, pre ktorého drží obálky (`queue_revoked_holders`).

**Zdieľanie stratené obnovou servera (stavový test SM24).** Notebook zdieľal priečinok s Bobom, server sa potom obnovil zo zálohy spred zdieľania. Full resync notebooku nechal len obálky, ktoré server vrátil (alebo s DEK, ktorý server stratil), takže Bobova obálka sa zmazala a Bob priečinok stratil natrvalo. Obálka tohto účtu, ktorú server nedrží, teraz ostáva a ide znova (zmaže sa jej `envelope_sync_state`), kým existuje jej DEK – ak nebola nikdy odoslaná, alebo ak zariadenie videlo, že server išiel späť. Obálku pre odobratého člena server odmietne.

**Re-key, ktorý server prijal, ale odpoveď sa stratila (stavový test SM25).** Telefón odobral Boba; dávka re-key na server dorazila, odpoveď nie, a dávka ostala čakať. Notebook re-key stiahol a upravil záznam v preklúčovanom priečinku. Znovu poslanú dávku server odmietol a pri prestavbe bola serverová kópia zapečatená novým kľúčom samotnej dávky – „sealed with another key“ pri každej synchronizácii. Nové DEK dávky vytvorilo len toto zariadenie, takže serverová kópia zapečatená jedným z nich dokazuje, že atomická dávka na serveri je (dnes sa to pýta servera: `rekey_batch_on_server`): uzavrie sa ako odoslaná, objekty dávky, ktoré sa odvtedy inde zmenili, prevezmú serverovú kópiu, ostatné sa označia ako odoslané a podržané úpravy sa vrátia ako konflikty.

**Neodoslané položky pod kľúčom odobratého člena (stavový test SM26).** Notebook vytvoril záznam a priečinok v priečinku zdieľanom s Bobom a pred pushom stiahol re-key z telefónu, ktorý Boba odobral. Obe položky boli ešte zapečatené starým DEK priečinka, ktorý Bob má, a server ich tak prijal. Pred každým pushom sa živá neodoslaná položka zapečatená vyradeným DEK priečinka (`scope = 'folder'`, bez priečinka) zapečatí znova aktuálnym DEK svojho priečinka (`_reseal_under_successors`; názov priečinka patrí pod kľúč rodiča, koreňa pod vlastný).

**Audit záznam re-key bez rodičov (stavový test SM27).** Telefón upravil záznam bez synchronizácie a potom odobral Boba. Audit záznam re-key má za rodičov skoršie audit záznamy telefónu, no atomická dávka niesla len objekty re-key a zvyšok mal ísť ďalším pushom. Odpoveď sa stratila, ďalší push neprišiel a server držal záznam, ktorého rodičov nemal – full resync iného zariadenia odmietol audit DAG. Neodoslané audit záznamy (len pripájané, bez konfliktov) teraz idú spolu s atomickou dávkou.

**Položky odoslané pred stiahnutím re-key (stavový test SM28).** Notebook vytvoril záznam a priečinok v priečinku zdieľanom s Bobom, kým telefón Boba odobral a priečinok preklúčoval. Notebook poslal skôr, než stiahol: server ich prijal ako nové objekty zapečatené DEK, ktorý Bob má, a SM26 (len neodoslané) ich už nevidel. Po každom pull sa vlastný zápis tohto zariadenia (`object_sent_version` = aktuálna verzia), ktorý server drží pod vyradeným DEK priečinka, zapečatí znova o verziu vyššie a odošle ako zmena (`_reseal_under_successors`; robí to len zariadenie, ktoré ho zapísalo – smie tam zapisovať).

**Rotácia identity, ktorá znova zapečatila obálku odobratého člena (stavový test SM29).** Notebook zdieľal priečinok s Bobom; telefón Boba odobral, ale jeho re-key ešte na server nedorazil, takže Bobova obálka bola živá na serveri aj na notebooku. Notebook potom rotoval identitu, čo znova zapečatí každú obálku, ktorú vytvoril – aj Bobovu. Server živú obálku pre odobratého používateľa odmietne a s ňou celú atomickú rotáciu, pri každej synchronizácii. Keď server atomickú dávku odmietne len pre takéto obálky, ostanú lokálne (`envelope_sync_state`, ako mimo dávky pri S5), vypadnú z `object_ids` čakajúceho re-key a dávka ide raz znova bez nich.

**Cudzia zmena hesla na epoche, ktorú obnova servera stratila (stavový test SM30).** Notebook zmenil heslo a server ho prijal ako key epoch 2 (alebo telefón takú zmenu prevzal); potom sa server obnovil zo zálohy spred nej a iné zariadenie zmenilo heslo znova – server ho prijal tiež ako epochu 2. Epochy zariadenia sa so serverom zhodovali (SM12 videl len server pod nimi), takže pokračovalo s kľúčovým materiálom, ktorý server už nemá, a DEK zabalené odvtedy nevedelo otvoriť. Zariadenie si teraz pamätá SHA-256 serverového `encrypted_keypair` pre epochu, ktorú drží (`server_key_material_hash`: čo poslal jeho push zmeny, alebo čo prevzal cez `adopt_rotated_key_material`), a keď server pri tej istej epoche hlási iný `key_material_hash`, vyhodí `KeyEpochStale` – prevzatie s aktuálnym heslom účtu.

**To isté na webe (stavový test SM80).** Stránka prihlásená po rotácii identity (epocha N+1) porovnávala len epochu: server obnovený zo zálohy spred rotácie a org recovery na desktope ho vrátili na N+1 s iným kľúčovým materiálom, takže relácia pokračovala a „Použiť verziu servera“ padlo na „invalid Ed25519 signature“. `pullAndBuildTree` si teraz pamätá `key_material_hash` z prvého pullu relácie (`state.keyMaterialHash`; po vlastnej rotácii hash nového wrapu) a pri inom hashi na tej istej epoche reláciu ukončí s `error.key_epoch_changed` (prihlásiť sa znova). Platí aj pre úplný pull uprostred relácie (Použiť verziu servera, prijatá obnova servera), ktorý začína so `syncObjects = null`. Test: `tests/test_review6_web_same_epoch_new_keys_sm80.py`.

**Re-key stiahnutý počas čakajúcej zmeny hesla (stavový test SM31).** Notebook zdieľal priečinok s Bobom; telefón Boba odobral (nepreklúčoval nič, SM23) a zmenil heslo, ale push zlyhal. Notebook potom priečinok preklúčoval. Jeho nový DEK je zabalený pod KEK, ktorý server ešte má a ktorý telefón už nahradil: priečinok bol na telefóne nečitateľný a jeho zmenu (musí niesť každý aktívny DEK) server odmietal pri každom pushi. Žurnál čakajúcej zmeny teraz drží aj starý KEK (`old_kek`, zapečatený novým ako ostatné položky žurnálu – kto má nový KEK, má už aj všetky DEK). Stiahnutý DEK, ktorý nový KEK neotvorí a starý áno, sa prebalí pod nový KEK o verziu vyššie (`DEKManager.rewrap_from`) a ide so zmenou; `pushed_dek_versions` drží verziu servera. Žurnál zaniká so zmenou (prijatá alebo zahodená).

**Druhé zdieľanie prežilo odobratie člena (stavový test SM32).** Telefón aj notebook (ten istý admin účet) zdieľali priečinok s Bobom skôr, než videli zdieľanie toho druhého. Notebook Boba odobral a priečinok preklúčoval – stiahol pritom len obálku, ktorú držal. Obálka telefónu, teraz pre vyradený kľúč priečinka, ostala živá; telefón Bobov re-key zaradil (SM23), no k tomu kľúču nepatrí žiadny priečinok, takže nepreklúčoval nič a obálku nechal. `rekey_after_revocation` teraz pri DEK bez priečinka zmaže obálky odobratého člena a pošle ich tombstony v dávke (bez nového DEK).

**Znova zapečatený zápis v priečinku zmazanom inde (stavový test SM33).** Notebook zdieľal priečinok s Bobom a potom ho zmazal. Telefón, ktorý nevidel ani jedno, v ňom vytvoril záznam a Boba odobral (nepreklúčoval nič, SM23). Push notebooku priečinok preklúčoval a poslal zmazanie. Pull telefónu znova zapečatil jeho záznam novým kľúčom priečinka (SM28) a označil ho ako neodoslaný – až potom, čo pull obnovil priečinky s neodoslanou prácou, takže server záznam odmietal („parent folder is deleted“) pri každom pushi. `_reseal_under_successors` teraz po zmene spustí aj `_revive_folders_of_unsent`.

**Zmena pod priečinkom zmazaným inde v atomickom pushi (stavový test SM34).** Telefón vytvoril podpriečinok v F, kým notebook, ktorý ho nevidel, F zmazal – server nechal podpriečinok živý pod zmazaným priečinkom. Notebook po poslednom pulle podpriečinok premenoval a zmenil heslo (alebo odobral člena a preklúčoval). Taký push je jedna atomická dávka a server premenovanie odmietol („parent folder is deleted“), takže zlyhal celý push. Priečinky s neodoslanou prácou obnovoval len pull; `_push_once` teraz pred zberom objektov spustí `_revive_folders_of_unsent` tiež.

**Tombstone obálky, ktorú server nikdy nemal (stavový test SM35).** Notebook zdieľal nový priečinok s Bobom, no push zlyhal – na server neprišiel ani kľúč priečinka, ani Bobova obálka. Telefón Boba odobral. Re-key na notebooku poslal tombstone Bobovej obálky zapečatenej kľúčom, ktorý server nepozná, a server odmietol celú atomickú dávku („envelope references unknown DEK“) pri každom pushi. To isté nastalo pri opakovanej dávke so strateným potvrdením, keď starý kľúč medzitým stratil priečinok. Server teraz tombstone obálky, ktorej živú kópiu nemá a ktorej kľúč nepatrí žiadnemu priečinku, prijme – neberie ani nedáva žiadny prístup.

**Rotácia identity so strateným potvrdením (stavový test SM36).** Rotácia znova zapečatí Bobovu obálku ako novú a pošle ju v atomickej dávke. Server ju prijal, odpoveď neprišla. Ďalší pull obálku stiahol a označil ako držanú serverom, takže ju zber už nevrátil, no čakajúca dávka ju stále vyžadovala („Atomic re-key batch is missing 1 local object(s)“) pri každom pushi. Obálka, ktorú server drží (`envelope_sync_state`), už v dávke nechýba ani sa nevyžaduje medzi prijatými.

**Úprava stratená pri prenesení re-key (stavový test SM37).** Notebook zdieľal priečinok s Bobom a upravil jeho záznam. Telefón, ktorý zdieľanie nevidel, Boba odobral a záznam presunul do podpriečinka s vlastným kľúčom. Re-key notebooku záznam zobral so sebou; po odmietnutí `_rebase_pending_rekey` prevzal serverovú kópiu (zapečatenú kľúčom podpriečinka) a úprava zmizla bez konfliktu. Záznam, ktorý drží úpravu používateľa (verzia iná než po re-key), teraz z dávky odíde a ostane konfliktom so serverovou kópiou.

**Full resync, ktorému obnovu servera neoznámil pull (stavový test SM38).** Notebook zdieľal priečinok s Bobom a server sa potom obnovil zo zálohy spred zdieľania. Full resync spustený hneď, bez pullu či pushu, kontroloval len príznak rollbacku, ktorý zanechá pull, a odoslanú obálku bral ako zámerne zmazanú: Bob priečinok stratil (SM24 to riešil len po pulle). Full resync teraz obnovu spozná aj z vlastného snapshotu (`check_token` kotvy commitu, alebo hlava servera pod kotvou).

**Re-key po obnove servera zo zálohy (stavový test SM39).** Notebook upravil súkromný záznam a odoslal ho; server potom obnovili zo zálohy spred tohto pushu. Notebook odobral Boba a re-key sa neodoslal. Čakajúci re-key blokuje full resync, preto jeho push išiel bez kontroly rollbacku: jeho audit záznam pristál na rodičovi, ktorého obnova stratila, a full resync telefónu odmietal audit DAG, kým ho nespustil aj notebook. Push s čakajúcou zmenou teraz kontrolu posiela tiež; keď server odpovie, že sa vrátil, `_resend_audit_lost_by_restore` znova označí ako neodoslané audit záznamy účtu, ktoré server už nemá (podpísané stratenou identitou podpíše aktuálnym kľúčom ako full resync), a push ide bez kontroly aj s nimi.

**Zmena hesla čakajúca, kým server zhutnil históriu (stavový test SM40).** Push zmeny hesla telefónu zlyhal. Notebook medzitým vytvoril priečinok (nový DEK) a zmazal záznam, a GC servera zozbieral tento tombstone za checkpointom telefónu. Zmena musí niesť každý aktívny DEK, takže ju server odmietal, kým telefón nový DEK nestiahol; delta pull bol 410 (treba full resync) a full resync bol pri čakajúcej zmene zakázaný. Telefón sa už nikdy nesynchronizoval. Zmena, ktorej žurnál drží starý KEK (od SM31), full resync prežije: každý DEK zo servera sa pri aplikovaní prebalí do zmeny. `full_resync_blocker` ho preto povolí; zmena bez starého KEK ostáva zakázaná. Od SM54 to platí aj pre zmenu s rotáciou identity: žurnál drží starý kľúčový pár (obálky pre starý kľúč sa ním otvárajú, kým rotácia nedorazí) a obálky prepečatené rotáciou čakajú v `pending_rekey_batch`. Predtým telefón s takou zmenou po 410 zostal zaseknutý navždy. Od SM57 full resync nezakazuje ani dávku rotácie identity (účet zdieľal priečinok s členom): jej neodoslané prepečatené obálky zahodí a po snímke servera prepečatí nanovo všetky obálky účtu, ktoré server má (aj tie, čo medzitým starým kľúčom zapečatilo iné zariadenie), funkciou `reseal_envelopes_for_rotation`. Predtým blokovanie pomenovalo `sezam abandon-rekey`, ktoré rotáciu identity odmieta. Ak server po obnove zo zálohy drží ešte starší KEK, full resync sa pred commitom vráti (vlastný DEK by sa neotvoril). Org recovery (Shamir) teraz do žurnálu tiež dáva KEK, ktorý má server (obnovený zo zdielov, alebo starý KEK čakajúcej zmeny). Jej push sa predtým zamietal pre DEK priečinka vytvoreného inde (recovery pred tým nič nestiahne) a jediná ponúknutá cesta von (`sezam abandon-pending-change`) potrebovala zabudnuté heslo. Push zmeny s takým žurnálom teraz pri odmietnutí „every active DEK“ raz stiahne zmeny (nové DEK sa prebalia do zmeny) a pošle ju znova.

**Premenovanie priečinka, ktorý zmazali inde, počas re-key (stavový test SM41).** Telefón zmazal zdieľaný priečinok; notebook ho bez stiahnutia premenoval a odobral člena. Re-key server odmietol, rebase vzal kópiu zo servera (zmazanú) a premenovanie zmizlo bez konfliktu. Úprava sa teraz podrží (`held_edits`) a po pristátí dávky sa vráti ako konflikt so zmazaním zo servera; podpriečinok s úpravou z dávky odíde a ostane konfliktom (ako záznam pri SM37).

**Full resync nechá vlastnú zmenu bez základnej verzie (stavový test SM42).** Full resync nechal neodoslaný objekt, ktorého kópiu server nemal (GC zozbieral jeho tombstone). Objekt nemal zapísané, z ktorej serverovej verzie vychádza, takže ďalší push prepísal kópiu, ktorú medzitým poslalo iné zariadenie, bez konfliktu. Taký objekt teraz dostane základnú verziu 0 („postavené na ničom“) a súbežná serverová kópia sa vráti ako konflikt.

**Org recovery nad rotáciou so strateným potvrdením (stavový test SM43).** Telefón zrotoval identitu; server push prijal, odpoveď neprišla a zmena ostala čakať. Po zabudnutí hesla org recovery (Shamir) preniesla čakajúcu zmenu aj s rotáciou do svojej. Server už nové kľúče mal a každý push odmietol („An identity rotation needs new keys“). Push zmeny pri tomto odmietnutí pošle zmenu znova bez časti s rotáciou.

**Org recovery nad kľúčmi priečinkov, ktoré posunul iný počítač (stavový test SM44).** Notebook zmenil kľúče účtu (raz alebo dvakrát); telefón zmenu prevzal bez pullu, takže kľúče priečinkov (DEK) mal v starších verziách. Org recovery nič nesťahuje a prebalila tieto staré verzie; server mal novšie a zmenu pri každom pushi odmietol („Atomic batch conflict“). Keď server odmietne len DEK čakajúcej zmeny hesla s `old_kek`, push spraví pull: ten novšiu kópiu DEK zo servera (ktorú starý KEK neotvorí) prebalí do čakajúcej zmeny pod jej KEK na verzii servera a zmena odíde znova.

**Úprava stratená obnovou servera, ktorú prepísala vyššia verzia (stavový test SM45).** Telefón upravil záznam a pushol; server sa potom obnovil zo zálohy. Notebook, ktorý úpravu nevidel, záznam na zálohe zmenil dvakrát (alebo zmenil a zmazal), takže jeho verzia bola vyššia než telefónova. Full resync telefónu ju bral ako nasledovníka vlastného zápisu a úpravu zahodil bez konfliktu (SM13 chytal len rovnakú verziu, SM17 len nižšiu). Po zistenom rollbacku sa potvrdený zápis zariadenia, nad ktorého základom server drží cudzí zápis inej verzie, ponechá a vráti ako konflikt.

**Kľúč člena, ktorému zdieľal iný počítač toho istého admina (stavový test SM46).** Notebook zdieľal priečinok Bobovi a Carol; telefón obálky stiahol, ale žiadny záznam Carol nikdy neoveroval, takže jej kľúč pripnutý nemal. Odobratie Boba z telefónu (re-key pre Carol) aj rotácia identity telefónu (preklad jej obálky) zlyhávali natrvalo („Missing verified encryption key“). Pred re-key a v `prepare_key_change` klient (`pin_envelope_holder_keys`) stiahne kľúč takého člena zo servera a pripne ho len vtedy, keď ním otvorí vlastnú obálku účtu pre tohto člena (crypto_box je symetrický: tajný kľúč účtu + verejný kľúč člena). Kľúč, ktorý ju neotvorí (server podstrčil iný), sa odopne a re-key ostane čakať.

**Kľúč člena po prevzatí identity otočenej inde (stavový test SM83).** Notebook zdieľal priečinok Bobovi a Carol, Boba odobral (re-key) a otočil identitu účtu. Telefón mal len pôvodné obálky. Po prevzatí rotácie (`adopt_rotated_key_material`) má nový keypair, no jeho obálky pre Carol sú zapečatené ešte starým, takže nimi serverový kľúč Carol nedokázal a nepripol: dokončenie Bobovho re-key na telefóne padalo pri každom pushi („Missing verified encryption key“). Prevzatie teraz pred výmenou keypairu odloží starý tajný kľúč a `pin_envelope_holder_keys(former_sks=…)` overí kľúče členov aj ním; potom sa vynuluje.

**Obálka odobratého člena pod nahradeným kľúčom (stavové testy SM47, SM48).** Notebook aj telefón (ten istý admin) zdieľali priečinok Bobovi a jeden o obálke druhého nevedel. Notebook Boba odobral: re-key presunul priečinok na nový DEK a stiahol len obálku, ktorú poznal; obálka telefónu ostala živá pod starým DEK. Keď ju notebook stiahol, (SM47) rotácia identity ju preložila — nová obálka pre odobratého člena pod DEK, ktorý rotácia zároveň prebalila bez priečinka — a server celú rotáciu natrvalo odmietol („envelope references unknown DEK“). Rotácia teraz obálky pod nahradeným priečinkovým DEK (`scope = 'folder'`, `node_id IS NULL`) neprekladá: neotvárajú nič aktuálne. (SM48) Po zmene hesla (tiež prebalí starý DEK bez priečinka) re-key podľa SM23 obálku len sťahuje a server aj to odmietal; tombstone obálky pod DEK bez priečinka teraz prijme aj nad živou kópiou (obálky smie posielať len admin; prístup to len berie).

**Zahodený re-key a premenovanie (stavový test SM49).** Notebook premenoval podpriečinok a ešte ho neposlal; telefón medzitým odobral člena a priečinok prekľúčoval. Re-key notebooku (SM23) server odmietol, pull priviazal priečinok ku kľúču telefónu a prekonaný batch sa zahodil (`abandon_pending_rekey`): podpriečinok vzal kópiu zo servera a premenovanie zmizlo bez konfliktu, lebo sa držali len úpravy zapečatené kľúčom batchu. Vlastná úprava sa teraz drží vždy a vráti sa ako konflikt.

**Zahodený re-key a podpriečinok pod odobratým kľúčom (stavový test SM55).** Notebook poslal podpriečinok v zdieľanom priečinku (meno zapečatené DEK priečinka) a potom odobral člena; jeho re-key podpriečinok prepečatil o verziu vyššie. Telefón podpriečinok nestiahol a jeho re-key dorazil prvý bez neho. Pri zahodení prekonaného batchu notebooku sa podpriečinok bral za „špinavý len preto, že jeho priečinok dostal nový DEK“ a označil sa ako odoslaný: server ho navždy držal pod DEK, ktorý mal odobratý člen. Riadok nad verziou servera (`object_base_version`) ostáva neodoslaný a ide von pod aktuálnym kľúčom priečinka.

**Re-key stratený obnovou servera (stavový test SM50).** Notebook zdieľal priečinok Bobovi a potom ho odobral: re-key dal priečinku nový DEK a záznamy znova zapečatil, ale samotný priečinok ostal na svojej verzii. Server sa potom obnovil zo zálohy spred re-key. Full resync notebooku záznamy ponechal (sú novšie ako serverové), no nový DEK zahodil, lebo ho menoval len ponechaný priečinok alebo vlastný kľúč záznamu. Priečinok naň stále ukazoval a commit padol na cudzom kľúči (`FOREIGN KEY constraint failed`); ponechané záznamy by sa ani nedali dešifrovať. Ponechaný záznam bez vlastného kľúča teraz drží aj kľúč svojho priečinka. DEK sa pošle znova (vypadne z `pushed_dek_versions`) spolu so svojím archívom (`dek_archive`, cez `reseed_archive_ids`). Bez archívu by ho ostatné zariadenia brali ako tier-2 kľúč a priečinok by nechali na starom.

**Položka presunutá pod koreň (stavový test SM51).** Telefón zmazal podpriečinok S priečinka F, notebook zmazal F a GC tombstonov zobral oba. Telefón poslal tombstone S znova pod F, ktorý server už nemal, a notebook ho bez F ukázal pod koreňom: lokálny presun pri tej istej verzii. Po obnove zo zálohy si oba full resyncy S ponechali a notebook poslal svoju kópiu prvý, s koreňom ako rodičom. Server potom vlastný zápis telefónu pri tej verzii odmietal pri každom pushi (porovnáva len hash blobu, ten je rovnaký) a S na telefóne ostal navždy neodoslaný. Presun pod koreň sa teraz pamätá (`reattached_parents`); keď sa priečinok vráti, položka sa presunie späť, kým má ešte tú istú verziu.

**Rebase re-key a člen odobratý medzitým (stavový test SM52).** Notebook zdieľal priečinok Bobovi a telefón to stiahol. Potom notebook zdieľal priečinok aj Carol a upravil záznam, Carol bola na serveri odobratá a telefón, ktorý jej grant nevidel, odobral Boba. Re-key telefónu server pre úpravu odmietol; rebase stiahol Carolinu obálku na starom DEK a chcel pre ňu zapečatiť nový, no jej kľúč telefón nikdy nepripol: `Missing verified encryption key` pri každom pushi. Rebase teraz kľúče takých členov pripne ako SM46 (`pin_envelope_holder_keys`), a člen, ktorý je na serveri odobratý, obálku na novom DEK nedostane (server by ju odmietol a jeho vlastný re-key by ju aj tak zahodil).

**Zmazanie cez neodoslanú úpravu a full resync (stavový test SM53).** Telefón offline upravil záznam a potom ho zmazal. Notebook ten istý záznam zmazal, poslal a obnovil z koša; GC tombstonov potom zobral tombstone zo servera. Full resync telefónu bral jeho zmazanie za bezpredmetné (server záznam mal a už nemá) a riadok zahodil aj s úpravou v ňom: obnova sa vrátila so starým obsahom a úprava telefónu zmizla všade, bez konfliktu. Zmazanie viac ako o jednu verziu nad svojou bázou (`object_base_version`) nesie takú úpravu; ponechá sa a s obnovou sa stretne ako konflikt.

**Obnova na tombstone, ktorý GC dovolil prepísať (stavový test SM56).** Notebook zmazal priečinok a poslal to; telefón ho pred stiahnutím zmazania premenoval. GC tombstonov priečinok zo servera zobral a notebook ho obnovil z koša (zápis nad tombstonom vo verzii 2). Premenovanie telefónu potom odišlo ako verzia 2 (server priečinok už nemal), iná kópia v tej istej verzii. Server obnovu notebooku voči nej odmietol a pull notebooku tú kópiu preskočil ako takú, na ktorej jeho úprava už stojí (rovnaká verzia): obnova ostala neodoslaná v každom kole a bez konfliktu. Kópia vo verzii bázy s iným hashom, než si zariadenie pamätá (`object_base_hash`), sa teraz berie ako prepísaná a vráti sa ako konflikt.

**Priečinok vrátený iným zariadením po GC (stavový test SM59).** Notebook zmazal priečinok a GC tombstonov ho zo servera zobral. Full resync notebooku potom mal DEK priečinka (server ho drží, `parent_ref` stále menuje priečinok), ale nie priečinok, a DEK odviazal (`_detach_orphan_deks`). Telefón medzitým pridal do priečinka záznam a po vlastnom full resyncu priečinok vrátil. Pull notebooku ho dostal bez DEK, ktorý by ho menoval (server ten DEK znova neposiela), a priviazal ho ku kľúču rodiča: záznam telefónu sa tam neotvoril a člen, ktorému bol priečinok zdieľaný, ho akoby stratil. Odviazaný DEK si teraz pamätá svoj priečinok (`detached_dek_folders`) a keď sa priečinok vráti, znova k nemu patrí.

**Zadržané zmazanie a full resync (stavový test SM60).** Zahodený re-key člena zadržal zmazanie priečinka, ktorý iné zariadenie medzitým zmenilo; zmazanie sa vrátilo ako konflikt vo verzii kópie servera a s jej blobmi (teda aj s jej `payload_hash`). Full resync konflikt zmazal a zmazanie ponechal ako neodoslanú zmenu kópie servera (`object_base_version` aj `object_sent_version` sedeli na verzii servera): odoslané vo verzii, ktorú server drží živú, bolo pri každom pushi odmietnuté a nebolo čo urovnať. Zmena „na kópii servera“ v rovnakej verzii platí už len vtedy, keď lokálny riadok tou kópiou naozaj je (rovnaký príznak zmazania a rodič, `_is_server_copy`); inak ostáva konfliktom.

**Rotácia identity, ktorá dorazila, a prevzatie ďalšej zmeny kľúčov (stavový test SM61).** Notebook rotoval identitu (re-seal obálok členov ako nové obálky); server dávku prijal, odpoveď sa stratila a ďalší pull notebooku ju prešiel. Telefón rotáciu prevzal a zmenil heslo. Pri prevzatí tejto zmeny notebook svoju rotáciu zahodil ako nikdy neodoslanú (`_undo_unsent_identity_reseal`): re-sealovaná obálka zmizla a vrátila sa pôvodná. Server držal re-sealovanú živú a žiadny pull ju už nepriniesol, takže grant člena nemalo žiadne zariadenie a odobratie člena ho na serveri nechalo. Keď je kľúčový pár servera vlastnou rotáciou zariadenia, rotácia dorazila: `adopt_account_kek(own_rotation_landed=True)` jej obálky ponechá ako odoslané (`_keep_landed_identity_reseal`).

**Grant pod kľúčom, ktorý re-key nahradil (stavový test SM62).** Notebook odobral člena a re-key zdieľaného priečinka mal zostavený, ešte neodoslaný. Telefón (ten istý účet, bez pullu) medzitým priečinok zdieľal s iným členom pod starým kľúčom a server prijal oboje; re-key dal obálky na nový kľúč len členom, o ktorých notebook vedel, takže nový člen mal len vyradený kľúč a priečinok stratil na všetkých zariadeniach. Pull teraz (`_grant_again_on_successors`, po `_reseal_under_successors`) zapečatí obálku tohto účtu pod vyradeným kľúčom priečinka znova na jeho aktuálny kľúč, ak člen nie je na serveri odobratý a nečaká re-key. Archív DEK menuje len nový kľúč; starý sa k nemu nájde tak, že archív otvorí na jeho kľúč (`DEKManager.successor_of`). Tým istým sa rozpozná aj prebalenie vyradeného kľúča zmenou hesla na inom zariadení (jeho `parent_ref` stále menuje priečinok): `_bind_pulled_deks` ho nechá vyradený, predtým ho vzal za tier-2 kľúč a znova naviazal na priečinok.

**Zahodený re-key a úprava položky zmazanej inde (stavový test SM63).** Notebook upravil záznam (alebo premenoval podpriečinok) a neodoslal; telefón ho zmazal, odobral člena a re-key poslal prvý. Re-key notebooku server odmietol a zahodil sa ako prekonaný (`rekey_abandon`): položka prevzala kópiu servera (zmazanie) a zadržaná úprava sa brala ako zmazanie urobené tu a ticho skončila v histórii. Zadržaná úprava si teraz pamätá, že kópia servera je zmazanie (`server_deleted`, ako SM41 pri re-key priečinku), a vráti sa ako konflikt so zmazaním servera; `_restore_held_edits` záznam znova oživí. Stavový stroj zároveň po `prepare_key_change` sleduje, čo zariadenie stiahlo (aj keď synchronizácia potom zlyhala); inak bralo neskoršie zmazanie za urobené bez znalosti stiahnutého priečinka.

**Odpojený DEK pri opakovanom odoslaní zmeny hesla (stavový test SM64).** Notebook zmenil heslo; server zmenu prijal, odpoveď sa stratila. Server potom zozbieral tombstone zmazaného priečinka a full resync notebooku nechal DEK priečinka odpojený (`deks.node_id` NULL, priečinok si pamätá `detached_dek_folders`, SM59), hoci na serveri má DEK stále `parent_ref` priečinka. Pri opakovanom odoslaní zmeny sa DEK zostavil bez `parent_ref`, takže to nebol identický retry a server odmietal celú atomickú dávku pri každej synchronizácii (a nový re-wrap by väzbu na serveri zmazal). Odpojený DEK sa teraz posiela pod priečinkom, ktorý si pamätá.

**Org recovery na obnovenom serveri (stavový test SM65).** Server bol obnovený zo zálohy staršej ako posledný push notebooku a telefón potom pridal priečinok (DEK, ktorý notebook nevidel). Heslo notebooku sa obnovilo cez org recovery; zmene chýbal ten DEK a pull, ktorý ho mal priniesť, zistil obnovu servera a nič neaplikoval. Odmietnutie potom radilo `sezam abandon-pending-change`, čo potrebuje zabudnuté heslo, takže notebook nemal cestu von. Teraz hlási full resync (`sezam pull --full-resync`); ten je pri zmene so `old_kek` v žurnále povolený a chýbajúci DEK do zmeny pribalí.

**Zmena hesla po obnove servera skryla obnovu (stavový test SM66).** Notebook premenoval priečinok a pushol to; jeho zmena hesla potom neodišla a server sa obnovil zo zálohy spred premenovania. Čakajúca zmena blokuje full resync, preto jej push ide bez kontroly rollbacku (SM39). Ten push však posunul kotvu commitov notebooku na históriu obnoveného servera, nasledujúci pull obnovu nevidel a premenovanie, ktoré server stratil, už nikdy neodišlo: neskoršie premenovanie z telefónu ho nahradilo bez konfliktu. Keď zmena dorazí, push teraz hlási rollback (`rollback_warning`, `server_rollback_head`) a full resync premenovanie pošle znova.

**Web po odvolanej relácii (stavový test SM67, webové zariadenie).** Prehliadač mal vo fronte neodoslané uloženie, keď desktop zmenil heslo účtu; server pri tom odvolá všetky tokeny účtu. Stránka token neobnovila, ale ostala odomknutá: Retry aj každé uloženie padali na „Token revoked“ a nič nepovedalo, že sa treba znova prihlásiť. `apiFetch` teraz po neúspešnom obnovení tokenu ukončí reláciu s hláškou `error.session_ended` (súbežné 401 čakajú na to isté obnovenie, `_refreshInFlight`). Po prihlásení novým heslom sa neodoslaná zmena odloží a banner ju obnoví s predchádzajúcim heslom. Reláciu ukončí len server, ktorý obnovenie odmietne (401/403 z `/api/auth/refresh`); výpadok siete, 5xx, 429 alebo zlyhaný `/api/auth/challenge` reláciu nechajú, požiadavka skončí chybou `error.session_refresh_unavailable` a ďalšia skúsi obnovenie znova (review d615826, `tests/test_review6_web_refresh_unavailable.py`).

**Stratená odpoveď na obnovenie tokenu (review 7c10379, web).** Server odvolá starý token v tej istej transakcii, v ktorej vydá nový. Keď odpoveď k stránke nedošla, ostal jej len odvolaný token a ďalšie obnovenie skončilo reláciu. Na 401 z `/api/auth/refresh` sa stránka teraz znova prihlási podpísaným challenge s kľúčovým párom relácie (`reverifySession`). Reláciu nechá len vtedy, keď `/api/auth/verify` vráti ten istý `user_id` a ten istý `key_material_hash`, aký relácia drží; zmena hesla inde (iný `key_material_hash`), odvolaný účet, rotácia identity na inom zariadení (409) alebo iné odmietnutie z verify reláciu stále ukončia; nechá ju len 429, 5xx alebo zlyhaný challenge. 403 z refresh končí reláciu hneď. Server pridáva do JWT náhodné `jti`: Ed25519 je deterministický, takže dva tokeny jedného účtu v tej istej sekunde boli rovnaký reťazec a nové prihlásenie by vrátilo práve odvolaný token. Po opakovanej požiadavke `apiFetch` spracuje aj 304 a 410 ako prvá požiadavka. Test: `tests/test_review7_web_lost_refresh_response.py`.

**Záznam v zmazanom priečinku zastavil pull webu (stavový test SM68).** Web upravil záznam, desktop (bez pullu) zmazal jeho priečinok; zmazanie priečinka prešlo, záznamu skončilo konfliktom a desktop si nechal verziu servera, takže server drží živý záznam pod zmazaným priečinkom. Pull webu spúšťa migráciu starých osobných podstromov (`migrateLegacyPersonalDescendants`), ktorá prechádza rodičov každého objektu; chýbajúci priečinok hodil „Parent folder is unavailable.“ pri tomto aj každom ďalšom pulle. Objekt, ktorého priečinok stránka nedrží, teraz migrácia preskočí.

**Obnova servera stratila org recovery a nikto to nepovedal (stavový test SM69).** Admin nastavil org recovery, server ho zaregistroval, potom bol server obnovený zo zálohy spred nastavenia. Trezor si pamätal lokálnu značku „server ho má“ (`org_recovery_server_ok`) a server sa už nepýtal, takže push ani odomknutie nehlásili, že zdieľania na serveri nefungujú — admin by to zistil až po zabudnutí hesla. `registration_issue` sa teraz pýta servera zakaždým (značka zrušená) a po pushi vypíše výzvu na `sezam org-recovery-setup --replace`. Stavový test teraz po pushi robí to isté čo CLI (`register_while_password_known`), za pokojný stav berie len prázdne `pending_states()` a po settle overuje, že org recovery je na serveri alebo to zariadenie hlási.

**Zmena webu zaradená pred re-key odišla pod starým kľúčom (stavový test SM70).** Web uložil záznam v zdieľanom priečinku bez siete, stránka si zašifrovaný záznam zaradila do fronty. Admin potom odobral člena, čo priečinok pre-kľúčovalo; odobratý člen drží starý DEK. Stránka si stiahla nový DEK, ale Retry poslal záznam tak, ako bol — pod starým DEK, ktorý odobratý člen prečíta. `retryAllWebDirtyObjects` teraz zaradenú zmenu, ktorej DEK priečinka už nahradil novší (`resealUnderFolderSuccessor`), znova zapečatí pod aktuálnym DEK priečinka, tak ako desktop (`_reseal_under_successors`).

**Web po obnove servera zo zálohy (stavový test SM71).** Checkpoint stránky bol pred obnoveným serverom, takže každý pull — a s ním každé prihlásenie v tomto prehliadači — skončil `ROLLBACK DETECTED` bez cesty von. Otvorená stránka obnovu ani nezbadala: prázdna delta vracia `max_commit_seq` = `since_commit_seq` a kontrola brala väčšie z neho a `head_commit_seq`; teraz berie len hlavu servera. Keď obnovený server medzitým prijal nové commity za seq stránky, ukáže to len commit token: checkpoint si drží `commit_token` posledného videného commitu a delta pull posiela `check_seq`/`check_token` (ako desktop, SM7). Pri rozpore sa stránka spýta (`sync.rollback_confirm`), či správca server obnovil; áno = úplný pull overený ako vždy a nový checkpoint (ako `sezam pull --full-resync`), nie = nič sa nezmení. Neodoslané zmeny ostanú vo fronte; čo stránka po vytvorení zálohy už odoslala a iné zariadenie nemá, sa stratí — otázka to hovorí.

**Web: uloženie v živom priečinku pod zmazaným (stavový test SM72).** Web vytvoril priečinok v priečinku, ktorý desktop medzitým (bez pullu) zmazal; zmazanie prešlo, takže server drží živý priečinok pod zmazaným a stránka ho ukazuje navrchu. Uloženie priečinka či záznamu v ňom hľadalo osobný priečinok nad ním, narazilo na zmazaného rodiča a hodilo „Parent folder is unavailable.“. `resolveInheritedPersonalDekId` teraz pokračuje cez tombstone zmazaného priečinka (`trashedNode`: zapečatené meno povie, či bol osobný); nečitateľný tombstone naďalej zlyhá zatvorene.

**Re-key priečinka zmazaného inde aj s rodičom (stavový test SM73).** Iné zariadenie zmazalo zdieľaný priečinok aj priečinok nad ním; toto zariadenie (bez pullu) v ňom vytvorilo záznam a odobralo člena. Rebase odmietnutého re-key priniesol obe zmazania, push oba priečinky vrátil kvôli neodoslanému záznamu (SM34), ale atomická jednotka brala len re-keyovaný priečinok – rodič čakal na bežný push po nej, takže server jednotku odmietal („parent folder is deleted“) pri každom syncu. `_revive_folders_of_unsent` si oživené priečinky zapisuje do `revived_folders` a `_revived_ancestors` pridá do jednotky tie, ktoré ešte neodišli a sú nad jej objektmi. Zadržaná úprava priečinka sa potom vracala ako konflikt, ktorého serverová strana bola zmazanie videné pri rebase, nie živý priečinok, ktorý jednotka poslala – „Použiť serverovú“ ho zmazala len lokálne; tieň konfliktu teraz berie stav, ktorý jednotka poslala.

**Oživený priečinok po úplnom resyncu (R15, nočný beh na e443cbc, cieľ #429 b).** Ten istý stav, ale cesta von z čakajúceho re-key pred úplným resyncom viedla cez `abandon-rekey`. Resync zahodil všetky zápisy z fronty (`drop_all_writes`) a ponechané lokálne kópie zaradil znova ako obyčajné úpravy, takže priečinok, ktorý server drží zmazaný, stratil značku `revived`. Jednotka ho preto nebrala a server ju odmietal („parent folder is deleted“) pri každom syncu. `full_resync` si teraz pred zahodením zapamätá `revived_folders` a ponechanému priečinku značku vráti, ak ju mal, alebo ak je jeho serverová kópia zmazaná. Test: `test_sync_state_machine_rekey_below_a_folder_deleted_elsewhere_survives_a_full_resync` (červený na e7db410).

**Web: vlastný zápis pred cudzím re-key (stavový test SM74, webová obdoba SM28).** Web uložil záznam v zdieľanom priečinku a server ho prijal skôr, než iné zariadenie (ktoré ho ešte nevidelo) priečinok re-keyovalo po odobratí člena – na serveri tak ostal pod starým DEK, ktorý odobratý člen pozná. Web si teraz pamätá svoje prijaté zápisy (`sentWrites`: id → verzia, šifrované KEK v IndexedDB pod `sent_writes:<user>`) a po pulle (`resealOwnWritesUnderSuccessors`) každý taký zápis, ktorý server drží v tej istej verzii pod vyradeným DEK priečinka, zapečatí znova o verziu vyššie pod aktuálnym DEK a odošle. Cudzie zápisy nechá ich autorovi; konflikt ostane vo fronte.

**Re-key dokončí vlastník priečinka, nie len autor zápisu (capability review run 134).** `sentWrites` je šifrované KEK: po zmene hesla na inom zariadení (alebo v novej karte či prehliadači) sa stránka prihlási bez neho a desktop opečatí len svoje zápisy – záznam weba tak ostal pod DEK odobratého člena, bez chyby a bez čakajúceho stavu. Teraz po pulle opečatí každú živú položku pod vyradeným DEK priečinka (bez ohľadu na autora) aj zariadenie, ktorého KEK otvára aktuálny DEK priečinka (desktop: DEK nie je vo `foreign_dek_ids`, web: je v `state.kekDekIds`) – tak ako to robí samotný re-key. Člen (cudzí DEK) opečatí naďalej len svoje zápisy. Web rozpozná aj vyradený DEK bez väzby na priečinok (`parent_ref` prázdny – tak ho po zmene hesla pošle desktop) podľa jeho archívu (H3 nižšie). Ak opečatenie narazí na konflikt (iné zariadenie bolo prvé), stránka ho zahodí – menil len kľúč – a ďalší pull rozhodne znova. Stavový stroj má pravidlo `web_new_browser` (prihlásenie v inom prehliadači s prázdnou IndexedDB).

**Web: kľúč vyberajú len podpísané fakty (review d615826 H3).** Označenie `scope` pri DEK je nepodpísané a server ho môže prepísať. Podpriečinok, ktorého DEK server označil `tier2`, web preskočil a nový záznam zapečatil kľúčom nadradeného priečinka, ktorý číta aj člen s prístupom len k nemu. Osobný DEK označený `folder` bol pre web vyradený kľúč priečinka a opečatenie po re-key (vyššie) presunulo osobný priečinok pod zdieľaný kľúč rodiča. Za aktuálny kľúč priečinka sa navyše bral najnovší ULID bez dôkazu o re-key. Teraz rozhodujú len podpísané údaje: `parent_ref` DEK, tier-2 záznam, ktorý DEK menuje, a `dek_archive`. `provenDekSuccessors` otvorí každý archív novým DEK (hlavička musí menovať jeho `parent_ref`) a starý kľúč, ktorý v ňom je, je vyradený – ako desktopové `successor_of`. Vyradené DEK a ich nástupcu (`finalDekSuccessor`, cez celý reťazec) určujú len archívy. `nearestFolderDekId` neprejde k rodičovi, kým má priečinok vlastný držaný nevyradený kľúč; `scope` už len zoradí kľúče toho istého priečinka (`tests/test_review6_web_dek_scope.py`).

**Web: kľúč priečinka ako na desktope, len od admina, nie z budúcnosti (review 7c10379 H3).** Ľubovoľná položka s `tier: 2` v meta vyradila svoj kľúč z výberu. Jedna položka, ktorú člen s právom zápisu zapečatil kľúčom priečinka s `tier: 2` (alebo poctivý webový presun tier-2 položky, ktorý ju zapečatil kľúčom cieľového priečinka), tak spôsobila, že nové položky v priečinku sa pečatili kľúčom rodiča, ktorý čítajú aj členovia len rodiča. Navyše vyhralo najnovšie ID kľúča: kľúč, ktorý si člen podpísal s ULID z budúcnosti, ostal kľúčom priečinka aj po odobratí člena. `nearestFolderDekId` teraz kľúče priečinka zoradí ako desktopové `_is_folders_own_key`, a to len keď ich je viac: kľúč, ktorý pečatí podpriečinok alebo položku tier 0/1 toho priečinka, alebo je nástupcom z archívu re-key, je kľúč priečinka; kľúč, ktorý menujú len tier-2 položky (podpísané adminom alebo týmto účtom – len oni robia kľúče), je posledný; inak vyhrá novšie ID. Jediný kľúč priečinka je jeho kľúč (aj na desktope sa prvý kľúč priečinka stane jeho kľúčom). Kľúč s ULID časom viac ako 10 minút v budúcnosti sa ignoruje. Kľúče, envelope (`keyEnvelopesForUser` pri pulle) a archívy (`provenDekSuccessors`) web berie len od tohto účtu a od admina (`keyAuthors`: podpisovateľ priečinka najvyššej úrovne – ten server prijme len od admina a admin je len bootstrap účet). Presunutá tier-2 položka si nechá vlastný kľúč (`resolveWriteDekId`, ako desktop). Hranica: server, ktorý prijal priečinok najvyššej úrovne od člena, z neho urobí „admina“ aj tu – nič podpísané adminov neuvádza (rovnako ako pri H4, #335). `tests/test_review7_web_folder_key_h3.py` zlyhá na kóde pred opravou (b60a91e).

**Web: kľúče nie ako hex reťazce (review 7c10379).** `provenDekSuccessors`, ktorý beží pri každom pulle aj novej položke, mal mapu s hex reťazcom každého držaného DEK a každého kľúča otvoreného z archívu re-key. Reťazec sa nedá vymazať, takže `memzero` nad `state.deks` pri zamknutí nechal kópie kľúčov priečinkov v pamäti. Starý kľúč z archívu sa teraz porovná bajt po bajte (`memcmp`) a hneď vymaže. Test `tests/test_review7_web_keys_not_hex.py` (žiadny `bytesToHex` nad kľúčom, otvorený kľúč vymazaný) zlyhá na kóde pred opravou.

**Desktop: rolu DEK neurčuje `scope` zo servera (capability review 149, 151).** Kľúč, ktorý zariadenie drží, si štítok ponechá. Nový kľúč, ktorého podpísaný `parent_ref` menuje priečinok, je kľúč priečinka bez ohľadu na štítok: označený `tier2` sa nerátal za vlastný kľúč priečinka a ďalší pullnutý tier-2 kľúč ho v priečinku nahradil; `root`/`audit` by ním pečatil priečinky najvyššej úrovne či audit. `tier2` odvodí `_bind_pulled_deks` (druhý kľúč priečinka bez archívu re-key), `personal` z podpísaných metadát (len osobný koreň má meta zapečatené vlastným kľúčom, `crud._node_meta_dek`). Ani nový vlastný kľúč bez `parent_ref` si rolu zo štítku neberie (stavový test SM82: auditný kľúč iného zariadenia sa stal ďalším koreňovým, koreňový auditným): `_derive_unbound_scope` ho určí z podpísaných metadát — zapečatí meta uzla bez rodiča → `root`, meta iného uzla → `personal` (osobný kľúč člena nemá `parent_ref`), meta položky → `tier2` (kľúč tier-2 položky v strome osobného koreňa, TL7), nič → `audit`; `_adopt_server_root` koreňu rolu `root` dá aj vtedy, keď jeho uzol prišiel až v ďalšej strane (`tests/test_review6_desktop_dek_scope_lie.py`; stavový stroj porovná štítok nového kľúča s tým, čo poslal poctivý server).

**Desktop: kľúč priečinka vs. tier-2 kľúč neurčuje poradie zo servera (capability review 155).** Kľúč priečinka aj jeho tier-2 kľúče majú `parent_ref` na ten istý priečinok; vlastným kľúčom sa stal ten, ktorý server v pulle poslal prvý (nepodpísané poradie), druhý dostal `tier2`. Server tak bez zmeny jediného podpísaného bajtu vymenil role: nové položky a podpriečinky by sa pečatili tier-2 kľúčom a tier-2 položky ostali pod kľúčom, ktorý má každý člen. `_bind_pulled_deks` teraz pri druhom kľúči priečinka bez archívu re-key rozhodne cez `_is_folders_own_key` z podpísaných faktov: meta podpriečinka je zapečatené vlastným kľúčom rodiča → kľúč priečinka; položka s `tier: 2` v podpísaných meta zapečatená kľúčom → tier-2 kľúč; ak nič z toho, vyhrá skoršie (podpísané) ID kľúča — kľúč priečinka vzniká s priečinkom, tier-2 kľúče neskôr. Test v tom istom súbore obráti poradie DEK v odpovedi; stavový stroj má lož `dek_order` (priečinok s položkou tier 1 a tier 2 z iného zariadenia, obrátené DEK v pulle) a overí štítky aj väzbu priečinka na jeho kľúč.

**Desktop: zadržaný archív re-key nevráti priečinok na vyradený kľúč (capability review 157).** Po odobratí člena majú nový kľúč priečinka aj vyradený kľúč (ten, ktorý odobratý člen drží) `parent_ref` na ten istý priečinok; spája ich len objekt `dek_archive`. Server, ktorý ho novému zariadeniu (alebo full resyncu) v pulle neposlal, nechal rozhodnúť pravidlo „skoršie ID vyhrá“ — a skoršie ID má vyradený kľúč: nové položky v priečinku by sa pečatili kľúčom odobratého člena. `_is_folders_own_key` teraz za podpísaný fakt „kľúč priečinka“ berie aj položku tier 0/1 v tom priečinku, ktorej meta je kľúčom zapečatené (re-key ich všetky prepečatí na nový kľúč), a keď nerozhodne nič, vyhrá neskoršie ID: nástupca re-key je vždy neskorší než kľúč, ktorý vyraďuje, a tier-2 kľúč bez položky má menej držiteľov než priečinok. `tests/test_review6_withheld_rekey_archive.py` (archív vynechaný, aj s obráteným poradím DEK) zlyhá na 12957e2; stavový stroj na konci každého príkladu, v ktorom server drží archív re-key, pripojí ďalšie nové zariadenie s vynechanými `dek_archive` a overí, že každý priečinok má ten istý kľúč ako na poctivom novom zariadení (archív menuje len nástupcu, nie vyradený kľúč — capability review 158; so starou logikou 12957e2 to zlyhá, s opravou prejde).

**Desktop: zmazané položky nerozhodujú, ktorý kľúč priečinka je aktuálny (stavový stroj, druhý admin).** Re-key prepečatí len živé deti priečinka; náhrobky zmazaných položiek a podpriečinkov ostanú zapečatené vyradeným kľúčom. Priečinok, ktorého deti boli všetky zmazané, sa bez archívu re-key na novom zariadení viazal na vyradený kľúč, lebo ten jediný ešte niečo pečatil. Fakt „kľúč priečinka“ v `_is_folders_own_key` teraz dávajú len živé deti (`is_deleted = 0`). Tier 2 v podpísanej mete zmazanej položky stále označí tier-2 kľúč, lebo táto rola sa nemení. Variant `deleted_entry` v `tests/test_review6_withheld_rekey_archive.py` zlyhá na kóde pred opravou.

**Desktop: odmietnutý re-key priečinka s podpriečinkom pristane aj po premenovaní podpriečinka inde (stavový stroj, druhý admin).** Podpriečinok je v dávke dvakrát: ako dieťa re-keyovaného rodiča (jeho meta je zapečatená kľúčom rodiča) a ako priečinok svojho nového kľúča. `_rebase_pending_rekey` kópiu servera v prechode rodiča prepečatil novým kľúčom rodiča, no prechod podpriečinka videl, že nie je zapečatená jeho starým kľúčom, a vrátil ju tak, ako ju má server, vo verzii servera. Každý ďalší push potom celú dávku odmietol („Atomic re-key batch conflict“). Kópiu zapečatenú starým kľúčom iného priečinka z tej istej dávky teraz prechod podpriečinka nechá na prechod rodiča. `tests/test_review6_rekey_rebase_nested_folder.py` (obe poradia `dek_map`) zlyhá na kóde pred opravou.

**Desktop: vlastný grant neprepadne s re-key, ktorý predbehlo iné zariadenie (stavový stroj, druhý admin).** Telefón zdieľal priečinok s Carol a pushol. Notebook (bez pullu) odobral Boba a nový kľúč dal len členom, o ktorých vedel; Carol mal grant znovu zapečatiť pull telefónu (SM62, run 140). Telefón však Boba odobral tiež: jeho vlastný re-key zmazal Carolinu obálku lokálne, kým dávka neodíde. Pull ju potom priniesol zo servera späť a `_apply_envelope` ju zapísal do `pulled_envelopes` (cudzí grant, ktorý pull podľa H2 znovu nepečatí); predbehnutú dávku telefón zahodil a Carol mala na každom zariadení len vyradený kľúč. Obálka, ktorú zmazal vlastný čakajúci re-key tohto zariadenia (`envelope_tombstones`), sa teraz za stiahnutú nepočíta — stiahnutá bola zapísaná už pri prvom príchode. `tests/test_review6_superseded_rekey_keeps_own_grant.py` zlyhá na kóde pred opravou.

**Desktop: podpriečinok bez vlastného kľúča ide s priečinkom aj bez archívu re-key (stavový stroj, druhý admin).** Podpriečinok bez vlastného kľúča (taký robí webový klient) si pri aplikovaní vzal kľúč rodiča, ešte pred viazaním kľúčov. S archívom `_bind_pulled_deks` presunie na nástupcu všetky uzly starého kľúča; bez archívu (rozhodne `_is_folders_own_key`) sa presunul len priečinok a podpriečinok na novom zariadení ostal na vyradenom kľúči. Teraz ide na nový kľúč priečinka každý uzol, ktorý mal ten starý. Variant `shared_subfolder` v `tests/test_review6_withheld_rekey_archive.py` zlyhá na kóde pred opravou.

**Web: plný pull po obnove servera (stavový test SM75).** Web odoslal zmeny, server sa potom obnovil zo zálohy spred nich a iné zariadenie naň zapísalo commity za seq stránky. Delta pull posiela token posledného commitu stránky (SM71), plný pull („Použiť serverovú“ pri konflikte, prihlásenie v novej karte) však neposielal nič, videl seq servera pred checkpointom a stav obnoveného servera prevzal bez otázky – čo mala len stránka, zmizlo. Plný pull teraz posiela `check_seq`/`check_token` checkpointu tiež a pri nezhode sa pýta ako SM71.

**Web: checkpoint prežije zmenu hesla inde (stavový test SM89).** Server sa obnovil zo zálohy a notebook potom na ňom zmenil heslo účtu. Checkpoint stránky bol zapečatený KEK-om: prvé prihlásenie novým heslom ho ako nečitateľný odložil a zahodil, plný pull nemal s čím porovnať a stav obnoveného servera prevzal bez otázky SM71 — položka, ktorú stránka uložila, zmizla bez slova. Kľúč odvodený z podpisového kľúča účtu nestačil: rotácia identity na inom zariadení ho zmení a checkpoint sa zahodil rovnako (SM90). Checkpoint je teraz zapečatený náhodným kľúčom tohto prehliadača (`syncCheckpointKey`, záznam `sync_checkpoint_key:<user>` v IndexedDB, AAD `sezam-sync-checkpoint-v2`), ktorý žiadna zmena kľúčov účtu nemení; chráni pred serverom, nie pred týmto prehliadačom (kto sem môže písať, checkpoint aj zmaže). Starý záznam (v1, KEK) sa ešte prečíta. `tests/test_web_restore_after_key_change_sm89.py` (zmena hesla aj rotácia identity) zlyhá na starom kóde.

**Shamir obnova po re-key so strateným potvrdením (stavový test SM77).** Re-key dávka po odobratí člena dorazila na server, odpoveď sa stratila, dávka ostala čakať a pull priniesol jej nový DEK priečinka. Org recovery (Shamir) čakajúci re-key zahodí (review 526419e V4) — aj tento, a s ním zmazala nový DEK, ktorý server drží. Zmena hesla z obnovy musí prebaliť každý DEK servera, takže ju server odmietal pri každom syncu („every active DEK“) a cesta von (`sezam abandon-pending-change`) potrebovala zabudnuté heslo. Dávka je atomická: keď server drží niektorý z jej nových DEK (`SyncClient.rekey_batch_on_server`), `SyncClient.close_rekey_if_landed` ju uzavrie ako odoslanú a zahodí sa len neodoslaná.

**`sezam abandon-rekey` po dávke, ktorá dorazila (stavový test SM78).** Pri zahodení re-key, ktorého odpoveď sa stratila, sa objekty dávky zapečatili späť pod starý DEK v tej verzii, ktorú dávka poslala. Server tú verziu už mal (pod novým DEK), takže každý push objekt odmietol ako konflikt, ktorý sa nedal vyriešiť, a sync sa nikdy neustálil. `abandon_pending_rekey` teraz kópiu, ktorú vyrobil re-key, zapečatí o verziu vyššie; prejde, či dávka na server dorazila, alebo nie.

**`sezam abandon-rekey` po pulle, ktorý dávku priniesol späť (stavový test SM84).** Dávka dorazila, odpoveď sa stratila a pull priniesol jej nový DEK priečinka; potom používateľ re-key zahodil. Zahodenie vrátilo priečinok pod starý DEK a nový zmazalo, hoci server aj druhý admin mali priečinok pod novým. Checkpoint bol už za ním, takže obálka, ktorú druhý admin zapečatil novému DEK, sa odkazovala na kľúč, ktorý zariadenie nemalo: každý pull padal na „FOREIGN KEY constraint failed“. Ako pri SM77: keď server drží niektorý nový DEK dávky, `abandon_pending_rekey` (aj rebase odmietnutej dávky) ju cez `close_rekey_if_landed` uzavrie ako odoslanú — člen ostáva odobratý (`requeued: False`).

**Či dávka dorazila, povie len server (R15, capability run 437, nočný beh 44891798136).** Predtým to rozhodovali tri lokálne stopy: `pushed_dek_versions` (restore a reseed ho mažú), kópia dávky, ktorú priniesol pull (len neodoslané riadky), a konfliktná kópia zapečatená novým DEK (SM25, pýtal sa jej len rebase). Každá cesta sa pýtala inej. Keď dávka dorazila, odpoveď sa stratila a server hneď nato vymyslel hlavu (full resync), nemala stopu žiadna: `abandon-rekey` vrátil priečinky pod starý DEK, nový zmazal, resync priniesol priečinok pod novým kľúčom, ktorý zariadenie už nemalo, a podpriečinok sa nedal otvoriť („Decryption failed“). Teraz sa všetky cesty (abandon, rebase, Shamir obnova, push) pýtajú jednej funkcie `SyncClient.rekey_batch_on_server`: `POST /api/objects/held {ids}` vráti, ktoré z daných objektov server drží (id, typ, verzia, zmazaný; bez payloadu, max. 200 id). Nové DEK dávky vytvorilo len toto zariadenie a posiela ich len v nej, takže jeden z nich na serveri dokazuje celú atomickú dávku. Nedostupný server chybu vyhodí — nehádá sa. Web dávku po odmietnutí vždy postaví znova zo stavu servera (nič lokálne nevracia), mobil člena nepreklúčuje. Testy `test_sync_state_machine_rekey_landed_with_its_reply_lost_is_not_abandoned` (červený na e443cbc, 42ab802, 1dc89e4) a `tests/test_r15_rekey_landed_on_server.py`.

**`sezam abandon-rekey` a cudzia obálka na novom DEK (review a159e97 H1).** Zahodenie re-key znova pečatí obálky udelené na nový DEK dávky, kým čakala. Bralo každú obálku bez ohľadu na to, kto ju vytvoril, takže účet „Eve“, ktorý vyrobil server a ktorý si obálku podpísal sám, dostal kľúč, pod ktorý sa priečinok vrátil (a ďalší re-key mu poslal aj nový). `_grant_again` teraz rovnako ako re-key (`reseal_key_row`) pečatí len obálku, ktorú udelil tento účet, alebo členovi s potvrdeným fingerprintom. Platí aj pre automatické zahodenie pri org recovery a pri prekonanej dávke. Test `tests/test_review8_abandon_foreign_grant.py`.

**Zápis pod neznámym priečinkom (review a159e97 H2).** Filter podvrhnutých zápisov (7c10379 H4) posudzuje priečinok alebo položku podľa priečinka, do ktorého sú zapísané. Rodiča, ktorého desktop nepoznal, pustil bez posúdenia a `_reattach_orphans` ho potom zavesil priamo pod root admina, kde ostal aj po každom ďalšom poctivom pulle. Serveru stačilo rodiča raz zadržať. Taký zápis teraz čaká v `writes_below_unknown_folders` (celý objekt, ako ho server poslal) a posúdi sa, keď rodič dorazí (`_with_held_back_writes` ho pridá k ďalšiemu pullu), spolu so všetkým pod ním; novšia kópia v pulle ho nahradí. Zápis tohto účtu alebo admina sa aplikuje ako doteraz (osirelý objekt pod rootom, d150605 #1). Full resync stav začne odznova zo snímky. Test `tests/test_review8_unknown_parent_h2.py`.

**Nepodpísaný `access_level` obálky (review a159e97 H3).** Úroveň prístupu nie je v podpise obálky. Server, ktorý zmenil „read“ na „write“, ho mal pri ďalšom pulle uložený na desktope a nasledujúci re-key ho skopíroval do obálky, ktorú admin zapečatil a poslal; eskalácia ostala, aj keď server prestal klamať. Chýbajúca úroveň znamenala „write“. Teraz: chýbajúca alebo neznáma úroveň je „read“; obálka vytvorená na tomto zariadení (nie je v `pulled_envelopes`) si pri pulle ponechá svoju úroveň; nová obálka (re-key, zahodenie re-key, rotácia identity) prevezme „write“ len z obálky vytvorenej na tomto zariadení (`vouched_access_level`), inak dostane „read“ a varovanie (zdieľať znova s právom zápisu). Podpísaný prístup prinesie tímový denník (#346). Test `tests/test_review8_unsigned_access_level_h3.py`.

**Cudzí audit záznam, ktorý sa nedá overiť (review a159e97 H11, regresia 3d59ab3).** Od 3d59ab3 full resync znova posiela záznamy iných účtov, ktoré obnovený server stratil (`audit_sync_state = 2`). Server obnovený zo zálohy pred rotáciou identity admina však pozná len jeho starý kľúč; záznamy podpísané novým kľúčom sa pri zostavení pushu neoverili a každý sync člena (aj full resync) skončil na „Invalid audit signature“. Cudzí záznam, ktorý sa kľúčom známym teraz neoverí, sa už nepošle (stav 1, varovanie); vlastný záznam, ktorý sa neoverí, ďalej zastaví push. Test `test_sync_state_machine_restore_loses_another_accounts_rotation`.

**Re-key z frontu na server obnovený zo zálohy (stavový test SM85).** Člen bol odobratý a priečinok prekľúčovaný nad kópiami, ktoré obnovený server už nemá. `sezam push` posiela re-key z frontu ako prvý: server ho odmietol („Server history changed“ alebo konflikt atomickej dávky, ktorej pull uvidel obnovu) a push hlásil rollback, no front namiesto toho pri každom syncu padal na „The re-key batch was not accepted“, prípadne „Atomic re-key batch conflict“, takže plný resync, ktorý varovanie menuje, sa nikdy neponúkol. Konflikt dávky so známym (alebo práve zisteným) rollbackom teraz vráti `rollback_warning` a `finish_queued_revocations` dávku nechá čakať; cesta von (zahodiť re-key, plný resync, push) člena odstrihne.

**Pull vrátil vlastnú kópiu riadku, ktorý ostal dirty (stavový test SM86).** Push podpriečinka dorazil, odpoveď sa stratila a riadok ostal dirty. Pull potom priniesol presne tú kópiu (vlastný odoslaný hash) spolu s re-keyom priečinka z iného zariadenia: základ sa posunul na jej verziu, no riadok ostal dirty na tej istej verzii. `_reseal_under_successors` neodoslanú zmenu zapečatí nanovo bez zvýšenia verzie, takže išla von ako zmena verzie, ktorú server už má, a server ju odmietal pri každom syncu (pri dávke re-keyu „Atomic re-key batch conflict“). Riadok, ktorého bloby, rodič a príznak zmazania sú presne serverová kópia, je teraz čistý (`_holds_server_copy`), a prepečatenie ide o verziu vyššie.

**Push za obnovou servera bez stratených DEK (stavový test SM87).** Re-key po odobratí člena dorazil, server sa potom obnovil zo zálohy staršej než on a nový DEK stratil. Notebook zmazal záznam (jeho kópia v koši ostáva zapečatená tým DEK) a odobral ďalšieho člena. S čakajúcim re-keyom ide push nekontrolovane za obnovu (SM39) a znova posiela stratené auditné záznamy, no stratený DEK nie: notebook ho mal v `pushed_dek_versions` ako uložený na serveri. Zmazaný záznam tak pristál pod kľúčom, ktorý iné zariadenie nedostane, a telefón ho v koši neotvoril. `_resend_audit_lost_by_restore` teraz zo snímky servera vyradí z `pushed_dek_versions` aj DEK, ktoré obnovený server nemá, a push ich pošle znova.

**Push za obnovou, ktorá stratila zmenu hesla (stavový test, druhý admin, bg238).** Notebook zmenil heslo a server zmenu prijal; potom sa server obnovil zo zálohy staršej než ona. Notebook odobral člena a re-key sa neodoslal. Jeho push narazil na obnovu, prečítal snímku servera na opätovné odoslanie strateného (SM39) a poslal re-key bez kontroly obnovy, s key_epoch, ktorý server už nemal. Zariadenie epochu považovalo za odoslanú, takže neposlalo všetky DEK, a server dávku odmietal pri každom pushi („Key epoch advance must include every active DEK“). `_resend_audit_lost_by_restore` teraz na tú snímku volá `_check_key_epoch` ako každý pull (SM12): zariadenie dostane `KeyEpochStale`, prevezme kľúčový materiál servera s heslom, ktoré server má, a re-key potom prejde. Čakajúca zmena hesla sa nekontroluje: tá prebalí všetky DEK a jej odmietnutie pomenuje cestu von (SM9). Test: `test_review6_key_change_lost_with_pending_rekey.py` (na starom kóde padá).

**Záznam presunutý von z priečinka prekonaného re-keyu (stavový test SM88).** Obe zariadenia admina odobrali člena; re-key telefónu dorazil prvý. Notebook pred vlastným pushom presunul záznam z toho priečinka do podpriečinka s vlastným DEK a zapečatil ho jeho kľúčom. Dávku notebooku server odmietol ako prekonanú a `abandon_pending_rekey` ju zahodil; presun išiel von nad re-key telefónu (SM1), no zapečatený znova kľúčom serverovej kópie, teda novým kľúčom pôvodného priečinka, hoci záznam už leží v podpriečinku. Žiadne zariadenie ho tam neotvorilo („Decryption failed“). Záznam presunutý do priečinka mimo dávky (iný rodič než serverová kópia, nezapečatený kľúčom dávky) teraz ostane zapečatený kľúčom svojho nového priečinka.

**Full resync a neodoslané zmeny (review d150605 #6).** Full resync po 410 (GC posunul `gc_floor_seq` za checkpoint) nahradil lokálnu kópiu serverovou a zahodil, čo zariadenie vytvorilo alebo upravilo offline. Desktop teraz pri full resyncu nechá každý vlastný neodoslaný (`is_dirty`) priečinok a záznam aj s ich kľúčmi a priečinkami nad nimi, ktoré server nemá. Výnimkou je len neodoslané zmazanie niečoho, čo server už nemá. Všetko ostane neodoslané a odíde ďalším pushom; novšia serverová kópia sa vráti ako konflikt. `sezam pull --full-resync` po resyncu ponúkne push. `--export-dirty PATH` uloží šifrovanú kópiu trezoru (ako `sezam export --format backup`), ktorú otvorí aktuálne heslo a `sezam restore PATH` ju načíta späť.

### 8.4 Known limitation: split-view

Server môže dvom klientom ukazovať rôzne svety (rôzne vault_objects). Bez zdieľanej state-root kotvy (gossip/blockchain) toto nie je detekovateľné. Pre malý dôveryhodný tím je to prijateľný kompromis.

---

## 9. Threat Model

### 9.1 Čo chránime

| Asset | Ochrana |
|-------|---------|
| Heslá, SSH kľúče, API tokeny | AEAD šifrovanie (XChaCha20-Poly1305) + KEK/DEK hierarchia |
| Názvy záznamov, kľúče polí | V `encrypted_meta`/`encrypted_data` — server nevidí |
| Štruktúra trezoru (názvy priečinkov) | V `encrypted_meta` — server nevidí |
| Identita používateľa | Ed25519 challenge-response (heslo nikdy neopustí zariadenie) |
| Integrita audit logu | Ed25519 podpisy + Merkle DAG |
| Integrita sync objektov | Ed25519 podpisy na každom objekte |

### 9.2 Útočné vektory a mitigácie

| Vektor | Mitigácia | Reziduálne riziko |
|--------|-----------|-------------------|
| **Brute-force master password** | Argon2id (256MB, 3 iter) | Slabé heslo = ohrozenie. Sila hesla je rozhodujúca. |
| **Server compromise** | Content-blind design. Server vidí len šifrované bloby. | Útočník vidí topológiu, veľkosti, vzory aktivity. Offline brute-force na encrypted_keypair. |
| **Admin compromise** | Known limitation — admin má KEK --> všetky DEK-y. | Plný prístup k celému vaultu. Rovnaký model ako KeePass/Bitwarden self-hosted. |
| **MITM (server podmieňa kľúče)** | TOFU + fingerprint overenie + lokálny key cache | Prvotné overenie musí byť mimo pásma (osobne/telefonicky). |
| **Replay (zachytený auth request)** | Challenge nonce + 30s timestamp + spent_challenges | — |
| **Swap útok (zámena blobov)** | AAD s blob_kind, dek_id, object_id, version | — |
| **Rollback (server vráti staršie dáta)** | state_hash checkpoint + per-object version | Split-view nie je detekovateľný bez gossip. |
| **Clipboard sniffing** | Auto-clear 15s + UI varovanie o clipboard managers | Clipboard manager môže zachytiť pred clearom. |
| **Memory dump** | bytearray + explicit zeroize (best-effort) | Python/JS GC môže mať kópie v pamäti. |
| **Side-channel (timing)** | Konštantný čas pre error responses. Fake salts pre neexistujúcich userov. | — |
| **DoS na recovery** | Proof sa overí pred zámkom; hádanie obmedzené per IP (10/h) | Cudzie zlé proofy nevymknú vlastníka — správne heslo prejde a zámok zruší. |
| **Share link brute-force** | 256-bit random ID + optional PIN (rate limited) | — |

### 9.3 Čo vedome NECHRÁNIME

| Scenár | Dôvod |
|--------|-------|
| Admin compromise --> plný prístup | Single-admin model (scope). Multi-admin quorum = Phase 4+. |
| Metadata leak medzi usermi (počty, veľkosti) | Pull model posiela celý vault všetkým. Bandwidth/simplicity trade-off. |
| Side-channel na veľkosť blobov | Padding (mocnina 2) ho redukuje, ale neodstraňuje úplne. |
| Python/JS memory safety | GC nemá secure zeroize. Dokumentované, nie záruka. |
| Split-view server útok | Vyžaduje gossip/blockchain, mimo scope. |

### 9.4 Encrypted keypair na serveri

**Vedomý kompromis:** `users.encrypted_keypair` na serveri = kompromitovaná DB --> offline brute-force na master password. Argon2id (256 MB) to robí extrémne pomalé, ale bezpečnosť = sila hesla.

**Alternatívy zvážené a zamietnuté:**
- SRP (Secure Remote Password): komplexné, obmedzená implementácia
- OPAQUE: ešte experimentálne (IETF draft)
- Zero-knowledge auth only: neumožňuje password-based recovery

---

## 10. Key Rotation

### 10.1 Zmena master hesla

```
1.  Staré heslo --> Argon2id --> starý KEK
2.  Odomkni všetky aktívne DEK-y (Root, per-folder, Audit, Tier2)
3.  Nové heslo --> Argon2id (NOVÝ salt) --> nový KEK
4.  Re-wrap všetky aktívne DEK-y novým KEK-om
5.  dek_archive: chain wrap DEK-y nie sú ovplyvnené (zabalené DEK-om, nie KEK-om)
6.  Audit DEK zostáva rovnaký (len nový KEK wrap) — chain nenarušený
7.  Ak existuje org recovery wrap: re-wrap nový KEK recovery kľúčom
8.  Re-encrypt encrypted_keypair novým KEK-om
9.  Re-derive auth_proof = Argon2id(nové_heslo, nový_auth_salt)
10. Upload: PUT /api/me/keypair {encrypted_keypair, argon2_salt, auth_salt, auth_proof}
    --> Server si dopočíta nový auth_proof_hash = HMAC-SHA256(verify_salt, auth_proof)
11. Inkrementuj key_epoch v vault_meta
12. Push na server. Server uloží key_epoch do sync_state
13. Atomic write lokálne
```

**key_epoch:** Globálny counter zmien hesla/KEK. Klient s nižším key_epoch musí urobiť pull pred push-om (zastaraný KEK wrap).

**Edge case — klient offline počas viacerých zmien hesla:**
Klient má starý KEK, server má encrypted_keypair wrappovaný novým KEK-om. Riešenie: klient pozná AKTUÁLNE heslo --> Cesta B recovery. Ak NEPOZNÁ aktuálne heslo --> „zabudnuté heslo" scenár.

**Zmena hesla v inom procese na tom istom desktope (review d615826 H4):** GUI alebo `sezam mcp-serve` ostane odomknuté so starým KEK-om, kým `sezam change-password` v inom procese prebalí všetky DEK-y novým KEK-om. DEK, ktorý starý proces potom zabalil starým KEK-om (nový priečinok, nová verzia wrapu, prebalenie po prevzatí rotácie), už neotvorilo ani staré, ani nové heslo. `DEKManager` si preto pri odomknutí zapamätá `kek_dek_id` z `vault_meta` a pred každým KEK wrapom (`create_dek`, nová verzia wrapu, `rewrap_all_deks`) aj pred `change_password` ho porovná s uloženým: ak sa líšia, vyhodí `KeyChangedElsewhere` („heslo bolo zmenené v inom programe Sezam, zamknite a odomknite trezor novým heslom“) a nič nezapíše. Test `tests/test_review6_stale_kek_process.py`: dva `Vault` objekty nad tým istým súborom, druhý zmení heslo, prvý nesmie vytvoriť priečinok ani zmeniť heslo a trezor sa potom otvorí novým heslom so všetkými DEK-mi. Review 7c10379 doplnil tú istú kontrolu na ďalšie miesta, ktoré pracujú s KEK-om procesu: `setup_org_recovery` (Shamir podiely zapečatili starý KEK, takže obnova nimi vrátila kľúč, ktorý trezor už nemá), `rebind_server_identity` (pripojenie v GUI prebalilo keypair starým KEK-om s novým `kek_dek_id` a trezor potom neotvorilo ani jedno heslo) a `current_auth_proof` (registrácia org recovery po pripojení brala nové heslo za zlé). Test `tests/test_review7_stale_kek_recovery_rebind.py`. Tiež sync: pull takého procesu posudzoval vlastníctvo DEK-u jeho starým KEK-om, takže DEK, ktorý iné zariadenie účtu vytvorilo pod novým account KEK-om, natrvalo zaradil do `foreign_dek_ids` (každá ďalšia zmena kľúčov a re-key ho potom vynechali); full resync tak označil všetky DEK-y. `SyncClient.pull`, `push`, `full_resync` a `Vault.adopt_account_kek` (aj jeho skratka pri rovnakom KEK-u, ktorá menila len `key_epoch`) preto začínajú `_require_current_kek` a takému procesu vyhodia `KeyChangedElsewhere` skôr, než sa dotknú trezoru alebo siete. Test `tests/test_review7_stale_kek_pull.py`; state machine má pravidlo `second_process_pull` (odmietnutý pull nič nezmení, úspešný nenechá na zozname cudzích žiadny DEK, ktorý otvára KEK trezoru).

**Medziprocesový zámok pre sync a zmenu kľúčov (review d615826 H4):** push, pull alebo full resync v GUI či `mcp-serve` nič neusporiadalo voči zmene hesla, prevzatiu rotácie alebo re-key v inom procese. `vault/oplock.py` drží exkluzívny zámok súboru `sezam.db.sync` (OS zámok rovnaký ako `inuse.py` usporiada procesy, RLock podľa cesty vlákna jedného procesu, vnorené držanie v jednom vlákne — push vnútri re-key alebo pullu — je zadarmo). Držia ho `SyncClient.push`, `pull`, `full_resync`, `adopt_rotated_key_material`, `abandon_pending_change`, `abandon_pending_rekey`, `Vault.change_password` (aj rotácia identity), `Vault.rekey_after_revocation`, `Vault.org_recovery` (Shamir obnova, `sezam org-recovery`) a `Vault.adopt_account_kek` (prevzatie hesla zmeneného inde z CLI aj z GUI dialógu pripojenia) — každá operácia, ktorá prebalí DEK alebo zmení `key_epoch` (capability review run 144). Druhý proces čaká najviac 120 s, potom dostane `VaultBusy` („iný program Sezam práve synchronizuje alebo mení kľúče trezoru“) ešte pred akýmkoľvek zápisom alebo sieťou. Na súborovom systéme bez zámkov sa usporiadajú len vlákna toho istého procesu. Bežné zápisy (aj odomknutie a `sezam list`) berú len zápisový zámok `sezam.db.write`; držiteľ sync zámku ho pustí počas každej sieťovej požiadavky mimo transakcie, takže na sieť push-u nečakajú (R16-M3, `tests/test_r16_push_lock_network.py`). Test `tests/test_review6_vault_oplock.py`: zámok v druhom procese zdrží zmenu hesla, Shamir obnovu aj prevzatie account KEK (bez zápisu do `vault_meta`), po vypršaní čakania ju aj push/pull/full resync/abandon-rekey odmietnu a vlákna sa striedajú.

### 10.2 Identity key rotation (incident response)

`PATCH /api/users/:id/rotate-keys` ostáva vypnuté (410): menil verejné kľúče na mieste, ale `encrypted_keypair` ostal so starými súkromnými kľúčmi. Rotácia identity ide ako zmena hesla — jedným pushom, ktorý posúva `key_epoch` (idea #11, `sezam rotate-identity`):

```
1. Desktop vygeneruje nový Ed25519 + X25519 keypair a lokálne (jedna DB transakcia):
   - prebalí DEK-y, zašifruje NOVÝ keypair KEK-om, key_epoch + 1,
   - certifikát: key_rotation_message(user, staré pk, nové pk) podpíše nový kľúč
     (rotation_signature) aj starý kľúč (authorization_signature),
   - obálky, ktoré tento používateľ zapečatil, zapečatí znova novým kľúčom pre
     pripnutý kľúč príjemcu; staré idú ako tombstone v tej istej dávke,
   - žurnál pending_key_rotation drží auth proof a starý súkromný keypair
     (zapečatené KEK-om): kým server rotáciu neprijme, prihlásenie ide starým kľúčom.
2. POST /api/sync {atomic_batch, key_epoch+1, key_rotation: {..., identity}}
   --> challenge podpísaný NOVÝM kľúčom, authorization_signature overená
       aktuálnym (starým) kľúčom účtu, objekty dávky overené novým kľúčom
   --> v jednej transakcii: user_key_archives (starý kľúč, certifikát,
       authorization_signature, retired_seq = posledný commit_seq pred touto dávkou),
       users.signing_pk/encryption_pk/key_fingerprint, encrypted_keypair,
       key_epoch, token_epoch + 1 (staré tokeny neplatia)
   --> archivovaný kľúč sa nesmie vrátiť ako nový (409)
3. Klienti overujú staré podpisy cez certifikovaný archív (GET /api/users/:id/keys).
   Archív vracia aj authorization_signature (ak je, musí platiť starým kľúčom).
   Podpis archivovaného (vyradeného) kľúča platí len pre presnú verziu objektu,
   ktorú menuje zoznam „key vouchers“ (review e443cbc R15, cieľ #443, INV-3):
   - Správa zoznamu: doména `sezam-key-vouchers-v1` + user_id + signer_pk +
     zoradené položky (id, version u64, payload_hash 32 B); podpis AKTUÁLNYM
     kľúčom účtu, ktorý zoznam posiela (`src/sezam/key_vouchers.py`, JS v app.js,
     Dart `mobile/lib/services/key_vouchers.dart`, spoločné vektory
     `tests/vectors/key_vouchers.json`).
   - Server: tabuľka `key_vouchers`; GET /api/users/:id/key-vouchers vráti len
     zoznamy podpísané aktuálnym kľúčom účtu, POST /api/users/me/key-vouchers
     zoznam pridá (aditívne, podpis aktuálnym kľúčom volajúceho), GET
     /api/users/me/signed-objects dá zariadeniu živé verzie, ktoré účet podpísal.
     Rotácia identity v pushi nesie zoznam podpísaný NOVÝM kľúčom a uloží ho v tej
     istej transakcii; keď v ňom chýba živý objekt starého kľúča, server vráti 409
     `key_vouchers_incomplete`.
   - Klient (desktop `sync_vouchers.py`, web, mobil) uzná podpis vyradeného kľúča
     pre (id, version, payload_hash), ak ho menuje zoznam podpísaný aktuálnym
     kľúčom (a) účtu podpisovateľa, (b) vlastného účtu zariadenia, (c) aktuálneho
     admina z overeného tímového denníka, alebo ak zariadenie túto verziu samo
     drží overenú (desktop, mobil; full resync tak nestratí overené kópie). Inak
     pull zlyhá a chyba menuje účet, ktorého vyradený kľúč objekt podpísal.
   - `retired_seq` (archív) a `commit_seq` (objekt) sú slová servera: klient ich
     na rozhodnutie nečíta (`server/app/unsigned_fields.py`: UNREAD / HINT).
     Pripínanie hraníc (`archived_key_bounds`) zaniklo.
   - Rotácie spred #443 a neaktívne účty (capability review run 480): každý
     desktop pošle zoznam verzií vyradených kľúčov, ktoré drží, pri prvom sync s
     #443 a po každej rotácii, ktorú uvidí. Člen, ktorý takú verziu nikdy nedržal
     a nedrží ju ani jeho účet ani admin, ju dostane, až keď sa synchronizuje
     podpisovateľ, admin alebo iné zariadenie jeho účtu.
   - Testy: `tests/test_key_vouchers_*.py` (vektory, server, desktop, web,
     telefón) a pravidlo stavového testu `server_holds_a_leaked_retired_key`
     (nové zariadenie, full resync, web).
   Ostatní členovia dostanú TOFU varovanie a nový fingerprint si overia s používateľom;
   po potvrdení desktop drží aj certifikovaný reťazec starých kľúčov.
   Iné zariadenie toho istého účtu so starým keypairom: /api/auth/verify vráti
   409 "Identity key rotated" (podpis platí len archivovaným kľúčom, token nie je),
   desktop/mobil to berú ako KeyEpochStale a nový keypair prevezmú heslom cez
   /api/auth/recover. Web otvára keypair zo servera pri každom prihlásení a vlastný
   pripnutý kľúč po rotácii prepíše (dokazuje ho keypair, ktorý otvorilo heslo).
4. Obálky zapečatené PRE starý encryption kľúč musí ich autor po overení
   nového fingerprintu vystaviť znova (sezam grant-access). Grant zistí, že
   existujúca obálka je pre iný kľúč (crypto_box ju vlastným kľúčom a aktuálnym
   kľúčom člena neotvorí), zapečatí novú a mŕtvu stiahne tombstonom v tej istej
   atomickej dávke (review 688edcb).
5. Stratená odpoveď vlastnej rotácie (review 688edcb): starý kľúč zo žurnálu
   dostane 409 "Identity key rotated", desktop sa potom prihlási novým kľúčom
   a opakovaný push žurnál uzavrie. KeyEpochStale je len vtedy, keď neplatí
   ani nový kľúč (rotáciu vyhralo iné zariadenie).
6. Prehratá offline rotácia: po prevzatí víťaznej rotácie heslom desktop vráti
   pôvodné obálky z tombstonov dávky a znova zapečatené (kľúčom, ktorý nikto
   nepozná) zahodí; pull potom prinesie obálky víťaza. Nič pod prehratým
   kľúčom sa nepushne.
```

**Žiadne DELETE + re-CREATE** — `users.username` je UNIQUE, rotation je in-place update.

**Posun `key_epoch` dokazuje aktuálne heslo (review 688edcb K1).** Podpis identitným kľúčom nestačí — práve ten môže byť ukradnutý, a útočník by si nastavil vlastné heslo a vlastníka natrvalo vymkol. Každý `key_rotation`, ktorý posúva epochu (zmena hesla, `rotate-identity`, KDF upgrade), musí niesť jedno z:

- `current_auth_proof` — proof hesla, ktoré server ešte má (desktop ho odvodí z Argon2 behu, ktorým overuje staré heslo, a drží ho zapečatený v žurnáli). Zlý proof sa počíta do rovnakých per-name počítadiel ako `/api/auth/recover` (403, po `recovery_max_total` 423).
- `recovery_challenge` + `recovery_signature` — challenge z `/api/org-recovery/challenge` podpísaný kľúčom odvodeným zo zloženého Shamir kľúča; platí len pre účet, ktorý org recovery na serveri nastavil. Web aj desktop (review e4cd15a #1): `sezam org-recovery-setup` (aj GUI) pri pripojenom trezore zaregistruje na serveri `recovery_signing_pk` (Ed25519 zo seedu = recovery secret, ako web) a blob vo webovom formáte (`nonce‖XChaCha20-Poly1305(KEK)`, AAD `sezam-org-recovery-v1`), takže shares fungujú aj na webe. `sezam org-recovery` zapečatí recovery secret do žurnálu; push ním podpíše challenge a po prijatí zmeny prebalí serverový blob na nový KEK. Ak server prebalenie neprijme (review 526419e N5; predtým sa to len zalogovalo a žurnál so secretom už bol preč, takže server navždy držal blob starého KEK a shares tam prestali fungovať), verejné telo `/store` čaká vo `vault_meta.org_recovery_rewrap_pending`, každý push ho skúsi znova, `sezam push` aj `sezam org-recovery` varujú a `sezam status` ho vypíše; 409 (účet medzitým zmenil heslo inde) ho zahodí, zmena KEK tiež. Jediný admin tak po obnove synchronizuje bez povolenia iného admina. Setup na ešte nepripojenom trezore (capability review run 91): verejné telo registrácie (`wrapped_kek` zapečatený recovery secretom, `recovery_signing_pk`, prah, počet, `key_epoch`) čaká vo `vault_meta.org_recovery_server_pending` a `sezam connect` (aj GUI) ho s dôkazom hesla pošle; po prijatí sa zmaže. Každá zmena KEK (zmena hesla, prevzatie kľúča účtu pri Path B, org recovery) ho zahodí, lebo by balil starý KEK. Ak connect nájde org recovery bez registrácie a server nemá aktuálny blob tohto účtu, varuje a odporučí `org-recovery-setup --replace`. Testy: `tests/test_org_recovery_setup_before_connect.py`.

**Kontrola registrácie, kým heslo poznáme (review 526419e V5, `vault/org_recovery_server.py`).** GUI odomknutie a `sezam push` (po úspešnom pushi) pri pripojenom trezore s `org_recovery_pk` zistia, či server recovery kľúč pozná: čakajúce telo pošlú s heslom z odomknutia (CLI sa na heslo opýta, bez terminálu len upozorní), a keď telo chýba a `/api/org-recovery/status` nemá blob tohto účtu (setup spred f7f43cc), upozornia, aby admin, kým heslo pozná, spustil `org-recovery-setup --replace`. Potvrdený kľúč si trezor pamätá v `vault_meta.org_recovery_server_ok` (= `org_recovery_pk`), ďalšie kontroly nejdú na server. `org-recovery-setup` (CLI aj GUI) registruje pred zobrazením shares: náhradu (`--replace`), ktorú server neprijme, vráti späť (staré shares platia) a skončí chybou; počas neodoslanej zmeny hesla náhradu odmietne vopred, lebo dôkaz nového hesla by server započítal ako zlý pokus. Prvý setup, ktorý server neprijal, zostane lokálne a registráciu ponúkne ďalší push/odomknutie. Testy: `tests/test_org_recovery_registration_check.py`.

**Obnova, ktorú server už má (review 526419e S2+S3).** Server drží jednu org recovery (`org_recovery_blobs.id = 1`). `org-recovery-setup` (CLI aj GUI) sa pred setupom spýta `/api/org-recovery/status`: obnovu tohto účtu z webu či iného zariadenia nahradí len s `--replace` (alebo potvrdením), obnovu iného admina len s `--replace-other-admin` (posiela `replace_other_admin`), inak skončí bez zmeny. Hláška pri inom adminovi neradí `--replace` (server by vrátil 409), ale povie, že po `sezam org-recovery` reset povolí iný admin (`sezam allow-key-reset`), a nahradenie jeho dielov len po dohode. Rovnako odomknutie/push (raz pre daný `org_recovery_pk`, `vault_meta.org_recovery_other_admin_noted`) a `sezam connect`. Testy: `tests/test_org_recovery_server_replace.py`.
- jednorazové povolenie iného admina: `POST /api/users/:id/allow-key-reset` (`sezam allow-key-reset <user_id>`, platí 1 h, sám sebe ho admin dať nemôže) — pre desktop org recovery, ktorej recovery kľúč server nepozná (shares spred e4cd15a #1).

**Registrácia NOVÉHO recovery kľúča dokazuje aktuálne heslo (review e4cd15a #1).** Recovery kľúč smie meniť kľúčový materiál, preto `POST /api/org-recovery/store` s iným `recovery_signing_pk`, než aký účet už má, vyžaduje `current_auth_proof` (zlý sa počíta ako pri `/recover`). Inak by si zlodej identitného kľúča zaregistroval vlastný recovery kľúč a heslo ním zmenil. Opätovné uloženie toho istého kľúča (prebalený KEK po zmene hesla) bez dôkazu hesla musí podpísať samotný recovery kľúč (`recovery_signature` nad `sezam-org-recovery-rewrap-v1\0 || user_id || u64be key_epoch || u8 threshold || u8 total_shares || SHA-256(wrapped_kek)`; review d615826). Predtým ho server prijal len s JWT, takže zlodej identitného kľúča nahradil blob, ktorý shares otvárajú, a obnova zlyhala práve vtedy, keď bola treba. Desktop (`_restore_org_recovery_blob`) aj web (journal `recovery_store`) podpisujú, kým recovery tajomstvo držia; telo alebo journal spred opravy server odmietne 403 a obnova sa ohlási ako zastaraná. Web si pri nastavení pýta heslo účtu (`shamir-password`). Zamknuté meno má tu rovnakú bránu ako výmena kľúčového materiálu (review 526419e V6, `key_gate_wait_s`): jeden overený dôkaz za okno, medzitým 429 + `Retry-After` bez overenia, aj pre správny dôkaz. Predtým sa overoval každý, takže zlodej identitného kľúča hádal heslo bez obmedzenia a správny tip prešiel aj pri zamknutom mene.

**Org recovery na webe v organizácii s viacerými používateľmi (review d615826).** Server posiela každému všetky objekty, aj DEK objekty kolegov s ich `owner_id`. Web si z pullu ukladal záznam objektu bez `owner_id` a objekt bez vlastníka počíta `ownKekDekIdsToRewrap` za vlastný. DEK kolegu, ktorý admin svojím KEK neotvorí, preto zastavil obnovu (`recovery.unlock_all_deks_failed`), len čo mal na serveri trezor ďalší používateľ. Záznam teraz `owner_id` drží (`syncObjectRecord`). Test so skutočným app.js a serverom: `tests/test_review6_web_org_recovery_two_users.py`. Review 7c10379: `owner_id` je však slovo servera. Server, ktorý za vlastníka nášho DEK označil kolegu, ho z prebalenia vynechal a DEK ostal pod KEK, ktorý obnova nahradila; náš ako vlastník cudzieho DEK obnovu zastavil. Vlastný je teraz DEK, ktorý náš KEK otvoril, alebo ktorý sme podpísali (overený `signature_user_id`); záznam bez podpisovateľa aj vlastníka ostáva vlastný (`tests/test_review7_web_org_recovery_signer.py`).

**Odmietnutý journal zmeny hesla na webe sa zahodí (review e4cd15a, nízke).** Org recovery na webe si zmenu hesla drží v journale v IndexedDB (`pending_kek_rotation:<meno>`) a prerušenú dokončí pri ďalšom prihlásení novým heslom. Keď ju server odmietne s 409 (napr. „Key epoch advance must include every active DEK“: na inom zariadení medzitým pribudol dátový kľúč), journal sa už nikdy neprijme. Predtým sa posielal pri každom prihlásení donekonečna. Teraz sa pri 409 zahodí a prihlásenie skončí hláškou `recovery.rotation_refused` (prihlásiť sa aktuálnym heslom účtu alebo obnovu zopakovať). Prehratý súboj epoch („Stale key epoch“) ostáva `KeyEpochChangedError`.

Opakované odoslanie už prijatej rotácie (stratená odpoveď) epochu neposúva a dôkaz nepotrebuje.

Poradie (review e4cd15a #2): správny `current_auth_proof` → platný recovery dôkaz → povolenie admina → až potom sa zlý proof odmietne (403) a započíta. Zariadenie, ktorého žurnál dokazuje heslo, ktoré server už nemá, tak s povolením admina prejde bez ďalších započítaných pokusov.

**Jedna neodoslaná zmena naraz (review 688edcb K2).** Kým žurnál `pending_key_rotation` čaká na server, desktop ďalšiu zmenu hesla ani `rotate-identity` nespraví („run 'sezam push' first“) — nový žurnál by prepísal proof hesla a starý identitný kľúč, ktoré server ešte pozná, a každé prihlásenie zariadenia by skončilo 401. Org recovery (heslo nepozná, čakať nemôže) z čakajúceho žurnálu prenesie `current_auth_proof`, `identity` a starý keypair do nového; povolenie iného admina vtedy netreba.

**Úniková cesta zo zaseknutého žurnálu (review e4cd15a #2).** Žurnál, ktorý server nikdy neprijme (spred K1 bez `current_auth_proof`, proof hesla, ktoré server už nemá, alebo rotácia prehratá s iným zariadením — aj keď org recovery posunula lokálnu epochu o dve vpred), zahodí `sezam abandon-pending-change` (žurnál spred K1 radšej dokončí `sezam finish-pending-change`: `/auth/recover` overí heslo servera, jeho dôkaz sa zapečatí do žurnálu a push pošle nové heslo; review 4acfdde R11): s heslom, ktoré má server teraz, prevezme kľúčový materiál zo servera (Path B, ako pri zmene hesla inde) a žurnál zmaže; dáta a ostatné zmeny ostanú. Pred tým varuje a pýta sa (`--yes` to preskočí; review 526419e N6): zahodí nové heslo nastavené na tomto zariadení a pri rotácii identity kľúča aj ju, takže starý (možno uniknutý) kľúč na serveri ostáva platný a treba hneď znova `sezam rotate-identity`. `sezam push` to pri 403 na vlastnú zmenu hesla poradí spolu s `allow-key-reset`. Rival rotáciu pod lokálnou epochou (`last_pushed < server_epoch ≤ local_epoch`, iný `key_material_hash`) pull aj push hlásia ako `KeyEpochStale` (prevzatie heslom), nie trvalým 409 „must include every active DEK“.

---

## 11. Shamir Secret Sharing

### 11.1 Implementácia

Schéma: `(t, n) = (3, 5)` nad **GF(2^8)** (Galois Field s 256 prvkami).

**Prečo GF(256):**
- Každý bajt je prvok poľa (jednoduchá byte-level aritmetika)
- Ireducibilný polynóm: `x^8 + x^4 + x^3 + x + 1` (0x11B, AES polynóm)
- Sčítanie = XOR, násobenie = lookup tabuľka alebo Russian Peasant algorithm

### 11.2 Algoritmus

```python
# Generovanie shares
def split_secret(secret: bytes, threshold: int = 3, shares: int = 5) -> list:
    """
    Rozdelí secret na n shares, t shares stačí na rekonštrukciu.
    secret: arbitrary-length bytes
    """
    result_shares = [bytearray() for _ in range(shares)]

    for byte_val in secret:
        # Pre každý bajt: vytvor polynóm stupňa (threshold-1)
        # konštantný člen = byte_val (tajomstvo)
        coefficients = [byte_val] + [secrets.randbelow(256) for _ in range(threshold - 1)]

        for i in range(shares):
            x = i + 1  # evaluation points 1..n (NIKDY 0 — to je tajomstvo)
            y = evaluate_polynomial_gf256(coefficients, x)
            result_shares[i].append(y)

    return [(i + 1, bytes(result_shares[i])) for i in range(shares)]


# Rekonštrukcia
def reconstruct_secret(shares: list, threshold: int = 3) -> bytes:
    """
    Lagrangeova interpolácia nad GF(256).
    shares: [(x_i, bytes), ...], musia byť minimálne threshold shares
    """
    assert len(shares) >= threshold

    xs = [s[0] for s in shares[:threshold]]
    secret = bytearray()

    for byte_idx in range(len(shares[0][1])):
        ys = [s[1][byte_idx] for s in shares[:threshold]]
        # Lagrangeova interpolácia, evaluácia v x=0
        value = lagrange_interpolate_gf256(xs, ys, x=0)
        secret.append(value)

    return bytes(secret)


def lagrange_interpolate_gf256(xs, ys, x):
    """Lagrangeova interpolácia nad GF(256)."""
    result = 0
    for i in range(len(xs)):
        basis = ys[i]
        for j in range(len(xs)):
            if i != j:
                # basis *= (x - xs[j]) / (xs[i] - xs[j])  v GF(256)
                basis = gf256_mul(basis,
                    gf256_mul(
                        gf256_sub(x, xs[j]),
                        gf256_inv(gf256_sub(xs[i], xs[j]))
                    )
                )
        result = gf256_add(result, basis)
    return result
```

### 11.3 GF(256) operácie

```python
# Sčítanie/odčítanie v GF(256) = XOR
def gf256_add(a, b): return a ^ b
def gf256_sub(a, b): return a ^ b  # rovnaké ako add

# Násobenie v GF(256)
def gf256_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return EXP_TABLE[(LOG_TABLE[a] + LOG_TABLE[b]) % 255]

# Inverzia v GF(256)
def gf256_inv(a):
    assert a != 0, "Zero has no inverse"
    return EXP_TABLE[255 - LOG_TABLE[a]]

# LOG a EXP tabuľky: predpočítané z generátora g=3 nad x^8+x^4+x^3+x+1
```

### 11.4 Recovery flow

```
1. 3 z 5 dôveryhodných osôb sa fyzicky stretnú
2. Každá zadá svoju časť (share)
3. Systém zrekonštruuje recovery kľúč = Lagrangeova interpolácia
4. recovery_key --> odomkne KEK wrapper (separátna obálka v deks pre root scope)
5. KEK --> všetky DEK-y --> celý vault
6. Nové master heslo --> nový KEK --> re-wrap DEK-y
7. Nový recovery key (voliteľne) --> nové shares
```

---

## 12. Memory Safety

### 12.1 Python desktop

**Stratégia: best-effort zeroize s bytearray**

```python
# SPRÁVNE: bytearray — mutable, explicit zeroize
kek = bytearray(argon2_hash)
try:
    # použitie kek
    ...
finally:
    kek[:] = b'\x00' * len(kek)  # explicit zeroize

# NESPRÁVNE: bytes — immutable, Python intern cache
kek = bytes(argon2_hash)  # NIKDY pre kryptomateriál!
```

**Dokumentované limitácie:**

| Limitácia | Dôvod | Mitigácia |
|-----------|-------|-----------|
| Python GC môže mať kópie | CPython reference counting + cyklický GC | `gc.collect()` po zeroize, ale nie záruka |
| `bytearray` resize môže realokovať | malloc implementácia | Pre-alokovať fixnú veľkosť |
| Swap file | OS môže swapovať RAM na disk | `mlock()` (Linux), nie vždy dostupné |
| Core dump | OS môže dumpovať pamäť pri crash | `setrlimit(RLIMIT_CORE, 0)` |

### 12.2 JavaScript web

**Stratégia: TypedArray + explicit zeroize + scope**

```javascript
// Kľúčový materiál v Uint8Array
const kek = new Uint8Array(32);
try {
    // ...použitie...
} finally {
    kek.fill(0);  // explicit zeroize
    // ale: GC môže mať referenciu ešte X ms
}
```

**Dokumentované limitácie:**

| Limitácia | Dôvod |
|-----------|-------|
| V8/SpiderMonkey GC | Nepodporuje secure zeroize |
| `crypto.subtle` vnútorné buffery | Mimo kontroly JS kódu |
| IndexedDB | Šifrované dáta, ale kľúčom prehliadača (nie používateľovým) |
| Dev Tools / Memory Inspector | Prístup ku všetkej pamäti |

### 12.3 Best practices

1. Kľúčový materiál výhradne v `bytearray` (Python) / `Uint8Array` (JS)
2. Explicit `fill(0)` / `[:] = b'\x00'...` v `finally` bloku
3. Minimálna životnosť: dešifruj, použi, zeroizuj
4. Auto-lock po 15 min nečinnosti — vymazanie všetkých DEK-ov z RAM. Na desktope je aktivitou písanie, klik aj koliesko kdekoľvek v aplikácii, aj v otvorenom dialógu (inak by auto-lock zatvoril dialóg s rozpísanou poznámkou). Kým beží volanie servera na pozadí (napr. odobratie člena a re-key jeho priečinkov), auto-lock počká a skúsi znova o 5 s. Ak sa re-key po odobratí na serveri predsa nepodarí, hláška povie, čo naozaj ostalo: čakajúca dávka, člen vo fronte (re-keyuje ho ďalší push), alebo – pri zamknutom trezore – nič, a treba odomknúť a odobrať člena znova (review 526419e S6+S7).

---

## 13. Web Security

### 13.1 Content Security Policy (CSP)

```http
Content-Security-Policy:
    default-src 'self';
    script-src 'self';
    style-src 'self' 'unsafe-inline';
    object-src 'none';
    base-uri 'self';
    frame-ancestors 'none';
    form-action 'self';
    connect-src 'self';
    img-src 'self' data:;
    font-src 'self';
```

**Žiadne inline skripty.** Všetky JS súbory sú externé, s SRI hashmi.

### 13.2 Subresource Integrity (SRI)

```html
<script src="/js/libsodium-wrappers.min.js"
        integrity="sha384-abc123..."
        crossorigin="anonymous"></script>
<script src="/js/argon2.min.js"
        integrity="sha384-def456..."
        crossorigin="anonymous"></script>
```

### 13.3 Ďalšie hlavičky

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### 13.4 IndexedDB a iOS Safari

**Problém:** iOS Safari maže IndexedDB po 7 dňoch nečinnosti.

**Riešenie:**
- Primárny storage: `encrypted_keypair` na serveri (vyžaduje heslo na dešifrovanie)
- Sekundárny: `.sezam-key` offline backup
- UI varovanie: „iOS Safari môže vymazať dáta po 7 dňoch nečinnosti."
- Auto-recovery: ak IndexedDB je prázdna, automaticky ponúkne Cestu B (password-based recovery)

**Cachovaný keypair po zmene kľúčového materiálu inde (lockout review N5):** keypair z IndexedDB sa otvorí heslom, pod ktorým bol uložený, aj keď účet medzitým dostal iný wrap. `POST /api/auth/verify` preto vracia `key_material_hash` (SHA-256 aktuálneho `encrypted_keypair` účtu). Keď sa hash nezhoduje s cachovaným wrapom (alebo server cachovaný kľúč odmietne s 401), web vydaný token hneď odvolá (`/api/auth/logout`), stiahne aktuálny wrap cez `/api/auth/recover` s proofom z tohto hesla a cache ním nahradí. Zastarané heslo tak skončí ako zlé heslo, aktuálne heslo prihlási a opraví cache. Hranica: identitný kľúč sa pri zmene hesla nemení, takže kto má starú cache aj staré heslo, má aj podpisový kľúč; kontrola chráni pred odomknutím aplikácie pod zastaraným KEK, nie pred takýmto útočníkom.

### 13.5 TOFU (Trust On First Use)

- Pri onboardingu kolega verifikuje fingerprint mimo pásma (osobne/telefonicky)
- Klient lokálne cachuje verejné kľúče v `known_keys`
- Pri každej interakcii porovnáva server kľúče s cache
- Zmena kľúčov --> GUI varovanie (MITM detection, analogicky SSH `known_hosts`)

### 13.6 Web Worker pre Argon2id

Argon2id WASM **MUSÍ** bežať vo Web Worker-i:
- Hlavné vlákno zobrazuje spinner
- Bez Worker-a: mobilný Safari môže zabiť tab pre OOM
- Desktop prehliadač zamrzne na 1-3s

Limity a zlyhania (lockout review N1):
- Parametre z `/api/meta` musia byť v rozsahu účtu na serveri (`AccountKdfParams`: time ≤ 20, pamäť ≤ 256 MiB, parallelism ≤ 8; v `app.js` `ARGON2_ACCOUNT_MAX`). Inak web nepokračuje a zobrazí `error.kdf_params_unsupported`.
- Worker má 60 s a pri time_cost nad 3 ďalších 10 s za každý stupeň (t=20 → 230 s).
- Ak worker zlyhá (OOM, timeout, chyba), derivácia sa na hlavnom vlákne **neopakuje**. Web zobrazí `error.kdf_failed` s odporúčaním použiť iný prehliadač alebo desktop/mobil. Hlavné vlákno sa použije len vtedy, keď prehliadač Worker vôbec nevie vytvoriť.

Účty bez uložených KDF parametrov (lockout review N2):
- Účet vytvorený pred stĺpcom `users.argon2_params` má NULL. `/api/meta` ho hlási so serverovým defaultom (3 / 128 MiB / 4), čo pre účet vytvorený s inými parametrami (napr. desktop 256 MiB alebo kalibrované) nedá správny KEK.
- Žiadny klient parametre nehádá: chýbajúce parametre v `/api/meta` sú chyba (web `error.kdf_params_unsupported`, mobil `FormatException`, desktop `RuntimeError`).
- Zariadenie, ktorého lokálny salt sa zhoduje so serverovým, použije svoje lokálne parametre (desktop `server_account_kdf`, mobil `_accountKdfFor`). Pri inom salte (heslo zmenené inde) platia serverové, no desktop ich neprijme pod tvrdou hranicou webu (spec 7.2: `time_cost` ≥ 2, `memory_cost` ≥ 64 MiB), zníženou nanajvýš na parametre, s ktorými bol vytvorený lokálny trezor. Inak by server, ktorý ohlási zmenu hesla s lacnými parametrami, dostal auth proof prelomiteľný offline (review d615826, `tests/test_review6_kdf_floor.py`).
- Desktop po prihlásení (`SyncClient.authenticate`) porovná serverové parametre s lokálnymi pri rovnakom salte. Ak sa líšia, pošle ich cez `PUT /api/me/kdf-params` so signed challenge. Server ich uloží len pri aktuálnom salte a len do NULL; uložené parametre nemení (409). Salt, pre ktorý je to vybavené, si desktop pamätá (`kdf_params_reported_salt`).
- Každý klient posiela v `/api/auth/recover` aj `argon2_params`, z ktorých odvodil proof. Pri zhodnom proofe server uloží tieto parametre do NULL účtu; uložené nemení.
- Nový kľúčový materiál (`PUT /api/me/keypair`, `key_rotation`) bez `argon2_params` server odmietne, takže ďalšie NULL účty nevznikajú. Posielajú ho tak len klienty spred N2: dostanú **426 Upgrade Required** s vetou „This Sezam app is too old for this server … Nothing was changed. Update the app and try again.“ (`OUTDATED_CLIENT_KDF`, review 688edcb N2), nie holú 422 o chýbajúcom poli. Push s takou rotáciou sa odmietne ešte pred prvým dotazom do DB.
- Zostáva: NULL účet vytvorený s inými než default parametrami, ku ktorému už nie je zariadenie s lokálnym trezorom, sa dá otvoriť len zálohou `.sezam-key` (nesie vlastné parametre) alebo org recovery.

```javascript
// main.js
const worker = new Worker('/js/crypto-worker.js');
worker.postMessage({
    action: 'derive_kek',
    password: password,
    salt: salt
});
worker.onmessage = (e) => {
    const kek = e.data.kek;
    // ...
};
```

---

## 14. Dátový model

### 14.1 Lokálna SQLite schéma (sezam.db)

Na Linuxe a macOS patrí adresár trezoru (`0700`) a `sezam.db` s `-wal`/`-shm` (`0600`) iba vlastníkovi. Nový `sezam.db` vznikne s `0600` skôr, než ho SQLite otvorí, a starší trezor s voľnejšími právami sa sprísni pri otvorení. Inak by ho mohol skopírovať iný lokálny používateľ a hádať heslo offline. Na Windows platí ACL profilu používateľa.

```sql
-- Strom a záznamy (všetky obsahové stĺpce sú ciphertext envelope)
CREATE TABLE nodes (
    id              TEXT PRIMARY KEY,     -- ULID
    parent_id       TEXT REFERENCES nodes(id),
    encrypted_meta  BLOB NOT NULL,        -- envelope: {name, tier, sync_flag, created_at, modified_at}
    dek_id          TEXT NOT NULL REFERENCES deks(id),
    version         INTEGER NOT NULL DEFAULT 1,
    is_dirty        INTEGER NOT NULL DEFAULT 1,
    is_deleted      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE entries (
    id              TEXT PRIMARY KEY,     -- ULID
    node_id         TEXT NOT NULL REFERENCES nodes(id),
    encrypted_meta  BLOB NOT NULL,        -- envelope: {name, tier, created_at, modified_at}
    encrypted_data  BLOB NOT NULL,        -- envelope: {fields: [{key, value, sensitive, sort_order}]}
    dek_id          TEXT REFERENCES deks(id),  -- NULL = dedí od node.dek_id
    version         INTEGER NOT NULL DEFAULT 1,
    is_dirty        INTEGER NOT NULL DEFAULT 1,
    is_deleted      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE deks (
    id              TEXT PRIMARY KEY,     -- ULID
    node_id         TEXT REFERENCES nodes(id),
    scope           TEXT NOT NULL CHECK(scope IN ('root','folder','tier2','share','audit')),
    encrypted_dek   BLOB NOT NULL,        -- VŽDY KEK-wrapped (AEAD)
    version         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE dek_archive (
    id              TEXT PRIMARY KEY,
    replaced_by     TEXT NOT NULL REFERENCES deks(id),
    encrypted_dek   BLOB NOT NULL,        -- starý DEK zabalený NOVÝM DEK-om (AEAD, blob_kind=6)
    archived_at     INTEGER NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE access_envelopes (
    id              TEXT PRIMARY KEY,
    dek_id          TEXT NOT NULL REFERENCES deks(id),
    user_id         TEXT NOT NULL,         -- komu patrí obálka
    created_by      TEXT NOT NULL,         -- kto obálku vytvoril (pre crypto_box)
    access_level    TEXT NOT NULL DEFAULT 'write' CHECK(access_level IN ('read','write')),
    encrypted_dek   BLOB NOT NULL          -- nonce(24B) + crypto_box(DEK)
);

CREATE TABLE entry_history (
    id              TEXT PRIMARY KEY,
    entry_id        TEXT NOT NULL REFERENCES entries(id),
    encrypted_snapshot BLOB NOT NULL,
    dek_id          TEXT NOT NULL,
    changed_at      INTEGER NOT NULL
);

CREATE TABLE audit_log (
    id              TEXT PRIMARY KEY,       -- ULID
    parent_ids      TEXT NOT NULL,          -- JSON array ULID-ov (DAG, nie lineárny chain)
    actor_id        TEXT NOT NULL,
    action          TEXT NOT NULL,          -- 'read'|'write'|'delete'|'approve'|'deny'|'share'|'rekey'
    encrypted_details BLOB,                -- envelope (Audit DEK)
    timestamp       INTEGER NOT NULL,
    signature       BLOB NOT NULL           -- Ed25519 podpis
);

-- Audit podpis canonical form:
--   id(26B) || actor_id(26B) || u16be(len(parent_ids_json)) || parent_ids_json
--   || u16be(len(action)) || action || timestamp_u64be(8B) || SHA-256(encrypted_details)(32B)
-- parent_ids_json = ULIDy sorted ASC, JSON bez whitespace

CREATE TABLE audit_dag_edges (
    child_id        TEXT NOT NULL REFERENCES audit_log(id),
    parent_id       TEXT NOT NULL REFERENCES audit_log(id),
    PRIMARY KEY (child_id, parent_id)
);

CREATE TABLE known_keys (
    user_id         TEXT PRIMARY KEY,
    signing_pk      BLOB NOT NULL,
    encryption_pk   BLOB NOT NULL,
    fingerprint     TEXT NOT NULL,
    first_seen      INTEGER NOT NULL,
    last_verified   INTEGER NOT NULL
);

CREATE TABLE vault_meta (
    key             TEXT PRIMARY KEY,
    value           TEXT
);
-- Kľúče: schema_version, argon2_params, vault_id, sync_checkpoint (encrypted),
--         last_known_commit_seq, org_recovery_pk, key_epoch
```

### 14.2 Server MariaDB schéma

```sql
CREATE TABLE users (
    id              VARCHAR(26) PRIMARY KEY,
    username        VARCHAR(255) UNIQUE NOT NULL,
    signing_pk      BLOB NOT NULL,
    encryption_pk   BLOB NOT NULL,
    key_fingerprint VARCHAR(64) NOT NULL,
    status          VARCHAR(10) NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending','active','revoked')),
    is_admin        TINYINT(1) NOT NULL DEFAULT 0,
    encrypted_keypair BLOB,
    argon2_salt     BLOB,               -- 16B encryption salt
    auth_salt       BLOB,               -- 16B auth salt (INÝ ako argon2_salt!)
    verify_salt     BLOB,               -- 32B server-only secret
    auth_proof_hash VARCHAR(255),       -- HMAC-SHA256(verify_salt, auth_proof)
    recovery_locked TINYINT(1) NOT NULL DEFAULT 0,
    created_at      BIGINT NOT NULL
);

CREATE TABLE vault_objects (
    id              VARCHAR(26) PRIMARY KEY,
    object_type     VARCHAR(20) NOT NULL,
    payload         LONGBLOB NOT NULL,
    owner_id        VARCHAR(26) NOT NULL REFERENCES users(id),
    target_user_id  VARCHAR(26) REFERENCES users(id) ON DELETE CASCADE,
    parent_ref      VARCHAR(26),
    version         INTEGER NOT NULL DEFAULT 1,
    commit_seq      BIGINT,             -- SERVER-ASSIGNED monotónny counter
    is_deleted      TINYINT(1) NOT NULL DEFAULT 0,
    payload_hash    VARCHAR(64) NOT NULL,
    client_signature BLOB,
    modified_at     BIGINT NOT NULL
);

CREATE TABLE shared_links (
    id              VARCHAR(43) PRIMARY KEY,  -- 256-bit random, base64url
    encrypted_blob  LONGBLOB NOT NULL,
    created_by      VARCHAR(26) NOT NULL REFERENCES users(id),
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    max_views       INTEGER NOT NULL DEFAULT 1,
    view_count      INTEGER NOT NULL DEFAULT 0,
    pin_hash        VARCHAR(255),
    pin_attempts    INTEGER NOT NULL DEFAULT 0,
    is_locked       TINYINT(1) NOT NULL DEFAULT 0
);

CREATE TABLE share_views (
    id              VARCHAR(26) PRIMARY KEY,
    share_id        VARCHAR(43) NOT NULL REFERENCES shared_links(id) ON DELETE CASCADE,
    viewed_at       BIGINT NOT NULL,
    viewer_ip_hmac  VARCHAR(64),
    user_agent_hmac VARCHAR(64)
);

CREATE TABLE server_audit (
    id              VARCHAR(26) PRIMARY KEY,
    user_id         VARCHAR(26) NOT NULL REFERENCES users(id),
    action          VARCHAR(50) NOT NULL,
    timestamp       BIGINT NOT NULL,
    request_hash    VARCHAR(64),
    commit_seq_range VARCHAR(100),
    client_signature BLOB NOT NULL
);

CREATE TABLE provisioning_tokens (
    token_hash      VARCHAR(64) PRIMARY KEY,
    user_id         VARCHAR(26) NOT NULL REFERENCES users(id),
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    is_used         TINYINT(1) NOT NULL DEFAULT 0
);

CREATE TABLE invitation_tokens (
    token_hash      VARCHAR(64) PRIMARY KEY,
    created_by      VARCHAR(26) NOT NULL REFERENCES users(id),
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    is_used         TINYINT(1) NOT NULL DEFAULT 0
);

CREATE TABLE spent_challenges (
    challenge_hash  VARCHAR(64) PRIMARY KEY,
    used_at         BIGINT NOT NULL
);

CREATE TABLE revoked_tokens (
    token_hash      VARCHAR(64) PRIMARY KEY,
    revoked_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL
);

CREATE TABLE write_acl (
    user_id         VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id         VARCHAR(26) NOT NULL,
    granted_at      BIGINT NOT NULL,
    PRIMARY KEY (user_id, node_id)
);

CREATE TABLE commit_counter (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    next_seq        BIGINT NOT NULL DEFAULT 1,
    gc_floor_seq    BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE sync_state (
    user_id         VARCHAR(26) PRIMARY KEY REFERENCES users(id),
    last_push_seq   BIGINT NOT NULL DEFAULT 0,
    last_pull_seq   BIGINT NOT NULL DEFAULT 0,
    last_activity   BIGINT NOT NULL DEFAULT 0,
    key_epoch       INTEGER NOT NULL DEFAULT 0
);
```

---

## 15. API referencia

### 15.1 Authentication

| Metóda | Endpoint | Auth | Popis |
|--------|----------|------|-------|
| POST | `/api/auth/challenge` | — | Získanie challenge pre prihlásenie |
| POST | `/api/auth/verify` | — | Overenie podpisu, vydanie JWT |
| POST | `/api/auth/refresh` | JWT | Refresh JWT |
| POST | `/api/auth/logout` | JWT | Invalidácia JWT --> revoked_tokens |
| POST | `/api/auth/provision` | — | Device provisioning (token + username --> keypair + salts) |
| POST | `/api/auth/recover` | — | Password-based recovery (rate limited) |

### 15.2 User management

| Metóda | Endpoint | Auth | Popis |
|--------|----------|------|-------|
| GET | `/api/meta` | — | Server verzia, argon2_web_params (verejné) |
| GET | `/api/meta?username=X` | — | argon2_salt + auth_salt (per-user, verejné, fake pre neexistujúcich) |
| PUT | `/api/me/keypair` | JWT / Onboarding JWT | Upload encrypted_keypair + salts + auth_proof + `argon2_params` (povinné) |
| PUT | `/api/me/kdf-params` | JWT + signed challenge | Doplní KDF parametre účtu uloženého bez nich (len aktuálny salt, len NULL) |
| POST | `/api/me/key-material-archive` | plný JWT + `auth_proof` aktuálneho hesla | Archív kľúčového materiálu (lockout review #11: keypair zabalený STARÝMI heslami, max 10 generácií), najnovšie prvé: `key_epoch`, `encrypted_keypair`, salty, `argon2_params`, `archived_at` – obnova, keď aktuálny materiál nejde otvoriť a vlastník pozná staré heslo |
| POST | `/api/me/key-material-archive/purge` | plný JWT + `auth_proof` aktuálneho hesla | Zmaže všetky archivované generácie (po zmene uniknutého hesla už staré heslo pri úniku DB nič neotvorí). Zlý proof na oboch endpointoch sa počíta ako zlý `/recover` proof (10 → zámok, potom 423), samotný token nič nevráti. Archív sa navyše maže po `SEZAM_KEY_MATERIAL_ARCHIVE_DAYS` (30 dní; upratovacia slučka, staršie sa ani neposielajú) – review 688edcb: predtým navždy cieľ offline hádania bez spôsobu obnovy |
| POST | `/api/users/invite` | JWT (admin) | Generovanie invitation (128-bit, 72h, one-time) |
| POST | `/api/users/register` | — | Registrácia cez invitation token --> onboarding JWT |
| GET | `/api/users` | JWT (admin) | Zoznam userov |
| PATCH | `/api/users/:id/approve` | JWT (admin) | Schválenie pending usera |
| PATCH | `/api/users/:id/rotate-keys` | JWT | Vypnuté — 410 (lockout review #11); rotácia identity ide cez `POST /api/sync` `key_rotation.identity` (10.2) |
| POST | `/api/users/:id/allow-key-reset` | Admin JWT | Jednorazovo (1 h) dovolí používateľovi zmeniť kľúčový materiál bez aktuálneho hesla (po desktop org recovery); nie sám sebe (10.2) |
| DELETE | `/api/users/:id` | JWT (admin) | Revokácia --> status='revoked', token_epoch+1, trigger re-key; volajúci admin sa overí pod zámkom (vždy ostane ≥1 admin) |
| PATCH | `/api/users/:id/reactivate` | JWT (admin) | Zruší revokáciu --> status='active'; write_acl a zdieľania treba udeliť znova |

### 15.3 Sync

| Metóda | Endpoint | Auth | Popis |
|--------|----------|------|-------|
| POST | `/api/sync` | JWT | Delta push (dirty objects, write_acl check, Ed25519 verify) |
| GET | `/api/sync?since_commit_seq=X` | JWT | Delta pull (objects with commit_seq > X), ETag support |

**Podpisy pred globálnym zámkom (review d615826).** Push serializuje riadok `commit_counter` (`FOR UPDATE`). Dekódovanie, SHA-256 payloadu a Ed25519 overenie každého objektu (aj staged dávky, prečítanej vopred) bežia ešte pred zámkom, vo vlákne mimo event loopu, proti kľúčom, ktoré locked pass pravdepodobne použije (aktuálny `signing_pk` a nový kľúč rotácie identity). Pod zámkom sa overuje znova len objekt pod kľúčom, ktorý iné zariadenie medzitým rotovalo. Predtým ktokoľvek s účtom poslal veľkú dávku a pushe všetkých ostatných čakali desiatky sekúnd.

**Staged dávka po jednom (review 7c10379 H7).** Každý push s `staged_batch_id` čítal a parsoval celú staged dávku (do 256 MiB) pred akýmkoľvek zámkom a pushe jedného účtu sa neserializovali: štyri 200-bajtové pushe zobrali 3,2 GB a kontajner padol na OOM. Teraz `/api/sync/stage` aj push so staged dávkou najprv vezmú claim účtu v tabuľke `sync_push_claims` (naprieč workermi; ďalší čaká najviac 120 s, potom 503 s `Retry-After`; claim mŕtveho workera po 10 min prevezme ďalší). Dávka sa prečíta raz, po 500 riadkoch, a pod zámkom sa už len overí, že čísla riadkov sedia (GC ich mohol medzitým zmazať → 409). Worker drží naraz staged dávky najviac za `MAX_STAGED_BYTES` (väčšiu dávku spracuje samotnú). Stage odmietne (400) objekt so zlým kódovaním alebo hashom payloadu; podpis overí až push, lebo dávku rotácie identity podpisuje nový kľúč, ktorý server dostane až s pushom. Test `tests/test_review7_staged_push_memory_h7.py`.

**Práca pod globálnym zámkom (review 7c10379).** Push s 100 000 objektmi držal riadok `commit_counter` 67 s, lebo každý objekt si `commit_seq` bral dvoma príkazmi (`UPDATE … next_seq + 1` a `SELECT`). Teraz push počíta `commit_seq` sám od hodnoty prečítanej s `FOR UPDATE` a na konci ju zapíše jedným `UPDATE` (pod tým istým zámkom, takže poradie `commit_seq` = poradie commitov ostáva). Pushe jedného workera čakajú na zámok v procese (`_push_gate`), nie na riadku s vlastným spojením z poolu: desať čakajúcich pushov predtým zabralo celý pool a `/health` vracal 503. Test `tests/test_review7_push_lock_work.py`.

**Mená sa nedajú zistiť cez `/verify` ani cez expiráciu počítadiel (review d615826).** `POST /api/auth/verify` overí MAC challenge (viazanej na meno) skôr, než hľadá účet, takže sfalšovaná challenge dostane pre každé meno rovnakú odpoveď `Challenge not found or expired`. Predtým ju overoval len pri existujúcom účte a neznáme meno odpovedalo `Authentication failed`. `next_failure_state` zabúda zlé pokusy staršie ako `recovery_lock_seconds` aj vtedy, keď meno nezamkli, rovnako ako cleanup zahodí tieňové počítadlá neznámeho mena. Predtým si reálny účet 9 starých pokusov pamätal a ďalší zlý dôkaz vrátil 423, kým neznáme meno 401. Test: `tests/test_review6_server_enumeration.py`.

**Neznámy `target_user_id` je konflikt objektu (review d615826).** `vault_objects.target_user_id` je cudzí kľúč na `users`. Objekt (typicky envelope), ktorého cieľového používateľa server nepozná (napr. medzitým zmazaného), dostane v pushi konflikt `unknown target user` a ostatné objekty dávky prejdú. Predtým porušenie FK na MariaDB zhodilo celý push na 500 a zariadenie potom neposlalo nič. Testy: `tests/test_review6_server_mariadb.py` (reálna MariaDB), `tests/test_review6_server_r6a.py`.

### 15.4 Share

| Metóda | Endpoint | Auth | Popis |
|--------|----------|------|-------|
| POST | `/api/share` | JWT | Vytvorenie share linku |
| GET | `/api/share/:id` | — | Stiahnutie blob (atómová SELECT FOR UPDATE) |
| PATCH | `/api/share/:id` | JWT (admin) | Unlock is_locked / manuálna deaktivácia |
| DELETE | `/api/share/:id` | JWT | Zrušenie + vymazanie blob |
| GET | `/api/shares` | JWT (admin) | Zoznam aktívnych zdieľaní |

**Jedno spojenie z poolu na požiadavku (review d615826 #1).** Keď kontrola pod zámkom (`_consume_view`) zistí, že share sa medzičasom spotreboval, transakcia sa najprv ukončí a až potom beží `fail()` s rezerváciou IP pokusu (vlastná transakcia). Predtým si `fail()` vzal druhé spojenie, kým prvé ešte držal: pri ~40 súbežných otvoreniach jedného linku čakali všetky spojenia poolu (`maxsize=10`) na ďalšie a worker natrvalo stál. `GET /health` robí `SELECT 1` cez pool (timeout 5 s) a pri zlyhaní vráti 503, aby kontajner so zaseknutým poolom zlyhal health check. Docker však kontajner označený `unhealthy` pri `restart: unless-stopped` nereštartuje (overené: `RestartCount` zostáva 0). Preto každý worker spúšťa `_db_watchdog`: každých 30 s rovnaký `SELECT 1` a po 6 zlyhaniach za sebou (~3 min) `os._exit(1)`. Uvicorn mŕtveho workera nahradí novým, a keby padol celý proces, reštartuje ho Docker. Testy: `tests/test_review6_server_r6a.py`, `tests/test_review6_server_watchdog.py`.

**Limitery bez deadlocku (review d615826).** Riadok IP limitu (`share_pin_rate_limits`, `org_recovery_rate_limits`, `recovery_ip_limits`, `recovery_name_limits`, `recovery_name_rations`) sa zakladá cez `INSERT … ON DUPLICATE KEY UPDATE <pk> = <pk>` a `recovery_probe_slots` jedným upsertom `probe_at = VALUES(probe_at)`. Predtým `INSERT IGNORE` na existujúcom riadku vzal len zdieľaný zámok a dve súbežné požiadavky z jednej IP, ktoré ho potom chceli `FOR UPDATE` (alebo `UPDATE`), sa navzájom zablokovali: InnoDB jednu zabil (1213) a klient dostal 500. Test na reálnej MariaDB: `tests/test_review6_server_mariadb.py` (`SEZAM_TEST_MARIADB`), statická kontrola v `tests/test_review6_server_r6a.py`.

### 15.5 User enumeration ochrana

`GET /api/meta?username=X`:
- Pre existujúcich userov: vráti reálne salts
- Pre neexistujúcich userov: vráti deterministický fake salt = `HMAC(server_secret, username)`
- Rovnaký response time pre oba prípady
- Útočník nemôže rozlíšiť existujúceho a neexistujúceho usera

### 15.6 Error responses

| HTTP Status | Význam |
|-------------|--------|
| 200 | OK |
| 304 | Not Modified (ETag match, žiadne nové dáta) |
| 400 | Bad Request (neplatný podpis, chybné parametre) |
| 401 | Unauthorized (expirovaný/neplatný JWT) |
| 403 | Forbidden (write_acl violation) |
| 404 | Not Found |
| 409 | Conflict (sync version mismatch) |
| 410 | Gone (since_commit_seq < gc_floor_seq, vyžaduje full resync) |
| 429 | Too Many Requests (rate limit) |

---

## 16. Recovery scenáre

### 16.1 Prehľad

| Scenár | Cesta | Vyžaduje |
|--------|-------|----------|
| Stratené zariadenie + viem heslo | Password-based recovery (Cesta B) | Heslo + prístup k serveru |
| Stratené zariadenie + viem heslo + bez servera | .sezam-key import (Cesta C) | Heslo + .sezam-key súbor |
| Admin zabudol heslo (firemný vault) | Shamir recovery (3 z 5) | 3 z 5 dôveryhodných osôb |
| Bežný user zabudol heslo | Strata dát (by design) | Žiadna obnova nie je možná |

### 16.2 Cesta B: Password-based recovery (najčastejšie)

```
Klient                                  Server
======                                  ======

1. GET /api/meta?username=peter
   ─────────────────────────────────>
                                        2. Vráť argon2_salt + auth_salt
   <─────────────────────────────────      (alebo fake salts ak user neexistuje)

3. auth_proof = Argon2id(password, auth_salt)

4. POST /api/auth/recover
   {username: "peter",
    auth_proof: base64(auth_proof)}
   ─────────────────────────────────>
                                        5. Server overí:
                                           a) HMAC-SHA256(verify_salt, auth_proof)
                                              == users.auth_proof_hash
                                           b) recovery_locked == 0
                                           c) Rate limit: 10 zlých/h per IP, 10 total per meno

   <─────────────────────────────────
                                        6. Response (ak OK):
                                           {encrypted_keypair: base64(...),
                                            argon2_salt: base64(...)}

7. KEK = Argon2id(password, argon2_salt)
8. keypair = AEAD_decrypt(encrypted_keypair, KEK)
9. signing_sk, encryption_sk = unpack(keypair)
10. Pokračuj normálnym challenge-response auth
11. Pull celý vault
```

**Cross-client testy „heslo zmenené na A, prihlásenie na B“ (lockout review L8):** prevzatie hesla zmeneného inde sa overuje na skutočnom serveri pod uvicorn (`tests/test_integration_client_server.py`, in-memory úložisko), nie proti atrapám. Desktop → desktop pokrývajú testy v tom súbore. Web v `tests/test_cross_client_password_change.py`: celý `web/static/js/app.js` beží v node so skutočnými handlermi (`handleLogin`, `handleShamirGenerate`, `handleOrgRecovery`). Simulované je len okolie prehliadača: IndexedDB v pamäti, ktorá pretrvá medzi reláciami ako profil prehliadača, DOM z obyčajných objektov a Argon2 Worker (Argon2id z node s rovnakými parametrami). Desktop → web (X1): Prehliadač B sa prihlási pred zmenou hesla, takže má keypair a checkpoint pod starým KEK. Potom desktop A zmení heslo (zmení aj salt) a pridá záznam. Staré heslo na B je zlé heslo: server odmietne jeho proof, nevznikne relácia a nič sa nestiahne. Nové heslo prihlási, cache keypairu nahradí aktuálnym wrapom účtu a záznamy z A sa dešifrujú. Na kóde pred review (c8c7b12) test padne, lebo nové heslo zlyhá na checkpointe pod starým KEK (nález #4). Web → desktop (X2): web heslo mení len cez org recovery s novým heslom. Admin si na webe nastaví org recovery a v ďalšej relácii obnoví účet sharmi a novým heslom (epoch 1, nový salt). Desktop so starým heslom dostane pri sync `KeyEpochStale`. Prevzatie so starým heslom odmietne („Wrong current account password“), s novým heslom prevezme kľúčový materiál, dáta sú čitateľné a push prejde. Trezor sa potom otvorí len novým heslom. Nové zariadenie sa starým heslom nepripojí, s novým prečíta všetko a web vidí záznam z desktopu. Na c8c7b12 test padne, lebo web po nastavení org recovery nenájde blob na serveri (nález #3). Desktop/web → mobil (X3): skutočné `AuthService`/`SyncService`/`VaultService` z `mobile/lib` bežia pod `flutter test` (`mobile/test/cross_client_password_change_test.dart`) proti tomu istému serveru. Python test ich spustí s `SEZAM_X3_*` a zahrá A. Bez týchto premenných sa Dart test preskočí. Pod `flutter test` nie sú pluginy: libsodium sa načíta z balíka `sodium_libs` v pub cache (`CryptoService.initForTesting`), Argon2id počíta node (`crypto.argon2Sync`), SQLite ide cez `sqflite_common_ffi` (dev závislosť). Secure storage a path_provider sú kanály v pamäti. Mobil v aplikácii heslo účtu nemení. Zmenu urobenú inde len preberie: pri sync dostane `KeyEpochStaleException` a `adoptPasswordChangedElsewhere` s aktuálnym heslom, alebo pri ďalšom odomknutí heslom so zadaním predchádzajúceho hesla. Telefón B založí prázdny server ako admin, desktop A sa k účtu pripojí obnovou keypairu heslom (opačný smer pokrýva test pripojenia nového telefónu nižšie). Po zmene hesla na A (desktop `change_password`, alebo web org recovery) sa B offline stále otvorí starým heslom, sync skončí `KeyEpochStaleException`. Prevzatie so starým heslom server odmietne. Prevzatie s novým heslom pri výpadku siete pred reláciou nič nezmení a staré heslo stále otvorí všetky záznamy. Prevzatie s novým heslom potom prejde, záznamy z A sú čitateľné a záznam z B sa pushne a A ho vidí. Odvtedy B otvorí offline aj online len nové heslo a server zostane na epoch 1. Na c8c7b12 (s rovnakým testovacím vstupom v `CryptoService`) variant desktop padne: po prevzatí, ktoré zlyhalo na sieti, sa telefón starým heslom už neodomkne (nález #9). Variant web padne už na náleze #3.

**Nový telefón sa pripojí k existujúcemu účtu heslom:** `AuthService.connectToServer` na serveri, ktorý už má používateľov, overí heslo obnovou (Path B, `/api/auth/recover`) a otvorí keypair účtu. Ak telefón keypair účtu ešte nemá, prevezme ho (`_moveDeviceToAccount`), rovnako ako desktop pri `connect`: keypair, salt a KDF účtu nahradia vlastné, vlastný lokálny trezor sa odloží (`sezam_vault.db.before-join`), zariadenie sa prihlási a stiahne účet a jeho priečinky a záznamy sa zapíšu znova pod kľúčmi účtu (`VaultService.addCarriedItems`, bez duplikátov pri opakovaní). Odložený trezor sa zmaže až potom. Pri akejkoľvek chybe dovtedy sa vráti databáza aj secure storage a trezor sa znova otvorí, telefón zostane ako bol. Trezor, v ktorom je niečo potvrdené serverom (`commit_seq`), patrí inému účtu a nemení sa. Lokálny trezor sa pri existujúcom serveri nemusí otvárať zadaným heslom účtu, ak je už odomknutý; zamknutý sa otvorí zadaným heslom. „Lokálny trezor existuje“ znamená uložený keypair v secure storage (`hasLocalVault`), nie súbor databázy: ten aplikácia vytvorí prázdny pri štarte (`main.dart` preto zisťuje trezor cez `hasLocalVault`). `SyncService.unreadableOwnDeks` na zariadení bez `kek_dek_id` a bez objektov vráti prázdny zoznam (predtým `recoverFromServer` na prázdnom telefóne padol na „Local KEK id is missing“). Test `test_new_phone_joins_an_existing_account_by_password` v `tests/test_cross_client_password_change.py` (Dart časť `mobile/test/phone_joins_account_test.dart`, spoločný harness `mobile/test/support/real_server_phone.dart`): desktop A založí účet so záznamom, telefón B sa pripojí. Variant „empty“: telefón bez trezoru. Variant „local“: telefón s vlastným offline záznamom; výpadok siete po prihlásení nič nezmení, potom sa záznam presunie do účtu a A ho vidí. V oboch variantoch zlé heslo nič nepripojí, správne heslo pripojí bez druhého účtu na serveri a odvtedy telefón otvorí offline aj online len heslo účtu. Na starom kóde test padne v oboch variantoch na „Nespravne heslo“: prázdna databáza sa považovala za trezor a odomknutý vlastný trezor musel otvoriť aj heslo účtu. Pri zhodnom hesle by telefón dostal pokyn žiadať pozvánku, lebo sa prihlasoval vlastnými kľúčmi.

**Pripojenie prerušené zabitím aplikácie, úplný prenos (review 688edcb).** Pred odložením databázy sa do secure storage zapíše žurnál `sezam_join_restore` s pôvodnými hodnotami kľúčov. Databázový súbor sa odkladá ako posledný, takže bez `sezam_vault.db.before-join` je originál stále na mieste. Bod potvrdenia je zmazanie žurnálu hneď po `addCarriedItems`. `AuthService.recoverInterruptedJoin` beží v `main.dart` pred otvorením databázy. Ak žurnál existuje, vráti odložený trezor aj kľúče. Ak ostali len odložené súbory po potvrdení, zmaže ich. Ďalší pokus o pripojenie pri nedokončenom predchádzajúcom najprv telefón vráti a ohlási to. Odložený trezor tak už nemôže prepísať. Predtým `.before-join` nikto neobnovil a druhý pokus originál prepísal. Prenos berie celé dešifrované meta aj dáta záznamu (`VaultService.carriedEntries`), nie len polia modelu: tier, `created_at`, AI politiku (`ai_read_secret`, `allowed_actions`, `max_session_minutes`, …) a `write_policy`. Záznam s tier 2 dostane v účte vlastný DEK ako na desktope. Živý priečinok alebo záznam, ktorý telefón nevie prečítať, pripojenie odmietne, nič sa nezmení. Test: variant „local“ v `test_new_phone_joins_an_existing_account_by_password` pridá záznam tier 2 s politikou, zasekne pull (aplikácia zabitá pri odloženom trezore), spustí obnovu ako štart aplikácie a pôvodné heslo otvorí oba záznamy. Po pripojení desktop A vidí tier 2 pod vlastným DEK, `created_at` aj politiku. Na starom kóde test padne: tier sa stratí a obnova neexistuje. Odložené súbory bez žurnálu (pripojenie prerušené vo verzii pred žurnálom, review e4cd15a S4) sa nemažú, ale premenujú na `*.before-join.kept-<čas>`. Review 526419e N7: predtým o nich vedel len debug log; Nastavenia → Key Management ich teraz vypíšu („Set-aside vault (dátum)“) s možnosťou uložiť kópiu mimo aplikácie (Android výber dokumentu) alebo ich po potvrdení zmazať (`AuthService.keptAsideVaults` / `deleteKeptAsideVault`, test `mobile/test/join_aside_kept_test.dart`).

### 16.3 Cesta C: .sezam-key offline recovery

```
1. Používateľ importuje .sezam-key súbor
   (obsahuje: encrypted_keypair + argon2_salt)

2. Zadá heslo
3. KEK = Argon2id(password, argon2_salt)
4. keypair = AEAD_decrypt(encrypted_keypair, KEK)
5. signing_sk, encryption_sk = unpack(keypair)

6. Ak je server dostupný:
   --> Challenge-response auth --> pull vault

7. Ak server nie je dostupný:
   --> Lokálna obnova (len kľúče, bez dát)
   --> Dáta sa stiahnu neskôr pri prvom sync
```

**Mobil: import bez okna straty (review 688edcb).** Import presunie lokálne DEK pod KEK zálohy (`_moveVaultToBackupKek`) a v tej istej SQLite transakcii (`applyLocalRekey(settings:)`) zapíše stav keypairu zálohy (`pending_keypair_migration` v `settings`). Ten obsahuje salt, KDF, obálku a user id. Až potom ho zapíše do Keychainu. Ak aplikáciu zabijú medzi presunom a Keychainom, `_completePendingKeypairMigration` pri ďalšom odomknutí dokončí stav z databázy. Predtým ostali DEK pod KEK, ktorý žiadny uložený salt neodvodil, a čisto lokálny trezor sa stratil. Test: `mobile/test/sezam_key_import_crash_test.dart`. Zápis do Keychainu po presune zlyhá, potom heslo trezor dvakrát otvorí so záznamami. Na starom kóde odomknutie zlyhá.

**Mobil: nový kľúč počas presunu DEK (review 7c10379).** `SyncService.rekeyLocalVault` (import `.sezam-key`, prevzatie hesla, pripojenie cez QR) prečítal riadky, prebalil ich a odomknutý trezor prepol na nový KEK až neskôr. Osobný priečinok vytvorený medzitým zabalil svoj DEK pod starý KEK. Import potom zlyhal na „Cannot unwrap N own key(s)“, rovnako každé ďalšie odomknutie, a čisto lokálny trezor sa stratil. `VaultService.whileKekFixed` teraz radí za sebou presun DEK, odomknutie a každé zabalenie nového kľúča (`createPersonalFolder`, prenesené tier-2 záznamy). Presun ešte pred uvoľnením prepne KEK v pamäti (`localDeksMovedTo`). Poradie zámkov je vždy sync → KEK. Test: `mobile/test/sezam_key_import_folder_race_test.dart` vytvára priečinky počas importu. Na starom kóde import aj odomknutie zlyhajú.

Pri prevzatí rotácie identity presun prepodpíše neodoslané riadky novým kľúčom účtu. Zápis zo zastaranej kópie prepísal úpravu uloženú medzitým a úprava po presune sa do odomknutia podpisovala vyradeným kľúčom. Server oboje odmietal pri každom pushi a úprava po načítaní zmizla. Preto teraz pod `whileKekFixed` bežia aj `createNode`, `createEntry`, `updateEntry`, `keepLocalChange` a mazanie. Presun v pamäti prepne aj podpisový kľúč. Test: `mobile/test/identity_takeover_edit_race_test.dart`, na starom kóde padne.

### 16.4 Shamir recovery (len firemný vault, len admin)

**Opakované nastavenie (lockout review N4).** Nové nastavenie vytvorí nový recovery kľúč, takže všetky doteraz rozdané kusy prestanú platiť. Ak už je org recovery nastavené, `Vault.setup_org_recovery` bez `replace=True` vyhodí `OrgRecoveryExistsError` a nič nezmení. `sezam org-recovery-setup` zobrazí varovanie a pýta si potvrdenie (predvolene „nie“). Bez terminálu skončí s kódom 1, ak nedostane `--replace`. GUI v tom prípade zobrazí dialóg „Nahradiť Org Recovery“, kde je predvolené „Nie“. Web si potvrdenie pýtal už predtým (`recovery.replace_own` / `replace_stale` / `replace_other_admin`).

**Epocha blobu na serveri (review 688edcb #3b).** `POST /api/org-recovery/store` nesie `key_epoch`, teda epochu KEK, ktorý klient naozaj zabalil. Pri nastavení je to `state.keyEpoch` relácie, pri zmene hesla cez org recovery epocha z journalu (`journalRecoveryStore`; starší journal bez nej použije vlastný `key_epoch`). Server blob s inou epochou, než má účet, odmietne (409) a uloží epochu od klienta. Bez `key_epoch` vráti 400 s výzvou na aktualizáciu klienta. Predtým server zapísal svoju aktuálnu epochu. Relácia, ktorá ešte držala KEK spred zmeny hesla na inom zariadení, tak uložila blob so starým KEK a `/status` ho hlásil ako aktuálny, až kým obnova nezlyhala.

```
1. 3 z 5 dôveryhodných osôb sa fyzicky stretnú
2. Každá zadá svoju časť (share) do recovery formulára
3. Systém zrekonštruuje recovery_key = Lagrangeova interpolácia nad GF(256)
4. recovery_key --> AEAD_decrypt(org_recovery_wrap) --> Root KEK
5. Root KEK --> odomkne všetky DEK-y --> celý vault je prístupný
6. Nový admin nastaví nové master heslo:
   a) Nové heslo --> Argon2id --> nový KEK
   b) Re-wrap všetky DEK-y novým KEK-om
   c) Re-encrypt keypair novým KEK-om
   d) Upload na server
7. Voliteľne: vygenerovať nový recovery key --> nové shares
```

### 16.5 Automatické snapshoty trezoru

Pred každou rizikovou operáciou desktop klient skopíruje `sezam.db` cez SQLite backup API do `<trezor>/snapshots/<UTC čas>-<dôvod>.db` (adresár `0700`, súbor `0600`) a drží posledných 20 snapshotov. Snapshoty `pre-restore` majú vlastný limit, posledné 3, a ostatné nevytláčajú (review 8595ec1: predtým každý pokus o obnovu, aj zrušený či vrátený, vytlačil najstarší snapshot, teda práve ten spred incidentu, ktorý sa hľadal; test `tests/test_review10_snapshots.py`).

| Dôvod | Operácia |
|-------|----------|
| `change-password` | zmena master hesla |
| `kdf-upgrade` | upgrade parametrov Argon2id |
| `org-recovery` | Shamir recovery (pred nastavením nového hesla) |
| `rekey` | re-key priečinkov po revokácii používateľa |
| `import` | `sezam import` a import v GUI |
| `server-connect` | `sezam connect` / `init --server` a pripojenie v GUI (po kontrole, že server odpovedá) |
| `full-resync` | potvrdený full resync, ktorý prepíše lokálnu kópiu |
| `server-reseed` | `sezam server reseed` (pred bootstrapom prázdneho servera) |
| `delete-folder` | zmazanie priečinka s podstromom (CLI/GUI) |
| `password-adopted` | po prevzatí hesla zmeneného na inom zariadení (otvára ho nové heslo) |
| `pre-restore` | pred `sezam snapshot restore` / `sezam restore` (vlastný limit 3) |

- **Fail-closed:** ak sa snapshot nepodarí, operácia sa nevykoná a nič v trezore sa nezmení.
- **Obsah:** snapshot obsahuje len to, čo `sezam.db`, teda šifrované dáta a zabalené kľúče. Je to jeden samostatný súbor (rollback journal, nie WAL). Otvára sa **heslom, ktoré platilo v čase snapshotu**.
- **Po zmene hesla (review d615826):** zmena hesla DEK-y nemení, takže snapshot spred nej otvorilo staré (možno uniknuté) heslo a jeho kľúče dešifrovali aj dnešné dáta – a držalo sa ich až 20. Zmena hesla, upgrade KDF, Shamir recovery aj prevzatie hesla zmeneného na inom zariadení teraz zmažú každý snapshot, ktorého `argon2_salt` nie je aktuálny (`drop_snapshots_of_other_passwords`). Ostane len snapshot, ktorý urobila samotná zmena (`vault_meta.key_change_snapshot`), ako cesta späť pri preklepe v novom hesle; zmaže sa pri prvom odomknutí novým heslom. Nečitateľné súbory ostávajú (nevedno, ktoré heslo ich otvára). Výnimka (review 7c10379): keď zariadenie s vlastným saltom pri pripojení (`sezam connect`, `init --server`, GUI) prevezme account KEK, snapshot `server-connect` toho istého pripojenia ostane ako cesta späť pred pripojenie – otvára ho doterajšie heslo zariadenia a nie je to `key_change_snapshot`, takže ho odomknutie account heslom nezmaže; zmaže ho až ďalšia zmena hesla (aj prevzatá z iného zariadenia). Staršie snapshoty starého hesla sa zmažú ako doteraz. Test `tests/test_review7_connect_snapshot_survives_adopt.py` (CLI aj GUI). Prevzatie hesla zmeneného na inom zariadení mimo pripojenia (`adopt_rotated_key_material`) predtým zmazalo všetky snapshoty a nový nevytvorilo, takže zariadenie nemalo žiadnu cestu späť (review 8595ec1). Teraz po prevzatí urobí snapshot `password-adopted` pod novým heslom a až potom zmaže snapshoty starého. Snapshot obnovený zo staršieho stavu tým neprichádza o novšie snapshoty: maže sa len pri zmene hesla, nie pri odomknutí. Snapshoty starého hesla, ktoré nechala zmena hesla vo verzii spred d615826, ostali až do ďalšej zmeny (review 4acfdde R11, nízke): `sezam status` a `sezam snapshot list` ich teraz menujú (`(earlier password)`) a `sezam snapshot drop-old-passwords` ich po potvrdení zmaže. Automaticky nie, lebo po obnove staršieho snapshotu by „iné heslo“ mali práve novšie snapshoty.

**`sezam snapshot list`** vypíše snapshoty od najstaršieho: názov, čas (UTC), dôvod a veľkosť.

**`sezam snapshot restore <názov>`** vráti trezor do stavu snapshotu:

1. Prijme len presný názov zo `snapshot list`, nie cestu. Symlinky a súbory s iným tvarom názvu ignoruje.
2. Skopíruje snapshot do súkromného dočasného adresára v trezore a overí `integrity_check` aj to, že ide o trezor Sezamu (`user_id`, `encrypted_keypair`, `argon2_salt`, `argon2_params`, `root_node_id`).
3. Bez TTY vyžaduje `--yes`, inak sa pýta na potvrdenie.
4. Vyžiada **master heslo, ktoré otvára snapshot**. Zlé heslo nič nezmení a počíta sa do limitu neúspešných pokusov. Obnova teda nikomu nedá prístup, ktorý by už nemal z kópie samotného snapshotu.
5. Ukončí CLI session a zamkne bežiace `mcp-serve` (ako `sezam lock`).
5a. Vezme exkluzívny zámok `sezam.db.inuse` (čaká naň najviac 5 s). Každé otvorené `VaultDB` (odomknutá desktopová aplikácia, iný príkaz CLI, MCP server) drží na ňom zdieľaný zámok, kým trezor nezamkne. Ak trezor drží otvorený iný proces, obnova sa odmietne a nič sa nezmení, ani snapshot `pre-restore` sa nevytvorí. Inak by ten proces ďalej čítal a zapisoval do nahradeného súboru (lockout review M7). Kým obnova zámok drží, nikto iný trezor neotvorí (čaká najviac 10 s). Zámok je advisory a uvoľní ho OS aj pri páde procesu. Na súborovom systéme bez zámkov (niektoré NFS/SMB/FUSE: `ENOLCK`/`EOPNOTSUPP`, na Windows `ERROR_NOT_SUPPORTED`) sa trezor predtým vôbec neotvoril; teraz si každý držiteľ nechá značku `sezam.db.inuse.<sh|ex>.<host>.<pid>.<token>` s rovnakými pravidlami (zdieľané sa znesú, obnova vylučuje). Značky mŕtvych procesov na tom istom stroji sa zmažú, značky iného stroja platia (review 688edcb, nízke). Držiteľ značku obnovuje (mtime každých 30 s); značka, ktorej sa 10 minút nikto nedotkol (merané hodinami súborového servera, nie lokálnymi), sa zmaže bez ohľadu na stroj a PID – pád na inom stroji, znovupoužitý PID ani premenovaný stroj tak obnovu nezablokujú navždy. Hláška „trezor je otvorený“ vymenuje blokujúce značky a povie, že ich možno zmazať, ak na tom stroji Sezam už nebeží. Stroj s funkčnými zámkami značky iných strojov rešpektuje rovnako (obnova nenahradí trezor otvorený strojom bez zámkov) (review e4cd15a S3). Proces, ktorému značku zmazali, kým spal (dlhšie ako 10 minút), ju už neobnoví a odmietne každý ďalší príkaz nad databázou (`VaultInUse`: zatvoriť a znova otvoriť trezor) – inak by zapisoval do trezoru, ktorý medzitým iný stroj obnovil. Existenciu svojej značky overí pred každým príkazom. Obnova, ktorá zmazala starú značku, počká ešte 1 s, aby zápis, ktorý kontrolou práve prešiel, dobehol pred snapshotom. Značky aj hodiny sa obnovujú zápisom (súbor `sezam.db.inuse-clock`), nie `utime()`: na SMB `utime()` zapíše hodiny klienta, zápis hodiny servera (review 526419e S1). Review d150605 N6: po prebudení stroja prvý príkaz Sezamu na ňom zmazal značku desktopovej aplikácie, ktorá tam bežala (jej heartbeat ešte neprebehol), a aplikácia potom odmietala zápisy. Zdieľané otvorenie teraz zdieľané značky nemaže (neblokujú ho); zastaranú značku živého procesu na tom istom stroji zmaže len vtedy, keď ju jej heartbeat do `MARKER_WAKE_GRACE_SECONDS` (40 s) neobnoví – znovupoužitý PID tak obnovu stále nezablokuje navždy.
6. Uloží aktuálny trezor ako snapshot `pre-restore`, takže aj obnovu sa dá vrátiť. Ak sa to nepodarí, nič sa nenahradí.
7. Zmaže `sezam.db-wal` a `sezam.db-shm` starej databázy (inak by sa staré WAL rámce prehrali do novej) a atomicky nahradí `sezam.db`.

Lokálne zmeny po čase snapshotu sa obnovou stratia, ak nie sú na serveri. Trezor pripojený k serveru si ich pri ďalšej synchronizácii stiahne späť.

**`sezam restore <súbor>`** vráti trezor zo zálohy `sezam export <súbor> --format backup` rovnakými krokmi 2–7 (heslo platné pri zálohe, `pre-restore` snapshot, zámok `inuse`). Trezor, ktorý ešte neexistuje, len vytvorí zo zálohy (review 526419e N3).

**Verzia schémy.** Pri otvorení `sezam.db` sa pred akýmkoľvek zápisom porovná `vault_meta.schema_version` s verziou, ktorú tento Sezam pozná. Trezor novšej verzie (aj nečitateľná hodnota) sa odmietne (`VaultSchemaTooNew`: aktualizujte Sezam) a súbor sa nezmení. Rovnako sa odmietne snapshot alebo záloha novšej schémy pri obnove. Trezor bez kľúča je pôvodná verzia 1 (review 526419e N3).

### 16.5a Kôš a história záznamu

Zmazanie záznamu aj priečinka necháva v `sezam.db` tombstone (`is_deleted = 1`) so šifrovanými blobmi z verzie pred zmazaním. Zmazanie priečinka navyše najprv uloží snapshot `delete-folder` (bez neho sa nezmaže nič).

- **`sezam trash`** vypíše zmazané priečinky (s počtom zmazaných záznamov v nich) a záznamy, ktorých priečinok ešte existuje. V GUI: pravý klik v strome → „Restore Deleted…".
- **`sezam trash restore ID`** vráti záznam, alebo priečinok so všetkými zmazanými podpriečinkami a záznamami v jednej transakcii. Záznam v zmazanom priečinku sa vracia s priečinkom. Bloby sa dešifrujú DEK-om z hlavičky (aj archivovaným po re-key) a zapečatia sa znova aktuálnym DEK-om o verziu vyššie, takže obnova odíde ďalším `sezam push` ako bežná úprava. Funguje aj na zariadení, ktoré zmazanie len stiahlo.
- **`sezam history CESTA`** vypíše staršie verzie polí záznamu (`entry_history`, ukladá sa pri každej úprave, len lokálne). `--show ID` ich zobrazí (citlivé polia ako `****`), `--restore ID` ich vráti; nahradená verzia sa pritom uloží do histórie. Full resync (`sezam pull --full-resync`) históriu zachová; zmaže len verzie záznamu, ktorý po resyncu neostal, alebo verzie pod DEK-om, ktorý neostal (review d615826, predtým zmazal celú tabuľku; test `tests/test_review6_full_resync_history.py`).

Full resync a `snapshot restore` históriu a lokálne tombstones nahradia, preto sa pred nimi robí snapshot.

### 16.6 Obnova servera z lokálnej kópie (`sezam server reseed`)

Keď server príde o databázu (alebo ide o nový server), `sezam server reseed [URL]` ho naplní z lokálneho trezoru. URL je predvolene server, ku ktorému bol trezor pripojený. Príkaz vyžaduje master heslo a funguje **len na prázdnom serveri** (`/api/bootstrap-status` vracia `needs_setup`). Inak skončí chybou a v trezore nič nezmení.

Na rozdiel od `sezam connect` účet nedostane nové `user_id`: zostane rovnaké id, rovnaké kľúče aj `key_epoch`. Ostatné zariadenia účtu sa tak naďalej prihlásia a ich objekty sedia.

**Bootstrap s existujúcou identitou.** `POST /api/bootstrap` s `user_id`, `key_epoch`, `challenge` a `signature`:

- `challenge` je čerstvá (30 s) challenge z `POST /api/auth/challenge`, viazaná HMAC na `username`, a dá sa použiť len raz (`spent_challenges`).
- `signature` je Ed25519 podpis identitným kľúčom (`signing_pk` z požiadavky) nad `reseed_message` = `"sezam-reseed-v1" ‖ challenge ‖ user_id (26 B) ‖ len(username) u16be ‖ username ‖ signing_pk ‖ encryption_pk ‖ key_epoch u64be`. Doménový prefix bráni tomu, aby prihlasovací podpis (nad `sezam-auth-challenge-signature-v1` ‖ challenge, u starších klientov nad holou challenge) prešiel ako dôkaz pre reseed alebo naopak. Podpis pokrýva všetky polia, takže sa nedajú zameniť.
- Zlý alebo chýbajúci dôkaz vráti 401 a nič nezapíše. `challenge`, `signature` ani `key_epoch` bez `user_id` vráti 400.
- Server vytvorí admina s navrhnutým `user_id` a `sync_state.key_epoch` nastaví na `key_epoch` klienta. Prvý push preto nemusí „posúvať“ epochu od 0.

**Opustený bootstrap (lockout review #10).** Admin vznikne skôr, než nahrá `encrypted_keypair`. Ak upload nikdy neprebehol (web drží súkromný kľúč do uploadu len v pamäti), server predtým odmietal každý ďalší bootstrap natrvalo. Jediný admin bez kľúčového materiálu, starší ako `SEZAM_ABANDONED_BOOTSTRAP_SECONDS` (predvolene 3600 s) a bez stôp (objekty, zdieľania, audit, pozvánky, provisioning tokeny) sa berie ako žiadny admin: `bootstrap-status` vráti `needs_setup` a nový bootstrap ho v tej istej transakcii nahradí. Zariadenie, ktoré kľúč drží (desktop), dovtedy dokončí upload cez plný JWT. Rovnako registrácia: `pending` účet bez kľúčov po expirácii onboarding tokenu uvoľní username. Web odvodí KEK ešte pred `/api/bootstrap` a `/api/users/register`, takže medzi vytvorením účtu a uploadom je len lokálne zabalenie kľúča.

**Nahradiť ho smie len sieť prvého bootstrapu (review 688edcb #10).** Predtým mohol hodinu po nedokončenom nastavení ktokoľvek z internetu urobiť bootstrap a stať sa adminom servera, ktorý prevádzkovateľ považoval za nastavený. Bootstrap teraz uloží HMAC siete klienta (IPv4 adresa, IPv6 /64; rovnako ako limity `/recover`) do `users.recovery_trusted_nets`. Opustený bootstrap nahradí (a `bootstrap-status` ponúkne `needs_setup`) len požiadavka z tej istej siete. Inak 403 a varovanie v logu servera; `bootstrap-status` vráti `unfinished_setup` s vysvetlením a cestou von (rovnaký text má `detail` odmietnutého bootstrapu) a web ho ukáže na prihlasovacej obrazovke (review e4cd15a, nízke – predtým web ukázal len login, cez ktorý nikto neprejde). Z inej siete, alebo pre nastavenie spred tejto opravy (sieť nezapísaná), to povolí prevádzkovateľ: `SEZAM_BOOTSTRAP_RESET_ANY_NETWORK=1`, reštart, bootstrap, potom premennú zrušiť. Sieť bootstrapu sa pre `/recover` ráta ako sieť vlastníka (nie je pod prídelom pokusov zamknutého mena).

**Bootstrap nastaveného servera nečaká na zámok (review a159e97 H6).** `POST /api/bootstrap` je bez prihlásenia. Predtým najprv vzal zámok `commit_counter`, ten istý, ktorý drží každý push, a až potom zistil, že používatelia už existujú. Počas dlhého pushu tak vlna anonymných bootstrapov držala spojenia poolu, ostatné požiadavky padali na 500, `/health` vrátil 503 a watchdog zabil workera. Teraz sa 403 rozhodne obyčajným čítaním bez zámku (vrátane prípadu, keď opustený bootstrap nahradiť nemožno); zamknutá kontrola v transakcii zostáva len pre prázdny server alebo nahraditeľný opustený bootstrap. Prevádzkovateľ môže bootstrap po nastavení prvého admina úplne vypnúť: `SEZAM_BOOTSTRAP_DISABLED=1` (403 hneď, bez databázy).

Dôkaz overuje, že žiadateľ drží súkromný kľúč identity, ktorú navrhuje. Neoveruje, že je to „ten pravý“ účet: prvý bootstrap prázdneho servera môže urobiť ktokoľvek s prístupom k serveru, rovnako ako bez reseedu.

**Klient** (`src/sezam/vault/reseed.py`):

1. Spraví snapshot `server-reseed`.
2. Pred odoslaním bootstrapu si do `vault_meta` zapíše `pending_server_reseed = "bootstrap <URL>"`. Ak sa stratí odpoveď, ďalšie spustenie vidí neprázdny server a pokračuje. Ak server bootstrap odmietne (4xx), záznam zmaže.
3. Nahrá zašifrovaný keypair (`PUT /api/me/keypair` so signed challenge, rovnako ako dokončenie prerušeného bootstrapu). Prihlasuje sa identitným kľúčom, takže ak medzitým server obsadil iný účet, reseed zlyhá a nič neoznačí.
4. V jednej transakcii označí na push všetko, čo účet vlastní, a zapíše `pending_server_reseed = "push <URL>"`:
   - všetky uzly a ich záznamy (okrem priečinkov zdieľaných iným používateľom, teda s cudzím DEK),
   - všetky vlastné DEK (`pushed_dek_versions` vynulované) a obálky k nim (`envelope_sync_state` vymazané),
   - archivované DEK (`reseed_archive_ids`; bežný push ich posiela len v re-key dávke),
   - audit záznamy, ktorých podpis overí voči kľúčom nového servera (ostatné by zablokovali každý push, preto ostanú len lokálne),
   - `last_known_commit_seq = 0` a zmazaný sync checkpoint, inak by klient nový server bral ako rollback. `last_pushed_key_epoch = key_epoch`, lebo epochu už nastavil bootstrap.
5. Pushne a stiahne (nový checkpoint). Až potom zmaže `pending_server_reseed`. Ak server niečo odmietne, záznam ostane a ďalšie `sezam server reseed` pošle zvyšok.

**Ostatné zariadenia účtu** majú checkpoint z pôvodného servera s vyšším `commit_seq`. Nový server preto hlásia ako rollback a nechajú si lokálne dáta, lebo ho nevedia odlíšiť od útoku. Po overení, že reseed urobil vlastník, sa zosynchronizujú cez `sezam pull --full-resync`.

**Reseed zo zastaraného zariadenia (lockout review M6).** Ak reseed urobilo zariadenie, ktorému chýbali neskoršie zmeny iných zariadení, nový server je za nimi. Desktop full resync to pozná podľa toho, že server má nižší `commit_seq` ako posledný známy, alebo staršiu verziu objektu, ktorý zariadenie už so serverom synchronizovalo. Vtedy si ponechá vlastné uzly a záznamy, ktoré server nemá alebo má staršie (aj mazania), ich DEK a obálky, označí ich na push a `sezam pull` vypíše, koľko ich ponechal. Ďalší `sezam push` ich pošle. Priečinky iných používateľov (cudzí DEK) sa riadia serverom. Pri bežnom full resyncu po GC tombstonov je server vpredu a objekt, ktorý nemá, bol zmazaný inde, takže sa lokálne odstráni ako doteraz.

**Limity:** reseed obnoví jeden účet. Ostatní členovia tímu na prázdnom serveri neexistujú a musia sa pripojiť pozvánkou. Priečinky, ktoré im patria, a ich zdieľania musia obnoviť oni sami.

### 16.7 Záloha a obnova servera (prevádzka)

Review 8595ec1: návod chýbal. Server drží len šifrované dáta, ale bez zálohy všetky tri časti nižšie prevádzkovateľ obnoví len cez `sezam server reseed` (jeden účet, ostatní znova pozvánkou).

**Čo zálohovať (všetko naraz, z toho istého okamihu):**

| Časť | Kde (compose.yaml) | Bez nej po obnove |
|------|--------------------|-------------------|
| Databáza `sezam` (MariaDB) | volume `sezam-db-data` | žiadne dáta, len `sezam server reseed` |
| `jwt_key.bin` | volume `sezam-api-data` (`/app/data`, `SEZAM_JWT_KEY_PATH`) | nový kľúč: každé zariadenie sa raz prihlási znova (401 `token_invalid`), dáta ostanú |
| `SEZAM_HMAC_SECRET` (a heslá DB) | `.env` vedľa `compose.yaml` | server neštartuje bez nej; s inou hodnotou neplatia rozdelané challenge, dôveryhodné siete vlastníkov (`recovery_trusted_nets`) ani limity podľa adries a falošné salty neznámych mien sa zmenia (rozlíšiteľné od starých) |

**Ako:** databázu konzistentne za behu, bez zámku tabuliek:

```bash
docker exec sezam-db sh -c 'mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" \
  --single-transaction --hex-blob --databases sezam' | gzip > sezam-$(date +%F).sql.gz
docker cp sezam-api:/app/data/jwt_key.bin ./jwt_key.bin
```

Zálohu chráňte ako tajomstvo: `jwt_key.bin` s databázou stačí na podpísanie platných JWT a databáza obsahuje zabalené keypairy (offline hádanie hesiel, `9.4`). Obnovu raz za čas vyskúšajte na samostatnom stroji.

**Obnova:** zastaviť `sezam-api`, naliať dump do prázdnej databázy (`gunzip -c … | docker exec -i sezam-db sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD"'`), vrátiť `jwt_key.bin` a rovnakú `SEZAM_HMAC_SECRET`, spustiť `sezam-api` (migrácie schémy prebehnú samy pod `GET_LOCK`). Zariadenia potom:

- uvidia server ako rollback (nižší `commit_seq` ako ich checkpoint) a lokálne dáta si nechajú; po overení, že obnovu urobil prevádzkovateľ, `sezam pull --full-resync` (`16.6`, review M6: zmeny novšie ako záloha pošlú späť);
- vrátia na server koniec tímového denníka, ktorý záloha nemá (`DESIGN_TEAM_LOG.md`, „Obnova servera“);
- člen zaregistrovaný po zálohe: `sezam server rejoin` (denník ho menuje, `users` nie; review 8595ec1 #1). Ak si jeho meno medzitým zaregistroval iný účet, server odpovie `409 username_taken` a člen sa vráti pod iným menom: `sezam server rejoin URL --username NOVE_MENO`, na mobile ponúkne aplikácia nové meno (id a kľúče ostávajú, review 4acfdde R11);
- člen, ktorý po zálohe rotoval identitu a zariadenie s novým kľúčom stratil: admin `sezam team-log readmit USER_ID --fingerprint FP`;
- jediný admin s Shamir obnovou registrovanou po zálohe: kľúč obnovy, ktorý menuje denník, platí aj bez bloby (review 8595ec1 #4).

JWT odvolané po zálohe platia do expirácie (najviac 1 h, `6.2`). Tombstony zmazané GC po zálohe sa vrátia; zariadenie, ktoré ich už stiahlo, ich už má.

**MariaDB:** CI testuje ten istý obraz ako `compose.yaml` (`mariadb:11.8.3`). Schéma uvádza kolaciu `utf8mb4_uca1400_ai_ci` výslovne, takže tabuľky ju majú bez ohľadu na predvolenú kolaciu servera (10.11 predvolene `utf8mb4_general_ci`; review 8595ec1). Nová databáza preto potrebuje MariaDB 10.10 alebo novšiu (`utf8mb4_uca1400_ai_ci` je až od 10.10); na staršej server neštartuje a hlási to. Databáza zo staršej verzie Sezamu má `users` v kolácii servera z čias jej vytvorenia (na 10.x `utf8mb4_general_ci`) a cudzí kľúč medzi stĺpcami s rôznou koláciou MariaDB odmietne (errno 150). `create_schema` preto nové tabuľky zakladá v kolácii a znakovej sade stĺpca `users.id` a do logu zapíše varovanie (review 4acfdde R11 #1, `tests/test_review11_mariadb_legacy_collation.py`). Existujúce tabuľky sa nekonvertujú. MariaDB 11.6+ s predvoleným `innodb_snapshot_isolation=ON` ukončí transakciu, ktorej zamknuté čítanie narazí na novší riadok, chybou 1020; server ju opakuje ako deadlock (`RETRYABLE_LOCK_ERRORS`). `SEZAM_TOMBSTONE_GC_DAYS` musí byť aspoň 7 (`MIN_TOMBSTONE_GC_DAYS`), inak server neštartuje (0 predtým zmazalo každý tombstone pri ďalšom behu GC).

---

## 17. SSH agent pre AI

`sezam ssh-agent` je OpenSSH agent, ktorého súkromné kľúče nikdy neopustia trezor. AI používa bežné `ssh`, `scp`, `sftp`, `rsync -e ssh` alebo `git`, kľúč však nikdy nevidí. Agent počúva na `~/.sezam/run/agent.sock` (`0600`), na Windows na pipe `\\.\pipe\sezam-ssh-agent-<používateľ>` prístupnej len vlastníkovi. Riadi sa CLI session ako `mcp-serve`: bez `sezam unlock` neponúka žiadne kľúče a `sezam lock` aj `sezam ai off` ho zastavia.

**Prihlásenia cez agenta po `ai off` (review d615826).** Agent podpíše len prihlásenie; shell, ktorý si AI vlastným `ssh` otvorí, brzda neukončí. `sezam ai off` s otvorenou CLI session preto vypíše každý `username@host:port`, pre ktorý agent od posledného `ai on` podpísal prihlásenie (z auditu `agent_sign`), bez session len upozorní, že také prihlásenia nezatvára. `sezam ai off --terminate-remote` (heslo si vypýta až po zatiahnutí brzdy) sa pri položke s obyčajným kľúčom prihlási tou položkou a pošle `SIGKILL` každej inej session (SID) toho účtu (`sezam/mcp/agent_sessions.py`), teda aj session človeka pod tým istým účtom; AI preto patrí vlastný účet. Prihlásenie so Sezam SSH certifikátom ukončí reaper z `sezam ai-host-setup` po uplynutí platnosti certifikátu (CA kľúč sa sám neprihlasuje), takže je len vypísané. Review 7c10379: pri OpenSSH s oddelením privilégií beží sshd proces vlastného prihlásenia (rodič shellu) pod tým účtom v inej session; starý príkaz ho zabil, spojenie padlo pred potvrdením a výsledok bol `FAILED`. Session rodiča sa teraz vynechá, skript beží v čistom `/bin/sh` (`env -i`, bez aliasov, funkcií a PATH účtu) a potvrdenie nesie nonce tohto behu, takže `~/.bashrc`, ktorý len vypíše starú pevnú značku, už neplatí ako úspech (`tests/test_review7_terminate_remote_openssh.py` s reálnym OpenSSH; beží v CI úlohe `host` ako root s `SEZAM_REQUIRE_HOST_SETUP=1`, takže sa tam nesmie preskočiť; na `agent_sessions.py` z `b60a91e~1` oba prípady padajú: `FAILED: exit -1` a `sessions killed` pri `~/.bashrc` so značkou). Hranica: štartovacie súbory účtu (bash číta `~/.bashrc` aj pri ssh príkaze) bežia pred skriptom, takže účet, do ktorého AI mohla písať, vie úspech predstierať aj s nonce (prečíta ho z príkazu); výsledok preto znie „ako hlási účet“. Istotu dá len `pkill -KILL -u <účet>` ako root na hostiteľovi alebo certifikátový účet s reaperom.

### 17.1 Politika položky

```
sezam mcp-policy Servers/web --tier 1 --allow-action ssh_agent
```

- Agent ponúka len Ed25519 a RSA kľúče z položiek s akciou `ssh_agent`. Položky s tier 2 a všetko v priečinku s tier 2 sú neviditeľné.
- Podpíše len SSH prihlásenie (`publickey` userauth) presne týmto kľúčom a ako `username` z položky. RSA len SHA-2 (`rsa-sha2-256/512`), SHA-1 nikdy. Podpis iných dát (napr. `git` SSHSIG) odmietne.
- Tier 0 podpíše hneď. Tier 1 ukáže okno „An AI agent wants to log in as X on Y“ s overeným odtlačkom host key. Po schválení sa voliteľne opýta, či rovnaké prihlásenie (položka, host, používateľ) povoliť bez pýtania na N minút (`--grant-minutes`, predvolene 10, `0` = nikdy). Povolenie je len v pamäti a zanikne pri zamknutí trezoru alebo vypnutí AI.
- Kľúč položky podpíše len na spojení zviazanom cez `session-bind@openssh.com` (OpenSSH ≥ 8.9) s host key hostiteľa z položky, rovnako ako ho overuje MCP broker pred pripojením: položka s `host_key_sha256` len s presne týmto host key, položka bez neho len ak je zviazaný host key v `~/.ssh/known_hosts` pre jej `host:port`. Inak odmietne (`host_key_mismatch`, `host_key_unknown`).
- Bez session-bind (napr. paramiko) agent nevie, na ktorý server podpis ide, preto podpíše len položka s akciou `ssh_agent_unbound` a len keď kľúč nemá žiadna iná ponúkaná položka pripnutý cez `host_key_sha256` bez tejto akcie. Tier 1 okno vtedy uvedie, že host key nie je overený.
- Cez forwardovaný agent podpíše len položka s akciou `ssh_agent_forwarding`.
- Každý podpis aj každé odmietnutie sa zapíše do auditu (položka, host, používateľ, dôvod).

### 17.2 Konfigurácia klienta

`sezam ssh-agent --print-config` vypíše bloky do `~/.ssh/config` pre všetky položky, ktoré agent ponúka, napríklad:

```
Host sezam-servers-web
    HostName web.example.com
    Port 22
    User ai-web
    IdentityAgent "~/.sezam/run/agent.sock"
    ForwardAgent no
```

`IdentitiesOnly yes` tam zámerne nie je: bez `IdentityFile` s verejným kľúčom by ssh kľúče z agenta ignoroval.

### 17.3 Obmedzenie

Po prihlásení má AI na serveri shell. Môže si do `~/.ssh/authorized_keys` pridať vlastný kľúč a odvtedy sa prihlasovať bez Sezamu. Preto AI dávajte samostatný účet s minimálnymi právami. Tvrdú hranicu dávajú krátkodobé SSH certifikáty zo Sezamu s `AuthorizedKeysFile none` (sekcia 17.4).

**Kill switch v MCP brokeri (review d615826 H5).** `close_all()` predtým zatváral len interaktívne session, takže bežiaci `ssh_execute` alebo SFTP prenos dobehol a agent dostal výsledok pár sekúnd po `sezam ai off`. `SSHManager` teraz eviduje aj klientov bežiacich `ssh_execute`, `ssh_upload` a `ssh_download` a `close_all()` ich preruší; operácia skončí chybou `cut_off` aj vtedy, keď brzda prišla počas pripájania. Broker navyše pred vrátením výsledku každého nástroja (aj FTP, HTTP a čítania tajomstva) znova overí stav vypínača a zámku: brzda, ktorú zapísal iný proces, výsledok zadrží (`ai_disabled`, v audite `FAILED cut_off`). Príkaz, ktorý už na serveri zbehol, sa tým nevráti späť, agent sa len nedozvie jeho výstup.

**Stav vypínača chránený MAC (review d615826).** Stav je vo `vault_meta`, teda v obyčajnej SQLite. Chýbajúci `ai_access_enabled` predtým znamenal ZAPNUTÉ, takže agent so shellom AI zapol príkazom `DELETE FROM vault_meta WHERE key='ai_access_enabled'`. Zvýšením `ai_remote_policy_epoch` na maximum zase každá brzda z mobilu vyzerala ako už aplikovaná. Teraz (`sezam/vault/ai_access.py`):
- ZAPNUTÉ platí len s `ai_access_mac` = HMAC-SHA256 nad (`enabled`, `epoch`) kľúčom odvodeným z KEK (`HMAC(KEK, "sezam/ai-access-state/v1")`). Chýbajúca, neplatná alebo nepodpísaná hodnota je VYPNUTÉ. Vypnutie MAC nepotrebuje, takže brzda funguje aj na zamknutom trezore.
- Epocha poslednej aplikovanej politiky z mobilu platí len s `ai_remote_policy_mac`. Bez neho je 0, takže platná politika z mobilu zabrzdí znova.
- Nový trezor (`Vault.create`, `import-key`) začína zapnutý a podpísaný. Pri zmene KEK (zmena hesla, prevzatá rotácia, org recovery) `rewrap_all_deks` prepodpíše, čo platilo pod starým KEK.
- Zamknutý trezor MAC overiť nevie. `sezam ai status`, GUI a štart `mcp-serve` preto bez odomknutia ukazujú len to, čo trezor tvrdí. Každé volanie nástroja potrebuje odomknutý trezor, a teda platný MAC.
- **Migrácia:** trezor sprzed tejto zmeny nemá MAC, takže AI je po aktualizácii vypnutá, kým vlastník raz nespustí `sezam ai on`.
- **Replay starého ZAPNUTÉ (review 7c10379 H6).** `disable()` predtým MAC nechal, takže stačilo zapísať späť (`"1"`, stará epocha) a AI bola pri ďalšom odomknutí zapnutá. Bežiacu brzdu navyše uvoľnilo akékoľvek ZAPNUTÉ prečítané pri zamknutom trezore (MAC sa vtedy overiť nedá), po čom replay prešiel aj pod bežiacim brokerom. Teraz `disable()` MAC v tej istej transakcii zmaže (nový zapečatí len `sezam ai on`), brzdu brokera uvoľní len overené ZAPNUTÉ (`verified_on_epoch`: odomknutý trezor, platný MAC, epocha aspoň epocha brzdy) a broker odmietne ZAPNUTÉ s epochou nižšou, než najvyššia, pri ktorej počas behu videl VYPNUTÉ (aj `sezam ai off` z iného procesu). Test `tests/test_review7_ai_switch_replay_h6.py`.
- **Dva brokery naraz (review 7c10379).** `disable()` čítal a potom zapisoval v odloženej transakcii. Keď medzi tým iný broker (iný proces nad tým istým trezorom) zapísal svoje VYPNUTÉ, SQLite zápis hneď odmietol (`database is locked`, `SQLITE_BUSY_SNAPSHOT`, ktorý `busy_timeout` neopakuje) a brzda sa neuložila. Teraz `disable()` aj zaradenie auditného záznamu na neskôr berú zámok na zápis pred čítaním (`VaultDB.transaction(immediate=True)`, `BEGIN IMMEDIATE`), takže druhý broker počká a započítajú sa obe vypnutia. Test `tests/test_review7_two_brokers_disable.py`.
- **Brzda uložená iným procesom počas pripájania (review 1141a20).** HTTP a FTP po nadviazaní spojenia overovali len príznak brzdy v pamäti brokera. Keď brzda došla do trezoru, ale nie k brokeru (riadiaci kanál zahltený alebo nedostupný, `sezam ai off` vtedy zapíše vypínač sám), požiadavka práve sa pripájajúca odišla na server a agent dostal chybu až dodatočne. Kontrola po pripojení (a pri SSH na začiatku operácie) teraz číta aj uložený vypínač; chyba pri čítaní znamená prerušiť. Test `tests/test_review9_ai_off_other_process_connect.py`.
- **Snapshot nenesie ZAPNUTÉ (review a159e97, 1141a20 M-AI4).** Obnova snapshotu alebo zálohy vypne AI v kópii ešte pred inštaláciou (`ai_access.off_for_restore`). Agent L1 však vedel skopírovať riadky vypínača z automatického snapshotu do živého trezoru a nový proces videl overené ZAPNUTÉ. Každá kópia trezoru (snapshot, záloha) preto vzniká s VYPNUTÉ a bez MAC (`ai_access.off_in_copy`); živý trezor ostáva zapnutý. Testy `tests/test_review8_restore_keeps_ai_off.py`, `tests/test_review9_ai_snapshot_switch.py`.
- **Uložené ZAPNUTÉ vrátené po reštarte brokera (review c78fd19 R13-11).** Agent L1 si počas zapnutej AI skopíroval riadky vypínača zo živého trezoru (`"1"`, epocha, platný MAC) a po `sezam ai off` ich zapísal späť. Bežiaci broker ich odmietol (jeho podlaha z H6), ale reštartovaný broker podlahu nemal a staré zapečatené ZAPNUTÉ prijal. Pri synchronizovanom trezore teraz broker drží najvyššiu epochu VYPNUTÉ aj na sync serveri (`PUT/GET /api/ai-anchor`, `remote_policy.ServerAnchor`), kam ju agent nevie znížiť. Kotva patrí jednému súboru trezoru. Jej domov (náhodné id, server a účet) je zapečatený pod KEK v trezore (`ai_anchor_home` + MAC, review 8bc70f7 R14-M3); predtým id vzniklo z mena stroja a cesty a server sa bral z `server_url`, ktorý agent vedel zmazať alebo presmerovať. Epocha nesie MAC pod KEK, takže ju server nevie zvýšiť, iba stratiť. Server ju nikdy neznižuje (nižšia epocha je 409). Broker ju zapíše hneď, keď uvidí nové VYPNUTÉ (poller sa zobudí, nečaká 30 s). Po každom odomknutí prvé volanie nástroja počká na jednu kontrolu kotvy, najviac 10 s. ZAPNUTÉ pod kotvou broker berie ako VYPNUTÉ. `sezam ai on` zapne AI na epoche aspoň takej, akú broker naposledy prevzal z kotvy (`ai_access_floor` v trezore). Ak agent tento riadok zmaže, AI zostane vypnutá, nie zapnutá. Zápis kotvy (`PUT /api/ai-anchor`) musí niesť podpis kľúčom účtu, samotný JWT nestačí (R14-M3). **R14-M3:** kontrola, ktorá zlyhala (server nedostupný, domov sa neoverí), sa už neráta ako vykonaná: trezor, ktorý kotvu očakáva (má domov alebo `server_url`), drží AI vypnutú (`ai_anchor_unverified`), kým kontrola neprejde. `sezam ai off` a prepínač v GUI kotvia svoju epochu VYPNUTÉ samy (`ServerAnchor.anchor_off`), nielen bežiaci broker: bez brokera agent inak vrátil uložené ZAPNUTÉ a ďalší broker ho prijal. Brzda ide vždy prvá a nikdy nečaká na server. Na zamknutom trezore (bez CLI session, zamknuté okno) sa kotviť nedá (MAC aj podpis potrebujú KEK): CLI to vypíše a odporučí `sezam unlock` a nové `sezam ai off`, GUI kotvu dopíše sama po odomknutí okna. **Hranice:** trezor bez sync servera kotvu nemá. Riadky, ktoré agent vráti medzi brzdou na zamknutom trezore (bez bežiaceho brokera) a jej zakotvením, kotva nezachytí. Testy `tests/test_review13_ai_switch_anchor.py`, `tests/test_review14_ai_anchor_fail_closed.py`, `tests/test_review14_ai_off_anchored.py`.
- **Hranica (L1):** agent pod tým istým OS používateľom vie stav nanovo vytvoriť len s KEK (napr. z keyringu počas CLI session). Vie však vrátiť kópiu riadkov (alebo celého súboru trezoru), ktorú si uložil, kým bola AI zapnutá. Bežiaci broker ju odmietne (pamätá si epochu brzdy aj najvyššiu videnú epochu VYPNUTÉ), nový proces nie. Brzdu z mobilu vráti aj nový proces, lebo jej epochu drží server (aplikovaná epocha sa vráti s kópiou, takže platná politika zabrzdí znova). Tvrdú hranicu dáva až samostatný OS používateľ (L2, sekcia 18).

### 17.4 Sezam ako SSH CA

Položka typu „AI SSH CA“ je SSH položka s poľom `ssh_ca` = `yes`, ktorej `private_key` je Ed25519 CA kľúč (iný typ CA kľúča agent neponúkne). `host`, `port`, `username` a `host_key_sha256` majú rovnaký význam ako pri bežnej položke, `username` je zároveň jediný principal certifikátu.

- Agent CA kľúč nikdy neponúkne ani ním neprihlasuje. MCP broker sa s takouto položkou nepripojí vôbec (`invalid_entry`).
- Pri `REQUEST_IDENTITIES` agent v pamäti vygeneruje efemérny Ed25519 kľúč a CA kľúčom mu podpíše certifikát `ssh-ed25519-cert-v01@openssh.com` (formát `PROTOCOL.certkeys`, zostavený v Pythone, `ssh-keygen -s` sa nevolá). Ponúkne ho s komentárom `sezam-cert:<cesta>`.
- Certifikát: typ user, `principals = [username]`, platnosť od teraz − 60 s do teraz + `cert_ttl_minutes` (predvolene 10, 1 až 60), rozšírenie len `permit-pty`, kritická voľba `source-address` len ak je vyplnené pole `source_address` (adresy alebo CIDR oddelené čiarkou), `key_id = sezam-ai:<id položky>:<AI epocha>:<náhodný nonce>`. `key_id` vidno v logu `sshd` aj v audite (`cert_key_id`, `cert_serial`, `cert_valid_before`).
- Neplatné `cert_ttl_minutes` alebo `source_address` znamená, že agent položku neponúkne (fail-closed).
- Rovnaký certifikát agent ponúka, kým mu ostáva aspoň 60 s, potom vydá nový. Podpisuje len certifikátom, ktorý už ponúkol a ešte platí. Pre podpis platia rovnaké pravidlá ako v 17.1 (session-bind k hostu položky, tier 1 schválenie, audit), algoritmus musí byť `ssh-ed25519-cert-v01@openssh.com`.
- Zamknutie trezoru a `sezam ai off` certifikát aj efemérny kľúč zahodia. Po `sezam ai on` je nová epocha, teda nový certifikát. Certifikát, ktorý si AI skopírovala, vyprší najneskôr o TTL.
- Na serveri: `TrustedUserCAKeys` s verejným CA kľúčom a pre AI účet `AuthorizedKeysFile none`, `AuthorizedPrincipalsFile` a zákaz forwardingu, pozri 17.5.

### 17.5 Príprava servera: `sezam ai-host-setup`

```
sezam ai-host-setup --entry Servers/Web-AI [--web-root /var/www/site] [--sudo-command "/bin/systemctl reload nginx"]
```

Príkaz **iba vypíše** shell skript, nič nespúšťa ani nikam nepripája. Skript skontrolujte a spustite ako root na serveri. Obsahuje len verejné údaje (verejný CA kľúč, meno účtu, cesty), všetky hodnoty sú overené a escapované (`shlex.quote`).

- Samostatný účet `username` z položky (`useradd --create-home`, bez sudo). Heslo `*`: prihlásenie heslom nejde, ale účet nie je zamknutý (`!` by pri `sshd` bez PAM odmietol aj certifikát). Meno musí byť bežné POSIX meno (malé písmená, číslice, `_`, `-`), nie `root` ani systémový účet.
- Nič, čo by prežilo kill switch: meno v `/etc/cron.deny` a `/etc/at.deny`, `loginctl disable-linger` a rootovský reaper `/usr/local/sbin/sezam-ai-reap-<user>` (systemd timer každých 30 s, inak `/etc/cron.d` každú minútu; bez systemd aj cronu skript skončí chybou ešte pred povolením účtu v `sshd`). Reaper ukončí SSH session účtu staršiu ako TTL certifikátu. Keď už účet nemá žiadnu živú session, zabije všetky jeho procesy, aj tie odpojené cez `setsid nohup`. Session pozná podľa rootovského procesu `sshd: <user> [priv]`, ktorý účet nevie podvrhnúť. Účet preto nemôže mať nič bežiace bez SSH session (ani dlhý build na pozadí), a to platí aj pre `su - <user>` od admina.
- `--web-root`: adresár (aspoň dve úrovne, mimo systémových adresárov) dostane skupinu účtu a `g+rwX`, podadresáre `g+s`.
- `--sudo-command`: presne jeden príkaz bez wildcardov a sudoers syntaxe do `/etc/sudoers.d/sezam-ai-<user>`. Súbor sa najprv overí `visudo -cf` a až potom presunie na miesto. Znaky `:` a `=` v argumentoch sa zapíšu escapované (`\:`, `\=`, review d615826). Neescapované `:` totiž v sudoers ukončí príkaz a začne ďalšie pravidlo, takže `"/bin/true x : ALL = NOPASSWD: ALL"` dalo AI účtu root a `visudo -c` to ako platnú syntax prepustil. Príkaz bez argumentov dostane `""` (review 7c10379): sudoers príkaz bez argumentov povolí s ľubovoľnými, takže `--sudo-command /usr/bin/systemctl` dovolil `sudo systemctl edit --full ssh`, teda root. S `""` nepovolí žiadne argumenty; príkaz s argumentmi musí sedieť presne. Ani presný príkaz nie je hranica, ak sám ponúka shell alebo editor (`less`, `vi`, `systemctl edit` …): takému príkazu `--sudo-command` nedávaj. Program musí byť taký, ktorý AI nevie prepísať (review 1141a20): `--web-root /var/www/site --sudo-command /var/www/site/deploy.sh` dal root čomukoľvek, čo AI zapísala do `deploy.sh`. Príkaz vo web roote, v `/home`, `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, `/var/www` alebo s `.`, `..` či `//` v ceste sa odmietne už pri generovaní. Skript navyše pred `visudo` spustí `sezam_root_only`: program aj každý adresár nad ním (aj po rozbalení symlinkov) musí patriť rootovi a nikto iný doň nesmie zapisovať, inak skript skončí bez pravidla. Test `tests/test_review9_ai_host_setup_sudo_target.py`. To isté platí pre argumenty (review c78fd19 R13-11): `/bin/sh /var/www/site/deploy.sh` predtým prešlo, lebo `/bin/sh` patrí rootovi. Každý argument, ktorý je absolútna cesta, prejde rovnakou kontrolou pri generovaní aj cez `sezam_root_only` na serveri. Argument s relatívnou cestou sa odmietne, lebo sa vyhodnotí v adresári, v ktorom AI spustí sudo. Shell alebo interpreter (`sh`, `bash`, `python3`, `perl` …) je povolený len so skriptom zadaným absolútnou cestou ako prvým argumentom. Samotný `/bin/bash` by bol root shell a `python3 -m x` či `sh deploy.sh` by spustili kód z adresára AI. Test `tests/test_review13_sudo_command_arguments.py`. Systémový program (v `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/lib*`, `/lib*`, `/usr/libexec`, `/usr/share`, `/snap`) prejde len v jednom z presných tvarov (review 8bc70f7 R14-M4): `systemctl restart|reload|try-restart|reload-or-restart|start|stop <unit>`, `service <unit> restart|reload|start|stop`, `nginx -t`, `nginx -s reload`, `apachectl`/`apache2ctl graceful|configtest`. Predtým sa odmietalo len to, čo bolo známe ako nebezpečné, takže prešlo `make install` (Makefile v adresári AI), `git pull` (jeho hooky), `systemctl status` (pager s `!sh`) či `tee /etc/sudoers`. Čokoľvek iné musí byť rootov skript v `/usr/local/sbin` (napr. `/usr/local/sbin/deploy`), spustený priamo alebo shellom či interpreterom zo systémových adresárov. Wrappery (`env`, `sudo`, `xargs`, `timeout`, `nice` …) sa neprijmú vôbec. Test `tests/test_review14_sudo_command_allowlist.py`. Predtým prešiel ako „skript“ akýkoľvek program mimo systémových adresárov (review 18c300f R16-L1), napríklad `/opt/conda/bin/ipython`, teda root shell. Skript na serveri cez `sezam_operator_script` overí, že skript sa aj po vyriešení symlinkov nachádza v `/usr/local/sbin` (nie symlink na `/usr/bin/make` či `/opt/conda/bin/ipython`) a že skript spúšťaný priamo začína riadkom `#!`, teda nejde o program skopírovaný do tohto adresára. Test `tests/test_r16_sudo_command_script_dir.py`.
- CA kľúč do `/etc/ssh/sezam_ai_ca_<user>.pub` a principal do `/etc/ssh/principals/<user>`.
- Na koniec `sshd_config` raz pripojí blok `Match User <user>` s `TrustedUserCAKeys` (CA platí len pre tento účet, nie pre root ani iných), `AuthorizedKeysFile none`, `AuthorizedPrincipalsFile`, bez hesla a bez agent/TCP/stream/X11 forwardingu, tunelov a `~/.ssh/rc`. Potom `sshd -t` a reload.

Výsledok je úroveň L3 (sekcia 18): kľúč, ktorý si AI pridá do `authorized_keys`, nefunguje. `sezam ai off` alebo brzda z mobilu zastaví podpisovanie CA a už vydaný certifikát vyprší najneskôr o TTL. Sezam sa na server nepripája, takže v režime agenta brzda sama zastaví len **nové** prihlásenia. Už otvorené spojenie (OpenSSH kontroluje platnosť certifikátu len pri prihlásení) a procesy účtu ukončí až reaper na serveri. Po brzde tak z účtu nič nezostane najneskôr o TTL plus jeden tik reapera. Ak sa AI stihne znova prihlásiť certifikátom, ktorý ešte drží, je to najneskôr o 2 × TTL plus jeden tik. Okamžité odstrihnutie priamo na serveri: `pkill -KILL -u <user>`.

### 17.6 Redakcia tajomstiev vo výstupe MCP brokera

MCP nástroje `ssh_execute` (stdout aj stderr) a `ssh_session_read` (`sezam/mcp/redact.py`) nahradia každý výskyt tajomstva položky textom `[REDACTED]` skôr, než výstup vráti agentovi. Tajomstvá sú polia označené `sensitive`, heslo (`password`, `ssh_password`), passphrase (`passphrase`, `key_passphrase`) a súkromný kľúč aj každý jeho riadok s aspoň 16 znakmi.

- Hľadá sa aj base64 v štandardnej aj URL-safe abecede, pri ktoromkoľvek zarovnaní tajomstva v dlhšom kódovanom texte (fragment aspoň 8 znakov), a URL-encoded tvar (`%XX` aj `+` za medzeru).
- Hodnoty kratšie ako 4 znaky sa neredigujú, inak by sa rozbil bežný výstup.
- `ssh_session_read` drží späť len chvost, ktorý môže byť začiatkom tajomstva, a úplný výskyt kratšieho tajomstva, ktoré môže byť začiatkom dlhšieho. Vráti ho pri ďalšom čítaní, takže sa redigujú aj tajomstvá rozdelené na hranici dvoch čítaní. Ostatný výstup (napr. prompt shellu) sa vráti hneď. Na konci streamu sa chvost uvoľní.
- `ssh_execute` s orezaným výstupom (`truncated`) rediguje aj začiatok tajomstva, na ktorom orezanie skončilo.

Je to ochrana pred náhodným únikom (napr. `cat .env`, `env`, chybová hláška s heslom), nie hranica proti agentovi, ktorý chce tajomstvo zámerne vyniesť: iné kódovanie (hex, rozdelenie znakov, šifrovanie) redakcia nezachytí.

### 17.7 Prehľad auditu: `sezam ai log`

```
sezam ai log [--since 24h] [--entry Servers/web]
```

Vypíše záznamy AI brokera z auditu trezoru (`sezam/mcp/audit_view.py`), jeden riadok na záznam: čas, agent, položka, akcia, výsledok a bajty, pod ním príkaz alebo cesty. Detaily auditu sú šifrované, preto príkaz potrebuje odomknutý trezor (CLI session alebo heslo na termináli). Bez terminálu sa na heslo nepýta a skončí chybou.

- MCP nástroje (`mcp_ssh`, `mcp_secret`): záznam zámeru (`started`) aj výsledku (`ok`, `exit N`, `FAILED <kód>`), takže je vidieť aj operácia, ktorá nedobehla. Pri `ssh_execute` príkaz (`$ …`) so zredigovanými tajomstvami položky (sekcia 17.6), najviac 500 bajtov, a bajty stdout/stderr. Pri uploade a downloade lokálna a vzdialená cesta, počet súborov a bajty, pri session bajty vstupu a výstupu (vstup session sa ukladá len ako SHA-256, môže obsahovať napísané heslá).
- Rozhodnutia (`mcp_approval`): `APPROVED by owner`, `DENIED by owner`, `DENIED (no answer)` pri tier 1 a `DENIED (policy)`, keď akcia položky nie je povolená. Schválenie, ktoré sa nedá zapísať do auditu, sa nevykoná.
- Podpisy SSH agenta: `user@host:port`, `key_id` certifikátu zo Sezam CA, spôsob schválenia (`auto`, `grant`, `owner`) a odmietnutia s dôvodom.
- Kill switch: `AI OFF` / `AI ON` s pôvodom (CLI, mobil, …) a epochou.
- Text, ktorý zvolil agent (príkaz, cesty, meno agenta), sa vypisuje cez `visible_text`: riadiace, bidi a neviditeľné znaky ako `\uXXXX`, takže nevie pohnúť kurzorom ani skryť text v termináli. Záznam s nečitateľnými detailmi sa vypíše ako `(details unreadable)`, nevynechá sa.

### 17.8 Koreň vzdialených ciest: `remote_root`

```
sezam mcp-policy Servers/web --remote-root /var/www/site    # --clear-remote-root zruší
```

Šifrovaná politika položky, spoločná pre prenosové nástroje (`ssh_upload`, `ssh_download`, FTP). Hodnota musí byť absolútna POSIX cesta bez `..` a uloží sa normalizovaná. Neplatná hodnota (napr. synchronizovaná z iného klienta) prenos odmietne (`policy_invalid`) a `sezam ai status` ju v stĺpci `REMOTE_ROOT` ukáže ako `invalid`.

- Relatívna cesta agenta sa berie od `remote_root`. Absolútna musí po normalizácii ležať pod ním. Každý komponent `..` aj spätné lomítko sa odmietne (`remote_path_denied`), rovnako súrodenec s rovnakým prefixom (`/var/www/site2`).
- Cez SFTP sa pred prenosom cez `lstat` skontroluje každý existujúci komponent cesty pod `remote_root`. Symbolický odkaz (`<root>/link -> /etc`) sa odmietne (`symlink_denied`). Upload nikdy neprepíše existujúci symbolický odkaz ani bez `remote_root`, zápis by išiel do jeho cieľa.
- Bez `remote_root` sa vzdialené cesty neobmedzujú. Ak má položka zároveň `ssh_execute` alebo `ssh_session`, `remote_root` nie je bezpečnostná hranica: agent si cez shell môže vytvoriť odkaz alebo kopírovať kamkoľvek. Hranicou je len pri položke, ktorá má iba prenosové akcie.

### 17.9 FTP/FTPS nástroj `ftp`

```
sezam mcp-policy Hosting/web --tier 1 --allow-action ftp --remote-root /www
```

MCP nástroj `ftp` (`sezam/mcp/ftp.py`) je pre hostingy bez SSH. Parameter `op` je jedna z operácií `list`, `upload`, `download`, `delete`, `mkdir`, `rename`, ďalej `remote_path`, pri prenose `local_path`, pri premenovaní `new_remote_path` a voľby `recursive` a `overwrite`. `delete` zmaže jeden súbor alebo jeden prázdny priečinok, rekurzívne nikdy.

Polia položky sú `host`, `port`, `username` a `password`, voliteľne `ftps_mode`, `tls_ca_cert` a `allow_plain_ftp`.

- **TLS je povinné.** `ftps_mode: explicit` (predvolené, port 21) pošle `AUTH TLS` ešte pred `USER`/`PASS` a po prihlásení `PBSZ 0` + `PROT P`, takže je šifrovaný aj dátový kanál. Dátové spojenia pokračujú v TLS session riadiaceho kanála, čo vyžadujú napr. vsftpd a ProFTPD. `ftps_mode: implicit` (predvolene port 990) má TLS od prvého bajtu. Certifikát servera sa overuje vrátane mena hostiteľa (`ssl.create_default_context()`, minimálne TLS 1.2). `tls_ca_cert` (PEM) dôveruje uvedenej CA alebo self-signed certifikátu namiesto systémového úložiska, meno hostiteľa sa overuje aj vtedy.
- **Bez TLS sa heslo nikdy nepošle.** Ak server `AUTH TLS` odmietne (`tls_unavailable`), certifikát neprejde (`tls_verify_failed`) alebo zlyhá handshake (`tls_failed`), spojenie skončí pred `USER`/`PASS`. Na nešifrované FTP sa nikdy neprepne.
- **Nešifrované FTP** je len s poľom `allow_plain_ftp: true` (bez `ftps_mode`). Schvaľovacie okno vtedy začína riadkom `WARNING: Plain FTP …` a ukáže `Encryption: NONE - plain FTP`. Každý výsledok nástroja vrátane chýb obsahuje pole `warning`. `sezam ai log` pri takej operácii uvedie `(PLAIN FTP, unencrypted)`. Neplatná kombinácia alebo hodnota položku odmietne (`invalid_entry`). Rovnako ju odmietne zalomenie riadku v mene alebo hesle, ktorým by sa dali vložiť ďalšie FTP príkazy.
- **Zdieľané politiky s SSH nástrojmi:**
  - explicitná akcia `ftp` a tiery 0/1/2,
  - schválenie so skutočným cieľom z položky (host, port, používateľ, šifrovanie),
  - `remote_root` (sekcia 17.8), `local_root` a chránené lokálne cesty,
  - limit veľkosti prenosu (aj počas sťahovania) a timeouty spojenia a operácie,
  - audit zámeru aj výsledku (`mcp_ftp`, v `sezam ai log` ako `ftp <op>`).
- **Kill switch:** `sezam ai off`, brzda z mobilu aj zamknutie trezoru odmietnu každé ďalšie volanie a prerušia aj prebiehajúci prenos (`cut_off`).
- **Výpis a typ cesty** sa zisťuje cez `MLSD`/`MLST` (RFC 3659). Na serveroch bez nich (vsftpd) sa použije `NLST`, `SIZE` a `CWD`. Pri rekurzívnom sťahovaní sa meno z výpisu servera s lomítkom, spätným lomítkom alebo `..` odmietne.
- **Symbolické odkazy:** typ, ktorý server pod `remote_root` ohlási ako odkaz (napr. `OS.unix=slink`), sa odmietne. Mnohé FTP servery však odkaz nasledujú a hlásia typ cieľa. Tam drží len chroot samotného FTP servera.

### 17.10 HTTP/API požiadavky (`sezam/mcp/http_api.py`)

Pre API hostingov a CMS (application passwords, API tokeny). Položka opisuje jediné API, ktoré smie AI volať:

| Pole | Význam |
|------|--------|
| `base_url` | `https://host[:port][/základná/cesta]`, bez mena, hesla, query a fragmentu. `http://` len s `allow_plain_http: true`. |
| `auth_header` | šablóna, napr. `Authorization: Bearer {token}`. `{pole}` je hodnota poľa položky, `{basic}` je `base64(username:password)` pre HTTP Basic (WordPress application password). Nesmie nastaviť `Host`, `Content-Length`, `Transfer-Encoding` ani `Connection`. |
| `allowed_methods` | zoznam z `GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS`. Predvolene len `GET`. |
| `allowed_path_prefixes` | **povinné** (default deny), relatívne k základnej ceste, porovnávajú sa celé segmenty (`/wp/v2` nepustí `/wp/v2x`). `/` povolí všetko pod `base_url`. |
| `allowed_params` | voliteľné: jediné mená parametrov, ktoré smú byť v query a v tele formulára/multipartu (napr. `per_page, status, _fields`). Bez neho prejde každé meno okrem odmietnutých nižšie. |
| `tls_ca_cert` | voliteľný PEM, ktorému sa dôveruje namiesto systémového úložiska. |
| `path_routing_only` | voliteľné `true` pre API, ktoré smeruje len podľa cesty (nie cez front controller): mená front controllerov (`q`, `s`, `action`, `p`, `url` …) sú potom bežné parametre. `rest_route`, prepisy metódy a mená s `_` ostávajú odmietnuté. |

- **Hlavičku vloží broker** a AI ju nevidí. AI smie nastaviť len `Accept`, `Content-Type`, `If-Match` a `If-None-Match`. Iné hlavičky (napr. `Authorization`, `Host`, `Cookie`) vrátia `header_denied`.
- **Len hostiteľ a port z `base_url`.** Cesta od AI musí byť absolútna, bez `.`/`..`, `//`, `\`, `#`, medzier a bez percentom zakódovaných `.`, `/`, `\` a NUL. Mimo prefixov skončí `path_denied`, metóda mimo zoznamu `method_denied`. Obe chyby vzniknú pred pripojením.
- **Smerovanie a metóda mimo URL (review d615826).** Metóda a prefix sa predtým kontrolovali len na ceste: WordPress cez `?rest_route=/wp/v2/users` dosiahne ľubovoľný endpoint a `_method=DELETE` (v query, alebo vo formulári/JSON tele pri Laravel, Rails, Symfony) zmení povolený POST na inú metódu. `rest_route` v query vráti `path_denied`, `_method`, `X-HTTP-Method-Override` v query aj `_method` ako meno poľa tela (formulár, JSON kľúč, multipart časť) vrátia `method_denied`; mená sa porovnávajú tak, ako ich číta PHP (`rest.route`, `rest route`, `rest[route`, `%5F`). Pole `payment_method` prejde. Cesta s `;` alebo `%3B` (Tomcat/Spring zahodia `;…` parameter a `..;/` vyjde z prefixu) vráti `invalid_path`.
- **Mená parametrov ako ich číta PHP (review 7c10379 H5).** Predtým stačilo `?+_method=DELETE` (`+` je medzera, PHP úvodné medzery zahodí), `?rest_route%00=` (PHP meno utne na NUL) alebo `rest_route` v tele formulára (WordPress smeruje aj podľa `$_POST`), a položka s povoleným len `GET /wp/v2/posts` zmazala články či vytvorila administrátora. Meno sa teraz dekóduje bajt po bajte, utne na NUL, zbaví úvodných medzier, `.` a medzera sú `_`, nespárovaná `[` je `_` (obe správania PHP 7 aj 8). Kontroluje sa query (oddelená `&` aj `;`) a telo podľa `Content-Type`, ktorý sa číta ako v PHP (po prvé `;`, `,` alebo medzeru): formulár a telo bez typu po poliach, multipart po `name=` častí, JSON po kľúčoch najvyššej úrovne. `rest_route` vráti `path_denied`, prepisy metódy `method_denied`, mená začínajúce `_` (`_fields`, `_wpnonce`, `_jsonp` …) `param_denied`, ak ich položka nemá v `allowed_params`. Pri `allowed_params` je v query, formulári a multiparte zakázané každé iné meno (`param_denied`); JSON telo nie sú parametre, kontrolujú sa v ňom len odmietnuté mená. Telo sa overí ešte pred oknom schválenia. Test `tests/test_review7_http_php_params_h5.py` posiela každú prijatú požiadavku na skutočný PHP (`php -S`, preskočí sa, ak `php` nie je nainštalovaný) a overuje, čo PHP videl.
- **JSON telo podľa najvoľnejšieho frameworku (review 7c10379, R7-H).** Kľúče JSON tela sa dekódovali len pri `application/json` a `*+json`. Laravel však číta telo ako JSON, keď `Content-Type` čo i len obsahuje `/json` alebo `+json` (`text/json`, `text/plain; x=/json`), a regulárny výraz pre `_method` v tele minie `"_m\u0065thod"`. Také telo sa kontrolovalo ako formulár a položka s povoleným len POST zmazala. Teraz sa kľúče dekódujú pri každom type, v ktorom je `json`, aj pri každom tele, ktoré je JSON objekt, a navyše prebehne kontrola podľa typu, ako ho číta PHP. Hlboko vnorené telo (`RecursionError`) už broker nezhodí. Test `tests/test_review7_http_json_override.py`.
- **Front controllery (review 1141a20 M-AI2).** Zoznam smerovacích parametrov bol zároveň príliš široký (`q`, `s`, `action` blokovali bežné API) a neúplný. Odmietajú sa teraz aj `p`, `page_id` (WordPress, Craft), `url` (SilverStripe), `eID` (TYPO3), `fc` (PrestaShop), `cl`, `fnc` (OXID), `d` (CodeIgniter), `do` (DokuWiki), `ctl`, `act` a `view` (Joomla), ak ich položka nemá v `allowed_params`. Položka pre API smerované len cestou nastaví `path_routing_only: true` a tieto mená sú pre ňu bežné parametre. Test `tests/test_review9_http_broker_mediums.py`.
- **Ne-ASCII tajomstvo v stavovom riadku a hlavičkách (review 1141a20 M-AI1).** `http.client` číta stavový riadok aj hlavičky ako latin-1 a hlavičku s tajomstvom posiela tiež v latin-1. Redakcia porovnávala UTF-8, takže heslo s diakritikou, ktoré server vrátil v reason phrase alebo v hlavičke, prešlo k agentovi. Text sa pred redakciou vráti na bajty, ktoré server poslal, a redaktor hľadá tajomstvo aj v latin-1 podobe. Test `tests/test_review9_http_broker_mediums.py`.
- **Redirecty sa nikdy nesledujú.** 3xx sa vráti so stavom, s `Location` a s `redirect_not_followed: true`. Proxy z prostredia sa nepoužije.
- **TLS** sa overuje vrátane mena hostiteľa (minimálne TLS 1.2). Chyba certifikátu (`tls_verify_failed`) skončí pred odoslaním požiadavky, takže hlavička s tajomstvom server nedosiahne.
- **Limity:** telo požiadavky aj odpovede najviac 1 MiB (odpoveď sa oreže a dostane `truncated: true`), celé volanie má deadline 30 s (`timeout`).
- **Odpoveď:** `http_status`, `reason`, `body` a len vybrané hlavičky (`Content-Type`, `Content-Length`, `Location`, `ETag`, `Last-Modified`, `Retry-After`, `Link`, `X-WP-Total`, `X-WP-TotalPages`). `Set-Cookie` sa nikdy nevráti. Z tela aj hlavičiek sa zredagujú tajomstvá položky (sekcia 17.6) vrátane každej hodnoty, ktorú používa `auth_header`, aj celej vyskladanej hlavičky. Tajomstvo prerušené orezaním odpovede sa zredaguje tiež. **Redakcia nie je hranica proti AI, ktorá smie meniť kód na cieľovom serveri** (cez toto API, SFTP alebo FTP): vlastný PHP súbor jej vráti hlavičku `Authorization` v ľubovoľnom kódovaní (hex a obrátené poradie sa zachytia, XOR či šifrovanie nie) a s tokenom potom pracuje aj po `ai off`. Pri takej položke ber poverenie ako známe agentovi: daj mu vlastný application password / token s najmenšími právami a po skončení práce alebo po `ai off` ho zruš.
- **Nešifrované HTTP** (`allow_plain_http: true`) pridá ku každému výsledku pole `warning`.
- **Vypínač tesne po nadviazaní spojenia (review 7c10379).** `close_all()` preruší spojenia, o ktorých vie. Spojenie, ktoré sa práve nadväzovalo, ešte nemalo soket, takže rez nastavil len príznak, ktorý po pripojení nikto nečítal, a spojenie zaregistrované až po rezne (medzi kontrolou politiky a pripojením) nepreťal vôbec: DELETE recenzenta dorazil 2 s po `ai off`. HTTP aj FTP manažér teraz po pripojení prečítajú príznak aj vypínač brokera (`cut_check`: `ai off` v pamäti alebo zamknutý trezor) a skončia `cut_off`, FTP ešte pred odoslaním hesla a znova pred samotnou operáciou. SSH už rezy počas pripájania počítal (generácia), `cut_check` dopĺňa rez spred začiatku operácie. Test `tests/test_review7_kill_switch_during_connect.py`. Od review 1141a20 `cut_check` číta aj uložený vypínač (brzda, ktorá došla do trezoru, ale nie k brokeru, sekcia 17.3).
- **FTP prenos po reze (review 7c10379, R7-H).** `close_all()` zatvára riadiace spojenie FTP; dáta však idú druhým soketom a ftplib riadiace spojenie číta až na konci. Server, ktorý dátový kanál po zatvorení riadiaceho nechá bežať, preto stiahnutie po `sezam ai off` dokončil a celý súbor zostal v adresári prenosov, len posledná odpoveď bola `cut_off`. Každý blok (stiahnutie aj nahratie) teraz kontroluje príznak rezu a prerušené stiahnutie sa vyprázdni. Test `tests/test_review7_ftp_cut_with_data_channel.py`.
- **Kill switch:** `close_all()` preruší prebiehajúce požiadavky (`cut_off`) hneď, nie až keď server odpovie. Na Windows `shutdown()` blokované čítanie nezobudí, preto sa handle soketu navyše odpojí (`detach()`) a zatvorí. Odpoveď, ktorá skončí pred `Content-Length`, je chyba (`connection_failed`), nie skrátené telo.

#### MCP nástroj `http_request`

```
sezam mcp-policy Weby/blog --tier 1 --allow-action http
```

Parametre: `path` (položka v trezore), `method`, `request_path` (cesta a query relatívne k `base_url`), voliteľne `body` (reťazec) a `headers` (len povolené hlavičky vyššie).

- **Zdieľané politiky s SSH a FTP nástrojmi:** explicitná akcia `http`, tiery 0/1/2 (tier 2 je pre AI neviditeľný, `not_found`).
- **Schválenie (tier 1)** ukáže skutočný cieľ z položky: `Host`, `Port`, `Request: <METÓDA> <origin z base_url><základná cesta + request_path>` a `Encryption`. Metóda a cesta sa overia voči `allowed_methods` a `allowed_path_prefixes` ešte pred otvorením okna, takže zakázaná požiadavka sa vlastníka ani nepýta. Telo a hlavičky od AI sú v `Details`. Pri `allow_plain_http` okno začína riadkom `WARNING: Plain HTTP …` a každý výsledok vrátane chýb nesie `warning`.
- **Audit** zámeru aj výsledku ako `mcp_http` (v `sezam ai log` ako `http request`, stĺpec čo je `METÓDA URL`, výsledok napr. `ok, HTTP 200`, bajty `in`/`out`, pri nešifrovanom HTTP `(PLAIN HTTP, unencrypted)`). URL sa do auditu zapíše s redakciou tajomstiev položky. Hlavička s tajomstvom ani telo sa do auditu nezapíšu.
- **Kill switch:** `sezam ai off`, brzda z mobilu aj zamknutie trezoru odmietnu každé ďalšie volanie a prerušia aj prebiehajúcu požiadavku (`cut_off`).

---

## 18. Threat model AI brokera (L1/L2/L3)

AI broker (`sezam mcp-serve`, `sezam ssh-agent`) je jediné miesto, cez ktoré AI agent používa tajomstvá z trezoru. Ako silná je táto hranica, závisí od toho, kde broker beží voči agentovi. Agent (napr. Claude Code) má zvyčajne shell a beží ako bežný OS používateľ.

| Úroveň | Nastavenie | Chráni pred | Nechráni pred |
|---|---|---|---|
| **L1** | Broker beží pod tým istým OS používateľom ako agent (predvolené). | Únik hesiel, kľúčov a TOTP seedov do chatu, histórie a logov AI služby. Prompt injection typu „pošli mi heslo“ (politiky položiek, tier 2 je pre AI neviditeľný, tier 1 schvaľuje vlastník). Kill switch `sezam ai off`, brzda z mobilu, audit každej operácie. Na Linuxe navyše core dump, `ptrace` a čítanie `/proc/<pid>/mem` brokera iným procesom toho istého používateľa. | Agentom, ktorý zámerne útočí na lokálny stroj: môže čítať `~/.sezam`, počas TTL CLI session vziať KEK z keyringu, podvrhnúť alebo reštartovať broker s inou konfiguráciou, upraviť inštaláciu Sezamu, odpočúvať zadanie master hesla. Na Windows a macOS si môže čítať aj pamäť bežiaceho brokera. |
| **L2** | Broker beží pod samostatným OS používateľom `sezam-broker` (systemd service / Windows service), trezor `0700` patrí jemu. Sockety `agent.sock` a `mcp.sock` majú skupinu `sezam-ai` a práva `0660`. | Všetko z L1. Agent navyše nevie čítať trezor, keyring ani pamäť brokera a nevie ho reštartovať. Brzdu `ai_off` môže potiahnuť aj skupina `sezam-ai`, zapnutie a odomknutie nie. | Tým, čo AI urobí na serveroch v rámci povoleného prístupu. Rootom na lokálnom stroji. Trvalým kľúčom, ktorý si AI po prihlásení pridá do `authorized_keys` na serveri. |
| **L3** | L2 + krátkodobé SSH certifikáty zo Sezamu a `AuthorizedKeysFile none` pre AI účet na serveri. | Všetko z L2. Navyše odstrihnutie na strane servera: vlastný kľúč AI nefunguje, skopírovaný certifikát vyprší najneskôr o TTL a reaper (`sezam ai-host-setup`) ukončí otvorené session aj odpojené procesy účtu najneskôr o TTL (2 × TTL, ak sa AI znova prihlási držaným certifikátom) plus jeden tik. Nie okamžite: Sezam sa na server nepripája. | Tým, čo AI urobí počas platnosti certifikátu, a zmenami mimo procesov účtu (súbory vo `--web-root`, príkaz cez `--sudo-command`, služby iných používateľov). Rootom na serveri alebo na stroji brokera. |

**Stav implementácie:** L1 je hotová. `prctl(PR_SET_DUMPABLE, 0)` volajú `mcp-serve` aj `ssh-agent` na Linuxe ešte pred otvorením trezoru. Ak volanie zlyhá alebo proces ostane dumpable, príkaz sa vôbec nespustí (fail-closed). Na Windows a macOS ekvivalent nie je, tam L1 pamäť brokera pred procesmi toho istého používateľa nechráni. L2 opisuje sekcia 18.1. L3 je hotová: Sezam ako SSH CA (sekcia 17.4) a príprava servera cez `sezam ai-host-setup` (sekcia 17.5).

### 18.1 L2: broker pod vlastným používateľom

`sezam broker install-service` iba **vypíše** (nič nespúšťa) príkazy a definície služieb. Na Linuxe sú to dve systemd jednotky `sezam-ssh-agent` a `sezam-mcp-serve` pod používateľom `sezam-broker` s domovom `/var/lib/sezam-broker` (`0700`). Na Windows sú to dve naplánované úlohy `schtasks /RU sezam-broker` spúšťané pri štarte. Mená a cesty sa pred vypísaním overia prísnym vzorom, takže sa do príkazov nedá nič podstrčiť. Voľby `--user`, `--group`, `--agent-user` a `--python` výstup prispôsobia.

- Broker beží s `--group sezam-ai`. Socket agenta a MCP socket majú práva `0660` a skupinu `sezam-ai` v adresári `$SEZAM_RUN_DIR` (`/run/sezam-broker`, `0750`, skupina `sezam-ai`). Skupina sa doň dostane, ale nemôže doň zapisovať. Na Windows dostane skupina v DACL pipe právo na pripojenie, čítanie a zápis, nie však `FILE_CREATE_PIPE_INSTANCE`, takže nemôže vytvoriť vlastnú inštanciu pipe.
- Riadiaci endpoint `control-<pid>` (`lock`, `ai_off`, `status`) ostáva len pre vlastníka. Skupina dostane samostatný brzdový endpoint `brake-<pid>`, ktorý prijme len `ai_off` a `status`. Brzdu teda potiahne aj agentov používateľ, zamknúť ani odomknúť broker nevie a `ai_on` nejde nikdy cez žiadny endpoint.
- Agentov používateľ nastaví `SEZAM_RUN_DIR=/run/sezam-broker`. `sezam ai off` a `sezam ai status` fungujú aj bez lokálneho trezoru: oslovia všetky brokery v dosahu a pri každom skúsia najprv riadiaci, potom brzdový endpoint. `ai off` skončí chybou, ak brzdu žiadny broker nepotvrdil.
- **Brzda pod záťažou (review 1141a20 H7).** Slučka `accept` na brzdovom sockete skončila pri prvej `OSError` a systemd jednotka nemala `LimitNOFILE`, takže agent zo skupiny `sezam-ai` otvoril ~1030 pomalých spojení, vlákno brzdy zaniklo a `sezam ai off` ani brzda v GUI už nič nezastavili. Teraz každý endpoint (riadiaci, brzdový, socket agenta, MCP socket aj Windows pipe) beží cez `control.serve_listener`: `accept` po `OSError` (aj `EMFILE`) a po zlyhaní štartu vlákna počká a pokračuje, nikdy neskončí. Spojenia majú globálny limit a limit na peera (uid cez `SO_PEERCRED`, na Windows SID klienta pipe); pri plnom limite brzdový endpoint vyhodí najstaršie spojenie, aby nové `ai_off` prešlo. Každé spojenie má celkový deadline (pomalý klient po bajtoch ho nepredĺži, pipe sa číta cez `PeekNamedPipe`). MCP riadok má limit 8 MiB na sockete, pipe aj stdio (`-32600 Request too large`). Jednotky majú `LimitNOFILE=4096` a `TasksMax=512`. Testy `tests/test_review9_ai_brake_accept.py` a na skutočnom AF_UNIX s nízkym `RLIMIT_NOFILE` `tests/wsl_brake_flood.py` (WSL).
- **Súbežné volania (review a159e97, 1141a20).** MCP socket obsluhuje klientov súbežne a jeden zámok už neradí všetky volania za sebou: volanie, ktoré čaká na schválenie vlastníka alebo na sieť, nezdrží iné. Spoločné spojenie trezoru chráni `VaultDB`: otvorená transakcia patrí vláknu, ktoré ju otvorilo, až do COMMIT/ROLLBACK, takže príkaz iného vlákna neskončí vnútri nej ani sa s ňou nevráti. Testy `tests/test_review8_mcp_concurrent_clients.py`, `tests/test_review9_ai_dispatch_concurrency.py`.
- Služby bežia s `--deny-tier1`, pretože bez plochy nemajú kde ukázať schvaľovacie okno. Položky s tier 1 preto odmietnu.
- Odomyká sa ako `sezam-broker` (`sudo -u sezam-broker -H … unlock`). Session KEK ide do keyringu tohto používateľa. Ak preň nie je k dispozícii keyring backend, broker ostane zamknutý.

**Alternatíva k L2:** broker na inom stroji (domáci server, Raspberry Pi) a socket prepojený cez `ssh -L` / `StreamLocalForward`. Agent potom nemá k trezoru ani k procesu brokera lokálny prístup.

---

## Appendix A: TOTP implementácia

TOTP seed je uložený ako field v `encrypted_data`:

```json
{
    "key": "totp_secret",
    "value": "JBSWY3DPEHPK3PXP",
    "sensitive": true,
    "field_type": "totp"
}
```

- UI: countdown kruhový indikátor (30s perióda)
- Ak zostáva <5s, čaká na nový kód pred kopírovaním
- Import: automatické rozpoznanie z KeePass/Bitwarden
- MCP: `vault_use(path, action="totp_code")` --> broker vygeneruje kód, vráti len 6 číslic (nie seed)

## Appendix B: Import/Export formáty

| Import | Export |
|--------|--------|
| CSV (Sezam formát) | Šifrovaný backup (sezam.db kópia) |
| KeePass `.kdbx` (cez `pykeepass`) | CSV (po explicitnom potvrdení + varovanie) |
| Bitwarden JSON | Bitwarden JSON (pre migráciu) |
| 1Password `.1pux` | |
| Plain text (`name: value` bloky) | |

**CSV formát:**
```csv
folder,name,field_key,field_value,sensitive,tier,entry,field_type
servers/hetzner,SSH Access,host,192.168.1.1,false,0,1,
servers/hetzner,SSH Access,password,tajne123,true,0,1,
servers/hetzner,SSH Access,otp,JBSWY3DPEHPK3PXP,true,0,1,totp
```

Riadky s rovnakým `folder` + `name` tvoria jeden záznam. Voliteľný stĺpec `entry` (export ho čísluje) rozlíši dva záznamy s rovnakým menom v jednom priečinku; bez neho začne ďalší záznam toho mena opakovaný `field_key`.

Aby export + import nič nestratil (review 526419e N1): záznam bez polí je jeden riadok s prázdnym `field_key`; voliteľný stĺpec `field_type` drží typ poľa (`totp`); `tier` je efektívny tier záznamu, lebo tiery priečinkov v súbore nie sú (záznam v priečinku tier 2 sa vráti s tierom 2, nie viditeľný pre AI); `/` oddeľuje priečinky a lomka či spätná lomka v mene priečinka sa píše `\/` a `\\` (`Work\/Prod` je jeden priečinok). Iná spätná lomka sa berie doslova, staré súbory sa čítajú ako predtým. Bitwarden JSON (review d150605 N9): `/` v mene priečinka vnára ako v Bitwardene, preto export píše mená priečinkov rovnako escapované (`Work\/Prod`) a import ich číta tým istým `split_folder_path`; import už nezahodí položku bez polí (záznam bez polí sa tak exportuje). Predtým sa záznam bez polí pri návrate stratil a priečinok `Work/Prod` sa vrátil ako `Prod` v `Work`.

Export (CSV aj Bitwarden, CLI aj desktop) spočíta priečinky a záznamy, ktoré toto zariadenie nevie dešifrovať (chýbajúci DEK, poškodený blob). Ak nejaký chýba, súbor sa zapíše, ale export nehlási úspech: CLI skončí s chybou `… is INCOMPLETE: N folder(s) … and M entr(y/ies) …`, desktop ukáže „Export Incomplete“ s tými počtami (review 526419e N2).

**Konflikty mien pri importe** (`skip` / `overwrite` / `duplicate`): položka sa páruje len so záznamom rovnakého mena, ktorý ešte nevzala iná položka toho istého importu (od najstaršieho). Dve položky „Gmail" v jednom priečinku tak nikdy nesplynú do jednej; opakovaný import ich spáruje každú s jedným existujúcim záznamom.

## Appendix C: Chybové scenáre

| Scenár | Správanie | Správa |
|--------|-----------|--------|
| Zlé master heslo | Delay 2s, max 5/15min | „Nesprávne heslo. Zostáva X pokusov." |
| Zabudnuté heslo (osobné) | Žiadna recovery | „Heslo nie je možné obnoviť." |
| Zabudnuté heslo (firemné) | Break-glass (Shamir) | „Kontaktujte držiteľov recovery kľúčov." |
| Výpadok siete počas push | Idempotentný retry | „Push zlyhal. Skúste znova." |
| Sync konflikt (409) | Pull ponechá obe kópie (`sync_conflicts`), varovanie v CLI aj GUI; `sezam conflicts` vypíše, `sezam conflicts resolve ID --keep local\|server` vyrieši (local = o verziu nad serverom, odíde ďalším pushom; lokálne zmazaný záznam odíde ako tombstone, jeho obsah sa prepečatí o verziu nižšie a ostane obnoviteľný z koša — review 688edcb M1, predtým `CryptoError` s tracebackom). Ponechaná lokálna kópia aj úprava zadržaná re-key rebasom sa prepečatí aktuálnym DEK priečinka, ak bola pod DEK-om, ktorý re-key po odobratí člena vyradil (review 526419e N9; predtým odišla na server pod kľúčom, ktorý odobratý člen má) | „SYNC CONFLICT: N item(s) were changed both here and on another device…" |
| Rollback detected | GUI varovanie | „Server vrátil staršie dáta. Možný útok." |
| Corrupted vault.db | SQLite integrity check | „Vault je poškodený. Obnovte zo zálohy." |
| Share expired | Blob vymazaný | „Odkaz vypršal." |
| Share PIN vyčerpaný | is_locked=1, admin PATCH | „Príliš veľa pokusov. Kontaktujte admina." |
| JWT expired | Auto-refresh / re-login | „Session vypršala. Prihláste sa znova." |
| Full resync (410) | GUI varovanie pred prepísaním | „Máte X nesynchronizovaných zmien." |

---

*Sezam Technická Dokumentácia v1.0 — Referencia pre bezpečnostných audítorov, kryptografov a developerov.*
*Referencuje SEZAM_SPEC_v15_FINAL.md (Version 1.0 FROZEN).*
