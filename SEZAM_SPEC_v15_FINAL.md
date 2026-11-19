# SEZAM — Osobný a firemný šifrovaný trezor

**Version:** 1.0 FROZEN
**Author:** Peter Bezemek / Claude
**Date:** 2026-03-18

---

## 1. Vízia

Šifrovaný trezor na heslá, prístupové údaje, SSH kľúče, API tokeny a citlivé poznámky — s hierarchickým stromom, granulárnym prístupom (osobný / firemný / AI agenti), full-text vyhľadávaním a self-hosted serverom pre zdieľanie v tíme.

### 1.1 Čo to rieši

- **Osobne:** Náhrada plain text súborov. Jeden trezor, jeden master password, bleskový prístup.
- **Firemne:** Nahradenie zdieľania credentials cez WhatsApp. Admin nastaví prístup, kolegovia vidia len to, čo majú, cez web. Server nevidí obsah.
- **Pre AI agentov:** Claude Code a ďalší agenti pristupujú k credentials cez MCP s approval flow. Agent nikdy nedostane raw kľúč — desktop broker vykoná operáciu za neho.

### 1.2 Čo to NIE JE

- Nie je to cloud služba s predplatným
- Nie je to enterprise riešenie pre tisíce ľudí (ale zvládne malý tím 2–100 ľudí)
- **Zabudnuté heslo = strata dát** (by design, žiadny password reset)
- **Strata zariadení ≠ strata dát** — ak vieš heslo, password-based recovery stiahne kľúče zo servera (sekcia 2.2 Cesta B)
- Pre firemný vault existuje org-level break-glass mechanizmus (sekcia 9.4)

---

## 2. Bezpečnostný model

### 2.1 Čo server vidí a čo nevidí

**Content-blind server** — presná definícia:

| Server VIDÍ (plain text) | Server NEVIDÍ (šifrované) |
|--------------------------|---------------------------|
| Počet objektov | Názvy uzlov a entries |
| Typ objektu (node/entry/dek/envelope) | Tier hodnoty |
| Stromová topológia (parent_ref) | Timestamps vytvorenia/zmeny obsahu |
| Kto vlastní ktoré objekty (owner_id) | Hodnoty polí (heslá, kľúče) |
| Sync timestamps (modified_at v vault_objects) | Kľúče polí ("username", "password") |
| Veľkosti šifrovaných blobov | Tagy |
| | Obsah audit záznamov |

> `modified_at` v `vault_objects` je **sync timestamp** (kedy bol objekt naposledy pushnutý), nie timestamp obsahu. Kľúče polí sú vnútri `encrypted_data` blobu — server ich nevidí.

> Starší pojem "zero-knowledge" je nepresný. Server je **content-blind** — nevidí obsah, názvy, tiery ani citlivé metadáta. Vidí topológiu grafu a vzory aktivity, čo je vedomý kompromis pre efektívnu synchronizáciu.

### 2.2 Identita a kľúče — dva páry na usera

Každý používateľ má **dva oddelené kľúčové páry**:

```
Ed25519 — PODPISOVÝ pár (auth + audit)
  - Súkromný: signing_sk (šifrovaný master heslom)
  - Verejný:  signing_pk (uložený na serveri)
  - Použitie: server auth (challenge-response), audit log podpisy, sync integrity

X25519 — ŠIFROVACÍ pár (envelope encryption)
  - Súkromný: encryption_sk (šifrovaný master heslom)
  - Verejný:  encryption_pk (uložený na serveri)
  - Použitie: NaCl crypto_box pre DEK obálky

Uloženie privátnych kľúčov:
  - Lokálne: v sezam.db (šifrované KEK-om, AEAD blob_kind=7)
  - Na serveri: encrypted_keypair v users tabuľke (šifrované KEK-om, AEAD blob_kind=7)
  - .sezam-key súbor: voliteľný offline fallback

Device provisioning (nové zariadenie) — DVE CESTY:

  CESTA A — Provisioning token (existujúce zariadenie je dostupné):
  1. Na existujúcom zariadení: vygeneruj provisioning token (128-bit, 10min, one-time)
  2. Token pošli na nové zariadenie (QR, správa)
  3. Nové zariadenie: POST /api/auth/provision {token, username}
     → Server vráti encrypted_keypair + salt
  4. heslo → Argon2id(heslo, salt) → KEK → dešifruj keypair → ready

  CESTA B — Password-based recovery (stratené VŠETKY zariadenia, žiadny .sezam-key):
  1. Klient: GET /api/meta?username=X → dostane argon2_salt (verejný, per-user)
  2. Klient: jeden beh Argon2id(heslo, argon2_salt, hash_len=64) → 64B
             KEK = raw[0:32], auth_proof = raw[32:64]  (VOĽBA B — wide-output split)
             → auth_proof aj KEK z toho istého behu; dve nezávislé 32B polovice
             → NErobí sa druhý Argon2id (šetrí ~256MB/pol s a DoS vektor na serveri)
  3. Klient: POST /api/auth/recover {username, auth_proof}
  4. Server: dopočíta HMAC-SHA256(verify_salt, auth_proof) a porovná s auth_proof_hash
     → Klient NIKDY neposiela auth_proof_hash, len auth_proof
     → Server si hash dopočíta sám (verify_salt je server-side only)
     → Ak match: vráti encrypted_keypair + argon2_salt
  5. Klient: KEK = raw[0:32] (už dopočítané v kroku 2) → dešifruj keypair → ready
  → Umožňuje recovery bez starého zariadenia aj bez .sezam-key
  → POZN: auth_salt stĺpec je pre VOĽBU B nepoužitý (legacy). Všetci klienti
    (desktop/web/mobil) odvodzujú auth_proof z argon2_salt — cross-client konzistentné.

  CESTA C — Offline fallback (.sezam-key súbor):
  1. Import .sezam-key → dešifruj KEK-om → ready
  → Bez servera, bez siete
```

**Prečo dva páry:** X25519 je Diffie-Hellman key agreement — nedá sa ním podpisovať. Ed25519 je podpisová schéma — nedá sa ňou šifrovať. Libsodium/pynacl podporuje konverziu Ed25519 → X25519 (`crypto_sign_ed25519_sk_to_curve25519`), ale pre bezpečnosť a čistotu návrhu udržiavame **oddelené páry** — žiadny cross-protocol risk.

**Fingerprint:** `SHA-256(signing_pk || encryption_pk)`. GUI zobrazuje dva režimy:
- **Vizuálny** (denné použitie): identicon/wavatar generovaný z fingerprint hash — drastická vizuálna zmena pri MITM
- **Slovný** (onboarding TOFU): 4 BIP39-style slová z fingerprint — napr. "Kôň Jablko Skala Modrá". Pokrýva **44 bitov** z 256-bit fingerprint (4×11 bit z 2048-word listu). Pre TOFU overenie dostatočné (MITM by musel trafiť rovnaké 4 slová = 1:17.6 bilióna). **Plná verifikácia vyžaduje hex**
- **Plný hex** (technický): celých 64 hex znakov (256 bitov) — pre plnú verifikáciu

### 2.3 KEK/DEK kľúčová hierarchia

```
Master Password (UTF-8)
        │
        ▼
   Argon2id(password, salt, time=3, mem=256MB, par=4)
        │
        ▼
   Root KEK (Key Encryption Key) — 256-bit
        │
        ├── Root DEK (scope='root')  ── šifruje encrypted_meta root uzla a top-level uzlov
        ├── Folder DEK "servers"     ── šifruje encrypted_meta + encrypted_data entries v servers/
        ├── Folder DEK "financial"   ── šifruje encrypted_meta + encrypted_data entries v financial/
        ├── Folder DEK "clients"     ── šifruje encrypted_meta + encrypted_data entries v clients/
        ├── Audit DEK (scope='audit')── šifruje audit log detaily (ODDELENÝ od content DEK-ov)
        └── ...
```

**Pravidlá:**
- **Root KEK** odomkne jednotlivé DEK-y. Nikdy nešifruje dáta priamo.
- **Root DEK** (`scope='root'`) — šifruje `encrypted_meta` root uzla a top-level folderov. Zabalený priamo KEK-om. Web user dostane obálku pre Root DEK, aby videl top-level štruktúru.
- **Granularita DEK: per-folder.** `encrypted_meta` uzla je šifrovaný DEK-om jeho rodičovského folderu. Uzly priamo pod rootom sú šifrované Root DEK-om. Web user dešifruje len uzly, ku ktorým má obálku.
- **Tier 2 entries** majú **samostatný DEK**, ku ktorému MCP agent fyzicky nemá prístup.
- **Audit DEK** — náhodne vygenerovaný, zabalený KEK-om, **verzovaný nezávisle** od master password lifecycle. Zmena master hesla neovplyvní audit chain.
- Kľúčový materiál v Pythone: výhradne `bytearray` s explicitným `key[:] = b'\x00' * len(key)` po zámku. **Best-effort** — Python GC limitácia dokumentovaná, nie záruka.

### 2.4 Envelope Encryption (multi-user)

Pridelenie prístupu ku zložke:
```
Folder DEK pre "clients/auto-moto"
    ├── zabalený NaCl crypto_box(admin_encryption_pk, admin_encryption_sk → Jankovi) → obálka
    └── poznámka: crypto_box je authenticated — príjemca vie, kto obálku vytvoril
```

> Používame `crypto_box` (authenticated), nie `crypto_box_seal` (anonymný). Admin je vždy odosielateľ obálky — autenticita je dôležitá.

**Revokácia prístupu — povinný re-key:**
1. Admin odvolá Jankovi prístup
2. Systém vygeneruje **nový DEK** pre danú vetvu
3. Všetky entries sa re-zašifrujú novým DEK-om (**jedna SQLite transakcia**)
4. Nové obálky sa vytvoria pre zostávajúcich používateľov
5. Starý DEK sa archivuje v `dek_archive` — **zabalený NOVÝM DEK-om** (nie KEK-om!). Ktokoľvek s obálkou pre nový DEK vie dešifrovať starý DEK a tým aj históriu. Revokovaný user nemá obálku pre nový DEK → nemá prístup k chain-u.

**Public key autentičnosť — TOFU (Trust On First Use):**
- Pri pridávaní kolegu admin overí fingerprint (zobrazený v GUI)
- Server nemôže podmeniť verejný kľúč bez toho, aby admin videl zmenu fingerpringu
- GUI zobrazí varovanie pri zmene kľúča (ako SSH `known_hosts`)
- **Lokálny key cache:** Klient ukladá `{user_id: (signing_pk, encryption_pk, fingerprint)}` lokálne. Pri pull overuje, že server kľúče sa nezmenili. Ak sa zmenili → GUI varovanie (MITM detection). Cache eliminuje závislosť na serveri pre crypto_box dešifrovanie obálok

### 2.5 Šifrovanie — presná špecifikácia

| Parameter | Hodnota | Poznámka |
|-----------|---------|----------|
| **KDF** | Argon2id | salt=16B, konfigurovateľné params, default: time=3, mem=256MB, par=4 |
| **Symetrické (content)** | **`crypto_aead_xchacha20poly1305_ietf`** (libsodium) | nonce=24B, tag=16B, **natívna AAD podpora** |
| **Symetrické (obálky)** | NaCl `crypto_box` | X25519 + XSalsa20-Poly1305 (authenticated key wrapping) |
| **Podpisy** | Ed25519 | Server auth, audit log, sync integrity |
| **Nonce** | **Náhodný: `os.urandom(24)`** | Uložený v envelope. 24B = kolízia nemožná |
| **AAD** | Kanonická definícia v sekcii 2.6 | Natívny AEAD parameter — kryptograficky viazané |

> **Prečo `crypto_aead_xchacha20poly1305_ietf`:** XChaCha20-Poly1305 s **natívnou AAD podporou**. NaCl `secretbox` (v4/v5-draft) AAD nepodporuje — AAD bol neimplementovateľný. Libsodium AEAD túto limitáciu odstráni. Nonce je náhodný 24B (uložený v envelope) — XChaCha20 navrhnutý pre random nonce.
>
> **AAD (Additional Authenticated Data):** Kryptograficky viažu ciphertext k jeho kontextu. Zmena AAD zneplatní Poly1305 tag — primitív to kontroluje natívne, nie custom kódom. `blob_kind` = `1=node_meta` | `2=entry_meta` | `3=entry_data` | `4=history_snapshot` | `5=audit_details` | `6=dek_wrap` | `7=keypair_wrap`. Zabraňuje swap útoku.
>
> **Obálky (crypto_box):** Pre key wrapping (DEK obálky pre userov) zostáva NaCl `crypto_box` — AAD tu nie je potrebné (obálka je viazaná na príjemcu cez jeho pubkey).

### 2.6 Ciphertext Envelope Format

Každý šifrovaný blob má štandardizovaný formát:

```
┌──────────────────────────────────────────────────┐
│ HEADER (plain text, ale autentifikovaný cez AAD)  │
│   alg: u8              (1 = xchacha20poly1305_ietf)│
│   schema_version: u8                               │
│   blob_kind: u8        (1–7, viď 2.5)              │
│   dek_id: 26 bytes     (ULID)                      │
│   nonce: 24 bytes      (os.urandom(24))             │
├──────────────────────────────────────────────────┤
│ AEAD OUTPUT (libsodium vracia ako jeden blob)      │
│   ciphertext: variable                             │
│   tag: 16 bytes (Poly1305, posledných 16B outputu) │
│   (plaintext pred šifrovaním = padding_len:u16     │
│    + padding_bytes + actual_data)                   │
└──────────────────────────────────────────────────┘
```

**Šifrovanie:**
```python
aad = alg(1B) || schema_version(1B) || blob_kind(1B) || dek_id(26B) || object_id(26B) || u32be(version)(4B)
# Všetky polia sú fixed-length → žiadna ambiguita pri konkatenácii. Celkom 59 bajtov.
padded_plaintext = u16be(padding_len) + padding_bytes + actual_data
ciphertext_with_tag = crypto_aead_xchacha20poly1305_ietf_encrypt(padded_plaintext, aad, nonce, dek)
```

**Dešifrovanie:**
```python
padded_plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext_with_tag, aad, nonce, dek)
# Ak AAD nesedí → tag verification FAILS → swap attack detected
padding_len = u16be(padded_plaintext[:2])
actual_data = padded_plaintext[2 + padding_len:]
```

- `tag` nie je fyzicky separovaný — libsodium ho pridáva na koniec ciphertextu automaticky
- Header je plain text ale **autentifikovaný** cez AAD — zmena headera zneplatní tag
- **`object_id` v AAD:** Pri šifrovaní = ID záznamu (nodes.id, entries.id, dek_archive.id). Pri dešifrovaní sa berie z **primárneho kľúča** záznamu v lokálnej SQLite tabuľke (nie z envelope — nie je tam uložený). Implementátor musí `object_id` vždy poskytnúť z DB kontextu
- **`version` v AAD:** Berie sa z `version` stĺpca záznamu v SQLite (nie z envelope)
- Padding: min. 32B, zaokrúhlené na mocninu 2, fill = `os.urandom()` (random, nie zero), `padding_length` v plaintexte (pred šifrovaním)

### 2.7 Server autentifikácia — Ed25519 challenge-response

```
1. Klient → Server: username
2. Server → Klient: challenge = random(32B) + server_timestamp
3. Klient: signature = Ed25519_sign(signing_sk, challenge)
4. Klient → Server: signature
5. Server: Ed25519_verify(signing_pk, challenge, signature)
6. Server: overí že server_timestamp je max 30s starý (replay protection)
7. Server: označí challenge ako "spent" (nonce tracking, prevent replay)
8. Server → Klient: JWT (alg=EdDSA, expiry=1h)
```

**JWT:**
- **Server signing key:** Ed25519 kľúčový pár generovaný pri prvom štarte servera, uložený v server config (súbor alebo env var). Nikdy v DB.
- **Algoritmus:** `alg=EdDSA, crv=Ed25519`
- **Expiry:** 1h, refresh cez podpísaný refresh challenge
- **Invalidácia:** `revoked_tokens` tabuľka pre okamžité zrušenie pri odhlásení/revokácii
- **Rotácia:** Server key sa rotuje manuálne (admin restart). Staré JWT-čka s predchádzajúcim kľúčom sú automaticky neplatné.

### 2.8 Identity key rotation

Ak je keypair kompromitovaný (napr. únik signing_sk):

> **Zmena (lockout review #11, idea #11):** `PATCH /api/users/:id/rotate-keys` vracia 410 — menil verejné kľúče bez `encrypted_keypair`. Rotácia ide namiesto toho v `key_rotation.identity` pushu, ktorý posúva `key_epoch` (`sezam rotate-identity`); nové verejné kľúče, `encrypted_keypair`, prebalenie DEK-ov, archív starého kľúča s certifikátom (podpis nového kľúča) a autorizácia starým kľúčom sú v jednej transakcii. Podrobne: TECHNICKA_DOKUMENTACIA 10.2. Kroky nižšie sú pôvodný návrh.

```
1. User vygeneruje nový Ed25519 + X25519 keypair (na existujúcom zariadení alebo cez re-onboarding)
2. Upload nových verejných kľúčov: PATCH /api/users/:id/rotate-keys {new_signing_pk, new_encryption_pk}
   → Server aktualizuje signing_pk, encryption_pk, key_fingerprint IN-PLACE (rovnaký users.id, rovnaký username)
   → Starý keypair sa archivuje server-side (pre overenie starých podpisov v audit logu)
3. Admin overí nový fingerprint v GUI (TOFU varovanie: "Kľúče sa zmenili")
4. Admin re-vytvorí obálky s novým encryption_pk → pushne
5. Staré obálky (s kompromitovaným kľúčom) sú tombstone-ované → trigger re-key
6. User upload novú encrypted_keypair zabalenú KEK-om
```

**Žiadne DELETE + re-CREATE** — `users.username` je UNIQUE, rotation je in-place update.
Toto je manuálny incident response. Pre pravidelný rotation je rovnaký flow.

### 2.9 Bezpečnostné záruky

1. **Content-blind server** — server nevidí obsah, názvy, tiery ani hodnoty. Vidí topológiu a vzory aktivity.
2. **Žiadny plain text na disku** — nikdy, ani dočasné súbory, ani search index
3. **Memory hygiene** — best-effort zeroize (`bytearray` + explicit wipe). Dokumentovaná Python/JS limitácia
4. **Atomic writes** — write to tmp → rename
5. **Clipboard discipline** — auto-clear po 15s. UI varovanie o clipboard managers
6. **Fail closed** — pri chybe → zamkni, nič neodhaľ
7. **Tamper-evident audit** — Ed25519 podpisy klientov, Merkle DAG pre offline fork handling
8. **No telemetry**
9. **No personal recovery by design** — org break-glass existuje pre firemný vault (sekcia 9.4)
10. **Web UI CSP** — povinné hlavičky, SRI, žiadne inline skripty
11. **Padding** — zapnutý defaultne (bloby paddované na najbližšiu mocninu 2). Vypnutie = opt-in s varovaním

### 2.10 Čo sa stane ak je admin zariadenie kompromitované

| Dopad | Vysvetlenie |
|-------|-------------|
| Všetky entries čitateľné | Admin má KEK → všetky DEK-y → celý vault vrátane Tier 2 |
| Všetky entries zapisovateľné | Admin je exempt z write_acl |
| Obálky manipulovateľné | Admin vytvára/maže obálky |
| Audit log podvrhnuteľný | Admin má signing_sk — vie vytvoriť platné záznamy |
| Recovery rozbitá | Admin vie zmeniť heslo + re-wrap recovery |

**Mitigácia:** Toto je vlastnosť zvoleného single-admin modelu (rovnaké ako KeePass, Bitwarden self-hosted). Pre vyšší trust model by bol potrebný multi-admin quorum (n-of-m schválenie pre kritické operácie) — mimo scope tejto verzie.

**Tier 2 a MCP ochrana:** Tier 2 separátny DEK chráni proti **MCP agentom a bežným userom**, nie proti admin compromise. Toto je zámer, nie bug.

**Čo NIE JE ohrozené pri admin compromise:**

| Zostáva bezpečné | Prečo |
|-------------------|-------|
| Server stále nevidí plaintext | Server nemá KEK — admin compromise ≠ server compromise |
| Iní klienti vedia detekovať podvrhnuté objekty | Ed25519 podpis na každom objekte — admin podpíše svojím kľúčom, nie cudzím |
| Share linky iných userov | Share key je v URL fragmente, admin ho nemá (ak link nevidel) |
| Audit log integrity (iných userov) | Záznamy iných userov sú podpísané ich kľúčmi, admin ich nevie sfalšovať |

---

## 3. Prístupový model — Tiery + Capabilities

### 3.1 Access Tiers (UX vrstva)

| Tier | Ľudský prístup | AI prístup |
|------|-----------------|------------|
| **0** Voľný | Plný po odomknutí | Broker vykoná operáciu bez schválenia |
| **1** Na požiadanie | Plný po odomknutí | Broker vykoná operáciu po schválení |
| **2** Tajný | Plný po odomknutí | Nevidí ani existenciu (separátny DEK) |

### 3.2 Capability Matrix (pod tiermi)

Tiery sú skratka. Pod nimi je capability model:

| Capability | Tier 0 | Tier 1 | Tier 2 | Popis |
|------------|--------|--------|--------|-------|
| `list_exists` | auto | auto | **deny** | Vidieť že entry existuje |
| `read_meta` | auto | auto | **deny** | Vidieť názov, kľúče polí |
| `read_secret` | **opt-in** | **opt-in** | **deny** | Vidieť plaintext — vyžaduje `"ai_read_secret": true` v `encrypted_meta` (per-folder/entry, nastavuje admin) |
| `use_secret` | auto | **approval** | **deny** | Broker použije secret (agent nevidí) — DEFAULT pre AI |
| `rotate` | deny | deny | deny | Zmeniť/rotovať heslo |
| `share` | deny | deny | deny | Vytvoriť share link |
| `approve_ai` | n/a | n/a | n/a | Schváliť AI request |

- `auto` = bez ľudského zásahu
- `approval` = GUI notifikácia → admin schváli/zamietne
- `deny` = kryptograficky nemožné (žiadny DEK)
- `rotate`, `share`, `approve_ai` = len pre ľudských používateľov (nikdy MCP)

**Rozšíriteľnosť:** Nové capabilities sa pridávajú do matrice bez zmeny tier systému. Tier je len preset — `tier: 0` = `{list: auto, read_meta: auto, read_secret: auto, use: auto}`.

### 3.3 Dedenie

- Každý uzol/entry má `tier` vo svojom `encrypted_meta` blobe
- Ak nie je nastavený, dedí od najbližšieho rodiča
- Root default: `tier: 1`

### 3.4 Multi-user prístup

- Admin vidí celý strom — má obálky pre všetky DEK-y
- Kolega vidí len vetvy, ku ktorým má obálku
- **Pull model:** Server pošle klientovi **všetky vault_objects** (celý vault). Klient si lokálne filtruje podľa toho, ktoré DEK-y vie odomknúť cez svoje obálky. Objekty bez príslušného DEK-u sú nepoužiteľné šifrované bloby.
  - **Výhoda:** Skutočne content-blind server — server nemusí vedieť, kto k čomu má prístup (okrem write_acl)
  - **Bandwidth:** Pre 2–15 userov s tisíckami entries = stovky KB, zanedbateľné
  - **Dokumentovaný kompromis — metadata leak medzi usermi:** Každý klient dostane celý vault_objects set a vie z neho vyčítať počet objektov, veľkosti blobov, vzory zmien a rast vetiev iných používateľov. Pre malý firemný tím (kde ľudia vedia, že firma má servery a klientov) je to prijateľné. Pre scenáre vyžadujúce izoláciu medzi usermi by bol potrebný filtered-pull mód (Phase 4+)
- **Web je read-write pre vault content** (entries, folders) — nie len read-only. Kolega s folder `write_acl` môže cez web vytvárať/editovať/mazať. Identity/auth operácie (onboarding, key upload, password recovery) sú read-write aj cez web.

#### Ownership ACL (`write_policy`) — kto smie editovať objekt

Každý `vault_object` (node/entry) nesie `write_policy`:

- **`owner_only`** (DEFAULT): editovať smie **len tvorca** (`owner_id`) alebo admin. Ostatní — aj keď majú folder `write_acl` a vedia objekt dešifrovať — majú k nemu **read-only**. Toto je základný režim: kto to zadal, ten to opraví; ostatní len čítajú.
- **`shared`**: editovať smie **ktokoľvek s folder `write_acl`** (kolaboratívny objekt).

Presadenie:
- **Serverovo** v `POST /api/sync` (nezávislé od DEK/obálky): pri update existujúceho objektu server odmietne (`not owner (read-only)`) ak žiadateľ nie je owner ani admin a `write_policy != 'shared'`.
- **Policy zmena:** len owner/admin smie zmeniť `write_policy`. Desktop pole neposiela, takže server existujúcu policy **zachová** (`None` = zachovať; pri create default `owner_only`). Web a mobil posielajú explicitnú policy pri create/update; pri bežnom update zachovajú hodnotu prijatú cez pull, kým ju owner/admin nezmení.
- **Pull** vracia `owner_id` + `write_policy`, aby klienti vedeli zobraziť read-only stav.
- **Admin** obchádza policy (edituje všetko). Desktop je admin klient.
- **UI (web/mobil):** entry detail ukáže „Read-only" stav a skryje Edit/Delete pre neownera pri `owner_only`; entry modal má „Shared" prepínač a klient posiela zvolenú policy. Server nezávisle presadí, že policy smie zmeniť len owner/admin. Desktop je admin klient, policy UI nemá a pole neposiela.
- Uložené v `vault_objects.write_policy VARCHAR(16)` (migrácia pre existujúce DB, default `'owner_only'`).

### 3.5 `sensitive` príznak

Kontroluje **len UI maskovanie** (hviezdičky vs. viditeľný text), nie úroveň šifrovania. Všetky hodnoty sú vždy šifrované rovnako.

---

## 4. Dátový model

### 4.1 Lokálne: SQLite (`sezam.db`)

```sql
-- ============================================================
-- STROM A ZÁZNAMY (všetky obsahové stĺpce sú ciphertext envelope)
-- ============================================================

CREATE TABLE nodes (
    id              TEXT PRIMARY KEY,   -- ULID
    parent_id       TEXT REFERENCES nodes(id),
    encrypted_meta  BLOB NOT NULL,      -- envelope: {name, tier, sync_flag, created_at, modified_at}
    dek_id          TEXT NOT NULL REFERENCES deks(id),
    version         INTEGER NOT NULL DEFAULT 1,  -- per-object version (increments on edit)
    is_dirty        INTEGER NOT NULL DEFAULT 1,  -- 1 = needs push to server
    is_deleted      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_nodes_parent ON nodes(parent_id);
CREATE INDEX idx_nodes_dek ON nodes(dek_id);

CREATE TABLE entries (
    id              TEXT PRIMARY KEY,   -- ULID
    node_id         TEXT NOT NULL REFERENCES nodes(id),
    encrypted_meta  BLOB NOT NULL,      -- envelope: {name, tier, created_at, modified_at}
    encrypted_data  BLOB NOT NULL,      -- envelope: {fields: [{key, value, sensitive, sort_order}]}
    dek_id          TEXT REFERENCES deks(id),  -- NULL = dedí od node.dek_id (envelope.dek_id = node.dek_id)
    version         INTEGER NOT NULL DEFAULT 1,
    is_dirty        INTEGER NOT NULL DEFAULT 1,
    is_deleted      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_entries_node ON entries(node_id);

-- ============================================================
-- KĽÚČE
-- ============================================================

CREATE TABLE deks (
    id              TEXT PRIMARY KEY,   -- ULID
    node_id         TEXT REFERENCES nodes(id),
    scope           TEXT NOT NULL CHECK(scope IN ('root', 'folder', 'tier2', 'share', 'audit')),
    encrypted_dek   BLOB NOT NULL,     -- DEK VŽDY zabalený KEK-om (aj v multi-user). access_envelopes sú DODATOČNÉ prístupové cesty pre kolegov. KEK-wrap je primárny — recovery a change-password pracujú cez neho
    version         INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_deks_node ON deks(node_id);

-- Archív starých DEK-ov (pre dešifrovanie entry_history po re-key)
-- Starý DEK je zabalený NOVÝM DEK-om (chain wrapping) — nie KEK-om.
-- Ktokoľvek s prístupom k aktuálnemu DEK vie spätne dešifrovať celý chain.
-- GC PRAVIDLO: dek_archive záznam sa maže LEN ak sa mažú aj VŠETKY príslušné entry_history záznamy.
-- Nikdy nemaž dek_archive bez mazania history — inak sa history stane nedešifrovateľná.
CREATE TABLE dek_archive (
    id              TEXT PRIMARY KEY,
    replaced_by     TEXT NOT NULL REFERENCES deks(id),  -- nový DEK ktorý ho nahradil
    encrypted_dek   BLOB NOT NULL,      -- starý DEK zabalený novým DEK-om (AEAD, blob_kind=6='dek_wrap', AAD viažuci na replaced_by)
    archived_at     INTEGER NOT NULL,   -- Unix ms
    version         INTEGER NOT NULL DEFAULT 1  -- vždy 1 (write-once), potrebné pre AAD
);

CREATE TABLE access_envelopes (
    id              TEXT PRIMARY KEY,
    dek_id          TEXT NOT NULL REFERENCES deks(id),
    user_id         TEXT NOT NULL,       -- komu patrí obálka (príjemca)
    created_by      TEXT NOT NULL,       -- kto obálku vytvoril (odosielateľ) — potrebné pre crypto_box dešifrovanie
    access_level    TEXT NOT NULL DEFAULT 'write' CHECK(access_level IN ('read', 'write')),
    encrypted_dek   BLOB NOT NULL       -- DEK zabalený NaCl crypto_box(sender_sk, recipient_pk)
);
CREATE INDEX idx_envelopes_dek ON access_envelopes(dek_id);
CREATE INDEX idx_envelopes_user ON access_envelopes(user_id);

-- ============================================================
-- HISTÓRIA
-- ============================================================

CREATE TABLE entry_history (
    id              TEXT PRIMARY KEY,
    entry_id        TEXT NOT NULL REFERENCES entries(id),
    encrypted_snapshot BLOB NOT NULL,   -- envelope (šifrovaný DEK-om platným v čase zmeny)
    dek_id          TEXT NOT NULL,      -- referencia na DEK (môže byť v dek_archive)
    changed_at      INTEGER NOT NULL
);
CREATE INDEX idx_history_entry ON entry_history(entry_id);

-- ============================================================
-- AUDIT LOG (Merkle DAG + Ed25519 podpisy)
-- ============================================================

CREATE TABLE audit_log (
    id              TEXT PRIMARY KEY,       -- ULID
    parent_ids      TEXT NOT NULL,          -- JSON array ULID-ov predchádzajúcich leafov (DAG, nie lineárny chain)
    actor_id        TEXT NOT NULL,          -- user ULID
    action          TEXT NOT NULL,          -- 'read' | 'write' | 'delete' | 'approve' | 'deny' | 'share' | 'rekey'
    encrypted_details BLOB,                -- envelope (šifrovaný Audit DEK-om): {target_path, context}
    timestamp       INTEGER NOT NULL,       -- Unix ms
    signature       BLOB NOT NULL          -- Ed25519_sign(actor_signing_sk, canonical_signed_data)
    -- canonical_signed_data (všetky polia fixed-length alebo length-prefixed):
    --   id(26B) || actor_id(26B) || u16be(len(parent_ids_json)) || parent_ids_json
    --   || u16be(len(action)) || action || timestamp_u64be(8B) || SHA-256(encrypted_details)(32B)
    -- parent_ids_json = ULIDy sorted ASC, JSON bez whitespace: '["01ABC","01DEF"]'
    -- Všetky variabilné polia sú length-prefixed → žiadna konkatenačná ambiguita
);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_actor ON audit_log(actor_id);

-- Materializované DAG hrany pre rýchle rekurzívne dotazy (WITH RECURSIVE)
-- Naplní sa pri INSERT do audit_log z JSON parent_ids
CREATE TABLE audit_dag_edges (
    child_id        TEXT NOT NULL REFERENCES audit_log(id),
    parent_id       TEXT NOT NULL REFERENCES audit_log(id),
    PRIMARY KEY (child_id, parent_id)
);
CREATE INDEX idx_dag_parent ON audit_dag_edges(parent_id);

-- ============================================================
-- LOKÁLNY KEY CACHE (TOFU — Trust On First Use)
-- ============================================================

CREATE TABLE known_keys (
    user_id         TEXT PRIMARY KEY,
    signing_pk      BLOB NOT NULL,
    encryption_pk   BLOB NOT NULL,
    fingerprint     TEXT NOT NULL,       -- SHA-256(signing_pk || encryption_pk), plný 64 hex
    first_seen      INTEGER NOT NULL,    -- Unix ms
    last_verified   INTEGER NOT NULL     -- Unix ms — kedy admin naposledy overil fingerprint
);
-- Pri pull: porovnaj server kľúče s cache → ak nesúhlasia → GUI varovanie (MITM detection)

-- ============================================================
-- METADÁTA
-- ============================================================

CREATE TABLE vault_meta (
    key             TEXT PRIMARY KEY,
    value           TEXT
);
-- Kľúče: schema_version, argon2_params (verejné — potrebné na unlock),
--         vault_id, sync_checkpoint (encrypted), last_known_commit_seq,
--         org_recovery_pk (verejný kľúč org recovery — pre re-wrap pri KEK rotácii),
--         key_epoch (globálny counter zmien hesla/KEK — inkrementuje sa pri change-password)
-- POZNÁMKA: argon2_params sú zámerne v plain texte — sú potrebné pred odomknutím.
-- Approval state NIE JE v vault_meta — je len in-memory (sekcia 7.3).
```

### 4.2 Server: MariaDB (content-blind blob store)

```sql
CREATE TABLE users (
    id              VARCHAR(26) PRIMARY KEY,
    username        VARCHAR(255) UNIQUE NOT NULL,
    signing_pk      BLOB NOT NULL,              -- Ed25519 verejný kľúč
    encryption_pk   BLOB NOT NULL,              -- X25519 verejný kľúč
    key_fingerprint VARCHAR(64) NOT NULL,        -- SHA-256(signing_pk || encryption_pk), plný hex
    status          VARCHAR(10) NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'active', 'revoked')),
    is_admin        TINYINT(1) NOT NULL DEFAULT 0,
    encrypted_keypair BLOB,             -- signing_sk + encryption_sk zabalené KEK-om (AEAD blob_kind=7)
    argon2_salt     BLOB,               -- 16B encryption salt (verejný — pre KDF → KEK aj auth_proof, VOĽBA B)
    auth_salt       BLOB,               -- 16B (LEGACY, VOĽBA B nepoužíva — auth_proof sa berie z argon2_salt splitu)
    verify_salt     BLOB,               -- 32B server-generated secret pre HMAC (nie verejný)
    auth_proof_hash VARCHAR(255),       -- HMAC-SHA256(verify_salt, auth_proof) — NIE Argon2id
                                        -- auth_proof = Argon2id(heslo, argon2_salt, 64B)[32:64] (VOĽBA B, wide-output split)
                                        -- Druhý Argon2id by bol zbytočne drahý a DoS vektor pre server
                                        -- argon2_salt je verejný (klient ho získa cez GET /api/meta?username=X)
                                        -- verify_salt je server-side only — klient ho nikdy nevidí
                                        -- Rate limit: max 3 pokusy/h per username, 10 celkových → endpoint ZAMKNUTÝ (admin odomkne)
    recovery_locked TINYINT(1) NOT NULL DEFAULT 0,  -- locked po 10 zlyhaniach recovery
    created_at      BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE vault_objects (
    id              VARCHAR(26) PRIMARY KEY,
    object_type     VARCHAR(20) NOT NULL,       -- 'node','entry','dek','dek_archive','envelope','history','audit'
    payload         LONGBLOB NOT NULL,
    owner_id        VARCHAR(26) NOT NULL REFERENCES users(id),
    target_user_id  VARCHAR(26) REFERENCES users(id) ON DELETE CASCADE, -- pre envelope: komu patrí
    parent_ref      VARCHAR(26),
    version         INTEGER NOT NULL DEFAULT 1, -- per-object edit counter
    commit_seq      BIGINT,                     -- SERVER-ASSIGNED monotónny counter (NULL = ešte nepushnuté)
    is_deleted      TINYINT(1) NOT NULL DEFAULT 0,
    payload_hash    VARCHAR(64) NOT NULL,       -- SHA-256(payload) pre idempotentný push a equivocation detection
    client_signature BLOB,                     -- Ed25519_sign — kanonická forma viď sync protokol 8.2 (id + object_type + parent_ref + target_user_id + is_deleted + version + payload_hash)
    modified_at     BIGINT NOT NULL,            -- sync timestamp (kedy pushnuté)
    INDEX idx_vo_type (object_type),
    INDEX idx_vo_owner (owner_id),
    INDEX idx_vo_target (target_user_id),
    INDEX idx_vo_parent (parent_ref),
    INDEX idx_vo_modified (modified_at),
    INDEX idx_vo_commit_seq (commit_seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE shared_links (
    id              VARCHAR(43) PRIMARY KEY,    -- 256-bit random, base64url (nie ULID!)
    encrypted_blob  LONGBLOB NOT NULL,
    created_by      VARCHAR(26) NOT NULL REFERENCES users(id),
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    max_views       INTEGER NOT NULL DEFAULT 1,
    view_count      INTEGER NOT NULL DEFAULT 0,
    pin_hash        VARCHAR(255),               -- Argon2id, len online brute-force ochrana
    pin_attempts    INTEGER NOT NULL DEFAULT 0,
    is_locked       TINYINT(1) NOT NULL DEFAULT 0,  -- locked po 10 PIN zlyhaniach, admin môže odomknúť
    INDEX idx_shares_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Po expirácii: riadok sa VYMAŽE. Cron job každú hodinu + endpoint VŽDY kontroluje expires_at
-- Share consumption je ATÓMOVÁ: SELECT FOR UPDATE → check expiry + views + PIN + lock → increment → return blob
-- Žiadne race conditions pri súbežných requestoch

CREATE TABLE share_views (
    id              VARCHAR(26) PRIMARY KEY,
    share_id        VARCHAR(43) NOT NULL REFERENCES shared_links(id) ON DELETE CASCADE,
    viewed_at       BIGINT NOT NULL,
    viewer_ip_hmac  VARCHAR(64),        -- HMAC(server_secret, IP) — nie plain hash (dictionary resistant)
    user_agent_hmac VARCHAR(64)         -- HMAC(server_secret, UA)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE server_audit (
    id              VARCHAR(26) PRIMARY KEY,
    user_id         VARCHAR(26) NOT NULL REFERENCES users(id),
    action          VARCHAR(50) NOT NULL,       -- 'sync_push' | 'sync_pull' | 'login' | 'share_create' | 'share_view'
    timestamp       BIGINT NOT NULL,
    request_hash    VARCHAR(64),                -- SHA-256(request body) — čo presne klient poslal
    commit_seq_range VARCHAR(100),              -- "from:to" commit_seq range (pre push audit)
    client_signature BLOB NOT NULL,             -- Ed25519_sign(user_signing_sk, id || user_id || action || timestamp_u64be || request_hash)
    INDEX idx_sa_time (timestamp),
    INDEX idx_sa_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Device provisioning tokeny (pre stiahnutie keypair na novom zariadení)
CREATE TABLE provisioning_tokens (
    token_hash      VARCHAR(64) PRIMARY KEY,    -- SHA-256(token), nie plain text
    user_id         VARCHAR(26) NOT NULL REFERENCES users(id),
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,            -- default 10 min
    is_used         TINYINT(1) NOT NULL DEFAULT 0,
    INDEX idx_prov_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE invitation_tokens (
    token_hash      VARCHAR(64) PRIMARY KEY,    -- SHA-256(token), nie plain text
    created_by      VARCHAR(26) NOT NULL REFERENCES users(id),
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,            -- default 72h
    is_used         TINYINT(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE spent_challenges (
    challenge_hash  VARCHAR(64) PRIMARY KEY,    -- SHA-256(challenge || username)
    used_at         BIGINT NOT NULL             -- auto-cleanup cron po 5 min
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- JWT invalidácia pri odhlásení/revokácii
CREATE TABLE revoked_tokens (
    token_hash      VARCHAR(64) PRIMARY KEY,    -- SHA-256(JWT)
    revoked_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL             -- auto-cleanup po JWT expiry
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Write ACL — kto má právo zapisovať do ktorého node
-- Content-blind pre OBSAH, ale nie pre write permissions (vedomý kompromis)
-- Write ACL pravidlá:
-- 1. Admin (is_admin=1) je EXEMPT pre topológiu (nodes, deks, envelopes, audit)
--    Pre entry_data: admin má KEK → má všetky DEK-y → smie čítať/písať
--    KNOWN TRADE-OFF: kompromitované admin zariadenie = plný prístup k všetkým entries
--    Mitigácia: Tier 2 entries majú separátny DEK, ale admin KEK ho stále odomkne
-- 2. Pre node/entry: server kontroluje write_acl podľa parent_ref (= node_id folderu)
-- 3. Pre dek/envelope/audit objekty: len admin smie pushovať
-- 4. Automatická aktualizácia: server pridá ACL pri prijatí envelope AK access_level='write' (target_user_id + parent_ref)
--    Read-only envelopes (access_level='read') NEDOSTANÚ write_acl záznam
-- 5. Automatické odobranie: pri tombstone envelope alebo user revokácii
-- 6. Tombstone GC maže aj osirelé write_acl záznamy
CREATE TABLE write_acl (
    user_id         VARCHAR(26) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id         VARCHAR(26) NOT NULL,
    granted_at      BIGINT NOT NULL,
    PRIMARY KEY (user_id, node_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Globálny commit counter (server-assigned)
CREATE TABLE commit_counter (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    next_seq        BIGINT NOT NULL DEFAULT 1,
    gc_floor_seq    BIGINT NOT NULL DEFAULT 0    -- najnižší commit_seq po tombstone GC
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- INIT: INSERT INTO commit_counter (id, next_seq, gc_floor_seq) VALUES (1, 1, 0) pri DB vytvorení

-- Sync stav per-user (server-side záznam pre diagnostiku a rate limiting)
-- Klient sa riadi svojím lokálnym last_known_commit_seq (vault_meta), nie touto tabuľkou
CREATE TABLE sync_state (
    user_id         VARCHAR(26) PRIMARY KEY REFERENCES users(id),
    last_push_seq   BIGINT NOT NULL DEFAULT 0,  -- posledný commit_seq priradený tomuto klientovi
    last_pull_seq   BIGINT NOT NULL DEFAULT 0,  -- posledný commit_seq stiahnutý týmto klientom
    last_activity   BIGINT NOT NULL DEFAULT 0,  -- Unix ms posledného sync requestu
    key_epoch       INTEGER NOT NULL DEFAULT 0  -- posledný známy key_epoch klienta
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### 4.3 Audit Log — Merkle DAG

Prečo DAG namiesto lineárneho chain-u:

```
Lineárny chain (v3 — BROKEN pri offline fork):
  A → B → C → [Peter offline] → D_peter
                 → [Janko offline] → D_janko    ← FORK! Chain sa rozbije.

Merkle DAG (v4):
  A → B → C → D_peter (parent_ids: ["C"])
               → D_janko (parent_ids: ["C"])
               → E_merge (parent_ids: ["D_peter", "D_janko"])   ← OK!
```

- Každý audit záznam referencuje **zoznam** posledných známych leaf-ov (nie jeden prev_hmac)
- Pri sync sa forky zlúčia cez merge-node (vytvára klient pri pull, actor_id = klient robiaci sync). Merge-node musí v `encrypted_details` obsahovať: **zoznam merged parent IDs + SHA-256 hash ich payloadov** — pre post-hoc auditovateľnosť. **Known limitation:** Merge-node autor nemôže kryptograficky dokázať, že merge korektne reflektuje oba forky — ale `encrypted_details` umožňujú post-hoc overenie. Pre malý dôveryhodný tím je to prijateľné
- Overenie integrity: traversuj DAG od root, over Ed25519 podpis každého záznamu
- Ed25519 podpis klienta je **nezávisle overiteľný** — server ani iný klient ho nemôže falšovať

**Epoch pruning (ochrana pred neobmedzeným rastom):**
- Po konfigurovateľnom období (default 180 dní) admin vytvorí **epoch checkpoint**
- Checkpoint = špeciálny audit_log záznam: `action='epoch_checkpoint'`, `encrypted_details` obsahuje SHA-256 hash všetkých entries pod epochou
- Entries staršie ako epoch checkpoint sa môžu fyzicky zmazať (voliteľné)
- Overenie: od epoch checkpointu vpred, nie od Genesis. Checkpoint je podpísaný adminom
- **Klientská validácia pri pull:** Klient po stiahnutí epoch checkpointu overí admin podpis a porovná hash s lokálne známymi entries pod epochou. Ak nesedí → GUI varovanie "Epoch checkpoint nesúhlasí s lokálnymi dátami"
- **Bez pruningu** audit log funguje korektne (len rastie) — pruning je optimalizácia, nie požiadavka

---

## 5. Vyhľadávanie

### 5.1 Lazy unlock + in-memory search

```
1. Unlock (master heslo ~1s Argon2id)
2. Dešifruj folder DEK-y → dešifruj encrypted_meta každého uzla/entry
3. Vybuduj in-memory FTS index z metadát
4. Hodnoty polí = on-demand (klik na entry)
5. Lock → zeroize DEK-y + vymaž FTS index + drop dešifrované dáta
```

**Web user:** Dešifruje len uzly, ku ktorým má obálku (folder DEK). Strom sa poskladá z dešifrovaných metadát. Uzly bez obálky neexistujú v jeho pohľade.

### 5.2 Desktop: FTS5 in-memory (SQLite `:memory:`)

`tokenize='unicode61 remove_diacritics 2'` — prefix search, diakritika, multi-token AND.

### 5.3 Web: Vanilla JS + normalizácia

```javascript
function normalize(s) {
    return s.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}
// Multi-token AND: "hetzner ssh" → obe slová musia matchovať
```

### 5.4 Čo sa prehľadáva

**Štandardný search:** Názvy, kľúče polí, tagy. **Nie hodnoty** — UI to komunikuje.

**Deep search (voliteľný, session-only):** Používateľ môže zapnúť "Hľadať aj v hodnotách" — dešifruje values on-demand do RAM a prehľadá. Výsledky sa **neukladajú** do FTS indexu. Deep search sa vypne pri lock.

**RAM trade-off:** Pri veľkom vaulte (5000+ entries s dlhými poznámkami/kľúčmi) môže deep search spôsobiť výrazný peak pamäte. Implementácia by mala dešifrovať a prehľadávať po dávkach (napr. 100 entries), nie celý vault naraz. GUI by malo zobrazovať progress a umožniť zrušenie.

---

## 6. Secure Share

### 6.1 Flow (content-blind)

```
Peter zdieľa entry:
1. Vygeneruje share_key (náhodný 32-byte symetrický kľúč)
2. Zašifruje entry: crypto_aead_xchacha20poly1305_ietf(share_key, plaintext, aad, nonce)
   AAD pre share: alg(1B) || schema_version(1B) || blob_kind=3(1B) || raw_share_id(32B) || u32be(1)
   (raw_share_id = 256-bit binary PRED base64url encoding, version=1 vždy)
3. Upload na server: {id=random_256bit_base64url, encrypted_blob, expires, max_views}
4. share_key → URL fragment (#)

Link: https://sezam.firma.sk/s/Kx7mP9...qR2#share_key_base64
                                  ▲                    ▲
                           256-bit random       nikdy na server
```

**Share ID:** 256-bit kryptograficky náhodný, base64url encoded. **Nie ULID** (ULID má timestamp — leak). Konštantný response čas pre všetky error stavy.

### 6.2 Parametre

| Parameter | Default | Poznámka |
|-----------|---------|----------|
| `expires_at` | 24h | 1h / 24h / 7d / vlastný |
| `max_views` | **1** | Security default. Používateľ môže zvýšiť na 3/10. |
| `require_pin` | nie | Rate limit: max 3 pokusy / 15 min / IP (429). Po 10 celkových zlyhaniach: `is_locked=1` (admin môže odomknúť). PIN hash = online ochrana |
| `notify_on_view` | áno | Desktop notifikácia |

**Po expirácii:** Server **vymaže riadok** (nie deaktivuje). Cron job každú hodinu.

**Share vs. re-key izolácia:** Share blob je šifrovaný jednorazovým `share_key`, nie folder DEK-om. Re-key folderu (sekcia 9.3) NEOVPLYVNÍ existujúce share linky — tie fungujú nezávisle.

### 6.3 Bezpečnostné hlavičky na share stránke

```http
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
```

---

## 7. Frontends

### 7.1 PySide6 Desktop

**Prvé spustenie (wizard):**
1. "Vitajte v Sezame. Vytvorte si master heslo." + varovanie o nenávratnej strate
2. Benchmark Argon2id, navrhne params (~1s na tomto HW)
3. Vygeneruje Ed25519 + X25519 kľúčové páry
4. Vytvorí `sezam.db`
5. Voliteľne: server URL, recovery sheet na tlač

**Denný flow:** Systray → `Ctrl+Alt+V` → heslo → spinner ~1s → search bar aktívny → hľadaj → kopíruj → auto-clear 15s (vizuálne odpočítavanie v tray)

**Admin funkcie (nové v v4):**
- Menu "Tím" → zoznam kolegov (meno, status, fingerprint, pridelené vetvy)
- Pridanie kolegu → vygeneruje invitation link (128-bit random, 72h expiry, one-time)
- Pridelenie prístupu → stromový checkbox výber vetiev
- Audit log viewer → filtre (actor, action, dátum), overenie Ed25519 podpisov
- Dashboard zdieľaní → aktívne share linky, revoke

**Ďalšie funkcie:** CRUD, drag & drop (s re-key transakciou), tier nastavenie, password generator (integrovaný do formulára), sila hesla indikátor, import/export, nastavenia (auto-lock, clipboard, Argon2id params, server URL), nedávne/často používané, keyboard navigácia.

### 7.2 Web UI

**Závislosti:** Vanilla JS + `libsodium-wrappers` (~120KB, AEAD + crypto_box + Ed25519) + `argon2-browser` WASM (~80KB). CSP, SRI na všetky skripty.

> `libsodium-wrappers` (sumo build) poskytuje `crypto_aead_xchacha20poly1305_ietf`, `crypto_box`, `crypto_sign` — rovnaké primitíva ako desktop `pynacl`/`pysodium`. `tweetnacl-js` (v4) nepodporuje AEAD s natívnou AAD → nahradené.

**Argon2id na mobile:** Fallback params pre mobilné zariadenia: `time=2, mem=128MB`. Appka detekuje dostupnú pamäť a automaticky zvolí profil. Web klient získa parametre z **`GET /api/meta`** (verejné, nešifrované — potrebné pred odomknutím). **Hard floor:** Web klient nikdy neprijme parametre nižšie ako `time=2, mem=64MB`, aj keby server poslal slabšie.

**Web Worker povinný:** Argon2id WASM MUSÍ bežať vo **Web Worker** (nie v hlavnom vlákne). Hlavné vlákno zobrazuje spinner "Odomykám...". Bez Web Worker-a: mobilný Safari môže zabiť tab pre OOM, desktop prehliadač zamrzne na 1–3s.

**Onboarding kolegu:**
1. Admin vytvorí invitation (desktop → vygeneruje 128-bit token, 72h expiry, one-time)
2. Kolega otvorí link → "Nastavte si heslo pre Sezam"
3. Browser vygeneruje Ed25519 + X25519 páry
4. Verejné kľúče → server (v rámci `POST /api/users/register`). Privátne kľúče → zašifrované KEK-om (Argon2id WASM)
5. `POST /api/users/register` spotrebuje invitation token a vráti **onboarding JWT** (15 min TTL, scope: len `PUT /api/me/keypair`)
6. Upload encrypted_keypair: `PUT /api/me/keypair` s onboarding JWT + IndexedDB lokálne
7. **Voliteľná záloha:** "Stiahnite si `.sezam-key` ako offline fallback"
8. **iOS auto-recovery:** Ak IndexedDB je prázdna (iOS 7-day purge), web klient automaticky ponúkne Cestu B (password-based recovery)
9. Stav: "Čakám na schválenie administrátorom" (polling / SSE)
10. Admin overí fingerprint (osobne/telefonicky), schváli, pridelí vetvy
11. Kolega dostane notifikáciu "Prístup schválený" → vidí pridelené vetvy

**IndexedDB a iOS Safari:** UI varovanie: "Váš šifrovaný kľúč je uložený v tomto prehliadači. iOS Safari môže vymazať dáta po 7 dňoch nečinnosti. Uložte si zálohu `.sezam-key` súboru."

**Session:** JWT 1h s refresh. Auto-lock 15 min nečinnosti. "Naozaj chcete odísť?" dialog. Dešifrovaný materiál zmizne pri zatvorení tabu. **Zašifrovaný privátny kľúč** v IndexedDB perzistuje (zámer — kolega sa nemusí znovu onboardovať).

**PWA:** `manifest.json`, service worker pre offline "Nie ste online" stránku (nie offline prístup k vaultu — to je len desktop). Responsive, 44×44px touch targets.

### 7.3 MCP Server — Broker pattern

**MCP nikdy nedostane raw DEK ani raw secret.** Desktop vault proces je broker:

```
AI agent zavolá vault_use("servers/hetzner/ssh", "ssh_connect")
        │
        ▼
MCP server (Python, rovnaký proces ako desktop app)
        │
        ▼
Tier check: tier 1 → vyžaduje approval
        │
        ▼
GUI notifikácia: "Claude Code žiada use_secret pre Hetzner SSH (ssh_connect)"
        │
Admin klikne "Schváliť"
        │
        ▼
Desktop broker: dešifruje DEK → dešifruje field → POUŽIJE secret (napr. otvorí SSH) → vráti výsledok
        │
AI agent dostane: {"status": "ok", "output": "Connected. ls output: ..."}
```

**Kľúčový princíp:** MCP vrstva nedostáva DEK-y. Dostáva len výsledok konkrétnej operácie. Broker dešifruje, vráti, a zeroizuje.

**MCP klient autentizácia:** MCP server beží ako lokálny Unix socket / named pipe s filesystem permissions. Len procesy s prístupom k socket súboru môžu volať. Voliteľne: per-session API token vygenerovaný pri spustení.

**Approval state:** Len **in-memory** (dict v Python procese). Nie v `vault_meta`, nie v SQLite. Reštart procesu = všetky schválenia expirujú. TTL: default 5 min, per-request, **single-use** (jedno čítanie, potom expiruje).

**Tool signatúry:**

```python
vault_list(path: str) → {"nodes": [...], "entries": [...]}  # tier 2 neviditeľný
vault_read(path: str, field: str) → {"status": "ok"|"pending"|"denied"|"timeout"|"not_found", ...}
vault_search(query: str) → {"results": [...]}
vault_use(path: str, action: str, params: dict) → {"status": "ok", "output": "..."}
```

**`vault_use` (Phase 3):** Broker nerobí vlastné protokoly (SSH, SQL klient). Namiesto toho robí **credential injection** — jednorazovo injektuje credentials do sub-procesu alebo dočasného proxy:
- SSH: broker spustí `ssh` sub-process s credentials v env vars, agent dostáva stdin/stdout pipe
- API: broker pridá auth header do HTTP proxy na localhost
- DB: broker spustí DB klienta s credentials, agent posiela SQL queries

Bezpečnostné mantinely (povinné):
- **Nikdy `subprocess.run(..., shell=True)`** — všetky akcie sú prísne typované Python funkcie
- **Command whitelist** per-entry: admin definuje povolené akcie v `encrypted_meta` (napr. `"allowed_actions": ["ssh_connect", "totp_code"]`)
- **Parametrizované, nie skladané:** AI vstup nikdy nie je súčasťou shell príkazu. Parametre sú validované schémou
- **Approval pre každé použitie** (rovnaký flow ako vault_read tier 1)
- **Sandbox (OS-dependent):** Linux: setuid/setgid + seccomp filter. macOS: App Sandbox / `sandbox-exec` profil. Windows: restricted token / job object. Presný sandbox model je súčasťou Phase 3 spec. stdout/stderr sa filtruje pred vrátením agentovi
- Kompletná špecifikácia action schém **pred Phase 3 implementáciou** (open item)

**Keď je vault zamknutý:** `{"status": "vault_locked"}`. Timeout 60s → deny.

### 7.4 CLI

```bash
sezam init                                # vytvor vault (wizard)
sezam unlock                              # heslo
sezam search "hetzner"                    # FTS
sezam get servers/hetzner/ssh/password --clip  # clipboard
sezam set servers/hetzner/ssh/password    # zmena
sezam list servers/                       # strom
sezam generate --length 24 --symbols     # heslo
sezam push                               # sync na server
sezam pull                               # sync zo servera
sezam share clients/auto-moto/money-s5 --expires 24h --views 3
sezam share-list                         # aktívne zdieľania
sezam share-revoke ID                    # zruš + vymaž
sezam change-password                    # zmena master hesla
sezam export --format backup             # záloha
sezam import --format keepass data.kdbx  # import
sezam lock                               # zamkni
```

---

## 8. Synchronizácia

### 8.1 Model

Offline-first, explicitný push/pull. Lokálny vault = primárny. Delta sync (len zmenené objekty).

### 8.2 Delta sync protokol

```
Sync model: SERVER-ASSIGNED commit_seq.
Server je jediný autoritatívny zdroj poradia. Klient má len per-object `version` a `is_dirty` flag.

Push:
1. Klient: objekty kde is_dirty = 1
2. POST /api/sync {objects: [{id, version, payload, payload_hash, signature}, ...]}
   -- signature = Ed25519_sign(signing_sk, canonical_signed_data)
   -- canonical_signed_data (všetky polia fixed-length alebo length-prefixed):
   --   id(26B)
   --   || u8(len(object_type)) || object_type
   --   || parent_ref_or_zero(26B)           -- 26B of 0x00 if NULL
   --   || target_user_id_or_zero(26B)       -- 26B of 0x00 if NULL
   --   || u8(is_deleted)
   --   || u32be(version)
   --   || payload_hash(32B)                 -- SHA-256(payload)
   -- → Viaže server-visible metadáta — topológia/ACL chránená podpisom
   -- Server overí podpis cez signing_pk z users tabuľky
3. Server PRE KAŽDÝ objekt (v transakcii):
   a) Skontroluje write_acl — má user právo zapisovať do tohto node? Ak nie → reject
   b) server.version < client.version → akceptuj, priraď commit_seq = next_global_seq++
   c) server.version == client.version AND payload_hash matches → akceptuj (idempotentný retry)
   d) server.version == client.version AND payload_hash differs → 409 Conflict
   e) server.version > client.version → 409 Conflict
4. Odpoveď (per-object): {accepted: [{id, commit_seq}], conflicts: [{id, server_version, server_payload_hash}]}
5. Klient: accepted → is_dirty = 0. Conflicts → zostávajú dirty, GUI ukáže diff
   **Odporúčaný merge:** Klient stiahne serverovú verziu, dešifruje obe, porovná na úrovni
   jednotlivých polí (nie celého blobu). Ak Janko zmenil "poznámku" a Peter "heslo",
   auto-merge vezme novšie pole z každej verzie. Ak sa zmenilo rovnaké pole → manuálna voľba.

   **Orphaned entries (strata prístupu počas offline):** Ak klient po pull zistí, že pre
   niektoré lokálne dirty entries už nemá DEK obálku (admin medzitým revokoval prístup a re-keyol),
   GUI zobrazí: "Nemáte prístup k X záznamom. Vaše nesynchronizované zmeny boli exportované do
   orphaned_DATUM.json." Klient exportuje dirty entries v dešifrovanej forme (klient ich stále
   má v RAM z pôvodného DEK-u) a potom ich lokálne zmaže

Idempotentný retry:
Klient pri retry posiela **presne ten istý blob** (uložený v push cache), NIE re-encrypt.
Re-encrypt by zmenil nonce → iný ciphertext → iný payload_hash → server vráti 409 namiesto OK.
Push cache = in-memory alebo SQLite temp, vymaže sa po úspešnom ack.

Atomicita re-key batchu:
Ak push obsahuje objekty s rovnakým dek_id (nový DEK + nové entries + nové obálky + tombstone starej obálky),
server ich spracúva v JEDNEJ DB transakcii (all-or-nothing). Partial success pri re-key = nekonzistentný stav.
Klient signalizuje atomický batch cez flag v push payload: {atomic_batch: true, objects: [...]}.

Pull:
1. GET /api/sync?since_commit_seq={last_known_commit_seq}
2. Server vráti objekty kde commit_seq > since_commit_seq (vrátane tombstones)
3. Klient pre každý objekt:
   a) Overí client_signature cez autorov signing_pk (z lokálnej cache alebo server users)
      → neplatný podpis = objekt ODMIETNUTÝ (fabricated by server)
   b) server.version > local.version → akceptuj (novšie)
   c) server.version == local.version AND payload_hash differs → CHYBA (equivocation, GUI varovanie)
   d) server.version < local.version → ignoruj (stale)
4. Tombstones: klient overí `client_signature` (podpis zahŕňa `u8(is_deleted=1)`) → ak podpis platný a autor mal write_acl, označí lokálne ako is_deleted. **Tombstone bez platného podpisu = ODMIETNUTÝ** (server nemôže fabricovať tombstones bez klientovho signing_sk)
5. Klient aktualizuje last_known_commit_seq = max(commit_seq z odpovede)
```

### 8.3 Rollback protection

Klient udržiava **sync checkpoint** (lokálne, v `vault_meta`, šifrovaný):

```json
{
  "last_sync_seq": 42,
  "state_hash": "<see below>",
  "timestamp": 1710764400000
}
```
`state_hash = SHA-256( concat( sort_by_object_id( object_id(26B) || u32be(version) || SHA-256(payload)(32B) ) ) )`
Sort: lexikograficky podľa `object_id` bytes (ULID je naturally sortable). Každý element je 62B fixed.

- Checkpoint je **klientský** — server ho neudržiava (content-blind). Klient po pull prepočíta `state_hash` a porovná s uloženým
- **Detekuje:** rollback (nižší commit_seq), tiché payload zmeny (payload_hash mismatch), equivocation (rovnaká version, iný payload)
- **Known limitation — split-view:** Server môže dvom klientom ukazovať rôzne svety. Bez zdieľanej state-root kotvy (gossip/blockchain) toto nie je detekovateľné. Pre malý dôveryhodný tím je to prijateľný kompromis
- **Tombstone forgery — MITIGOVANÉ:** Tombstones musia mať platný `client_signature` (krok 4 pull). Server bez signing_sk nemôže fabricovať platný tombstone. Zostáva riziko len ak je kompromitovaný klient s write_acl
- **Known limitation — access_level je server-enforced, nie kryptograficky vynútený.** Read-only user má DEK (potrebuje ho na čítanie). Kompromitovaný server by mohol pridať write_acl a umožniť zápis. Pre content-blind model (server je čiastočne dôveryhodný pre ACL) je to prijateľný kompromis
- **payload_hash sémantika:** `SHA-256(payload)` je **bitwise integrity check** (rovnaký šifrovaný blob?), nie semantic dedup (rovnaký plaintext?). Dva rôzne encrypty rovnakého plaintextu majú rôzny hash (kvôli random nonce). Toto je zámer
- Každý pushnutý objekt je podpísaný klientovým Ed25519 kľúčom — ostatní klienti môžu overiť autorov

### 8.4 Tombstone GC

Tombstones (`is_deleted=1`) sa fyzicky mažú po **90 dňoch** od `modified_at`. Server aj klient. Audit log si ponechá záznam o mazaní (Ed25519 podpísaný).

**Long-offline klient:** Server udržiava `gc_floor_seq` v `commit_counter`. Ak klient príde s `since_commit_seq < gc_floor_seq`, server vráti `410 Gone`.

Full resync flow:
1. GUI varovanie: "Máte X nesynchronizovaných zmien. Full resync ich prepíše."
2. **Ponúkni export dirty objektov** pred prepísaním (JSON dump do súboru — poistka)
3. Ak používateľ potvrdí: stiahni celý vault
3. **Overí client_signature** na každom objekte (rovnako ako pri delta pull krok 3a)
4. Nahraď lokálny stav
5. Dirty (nepushnuté) objekty sa stratia — dokumentovaná limitácia pre 90+ dní offline

### 8.5 ETag pre efektívny pull

`GET /api/sync` vracia `ETag` header z `MAX(commit_seq)` v `vault_objects`. Klient posiela `If-None-Match` — ak sa nič nezmenilo, server vráti `304 Not Modified`.

### 8.6 API endpointy

```
POST   /api/auth/challenge    (username → challenge)
POST   /api/auth/verify       (signature → JWT)
POST   /api/auth/refresh      (refresh JWT)
POST   /api/auth/logout       (invalidácia JWT → revoked_tokens)

POST   /api/auth/provision    (device provisioning: {token, username} → encrypted_keypair + salts, bez JWT)
POST   /api/auth/recover      (total device loss: {username, auth_proof} → encrypted_keypair + salts, bez JWT, rate limited)
PUT    /api/me/keypair        ({encrypted_keypair, argon2_salt, auth_salt, auth_proof} — vyžaduje JWT)
                              -- Akceptuje plný JWT (change-password/rotation) ALEBO onboarding JWT (scope=keypair_upload)
                              -- Server dopočíta auth_proof_hash = HMAC-SHA256(verify_salt, auth_proof)

POST   /api/sync              (delta push — dirty objects, server assigns commit_seq, checks write_acl, verifies Ed25519 signatures)
GET    /api/sync?since_commit_seq=X  (delta pull — objects with commit_seq > X)
GET    /api/meta              (verzia, timestamp, argon2_web_params — verejné, nešifrované)
GET    /api/meta?username=X   (argon2_salt + auth_salt — verejné, per-user, pre provisioning/recovery)
                              -- User enumeration ochrana: pre neexistujúcich userov server vracia
                              -- deterministický fake salt = HMAC(server_secret, username), rovnaký response time

POST   /api/users/invite      (admin: vygeneruj invitation, 128-bit, 72h, one-time)
POST   /api/users/register    (kolega: registrácia cez invitation token → vráti onboarding JWT, 15min, scope=keypair_upload)
GET    /api/users             (admin: zoznam userov, vrátane pending)
PATCH  /api/users/:id/approve (admin: schváliť pending usera → status='active')
PATCH  /api/users/:id/rotate-keys (vypnuté — 410, lockout review #11)
DELETE /api/users/:id         (admin: revokácia → status='revoked', trigger re-key; vždy ostane ≥1 admin)
PATCH  /api/users/:id/reactivate (admin: revoked → active; práva a zdieľania znova)
-- Zmena prístupov = dve operácie:
-- 1. Obálky: Admin dešifruje DEK, vytvorí/zmaže obálky, pushne cez POST /api/sync (klientská operácia)
-- 2. Write ACL: Server automaticky aktualizuje write_acl pri prijatí/zmazaní envelope objektov
--    (keď server prijme vault_object s object_type='envelope', pridá/odoberie write_acl pre target_user_id + parent_ref)

POST   /api/share             (vytvor share link)
GET    /api/share/:id         (stiahni blob — atómová SELECT FOR UPDATE)
PATCH  /api/share/:id         (admin: unlock is_locked, alebo manuálna deaktivácia)
DELETE /api/share/:id         (zruš + vymaž blob)
GET    /api/shares            (admin: aktívne zdieľania)
```

---

## 9. Key Management

### 9.1 Zmena master hesla

```
1. Starý heslo → Argon2id → starý KEK
2. Odomkni všetky aktívne DEK-y (vrátane Root DEK, Audit DEK)
3. Nové heslo → Argon2id (nový salt) → nový KEK
4. Re-wrap všetky aktívne DEK-y novým KEK-om
5. dek_archive: chain wrap DEK-y nie sú ovplyvnené (zabalené DEK-om, nie KEK-om)
6. Audit DEK zostáva rovnaký (len nový KEK wrap) — chain nenarušený
7. Ak existuje org recovery wrap: re-wrap nový KEK recovery kľúčom (inak recovery po zmene hesla nefunguje!)
8. Re-encrypt encrypted_keypair novým KEK-om
9. Z jedného Argon2id(nové_heslo, nový argon2_salt, hash_len=64) rozdeľ raw[0:32] = nový KEK a raw[32:64] = nový auth_proof (VOĽBA B; bez druhého saltu/behu)
10. Upload: PUT /api/me/keypair {encrypted_keypair, argon2_salt, auth_salt, auth_proof} (`auth_salt` je legacy; pošli rovnakú hodnotu ako `argon2_salt`)
    → Server si sám dopočíta nový auth_proof_hash = HMAC-SHA256(verify_salt, auth_proof)
11. Inkrementuj `key_epoch` v vault_meta (globálny counter zmien hesla/KEK)
12. Push na server. Server uloží key_epoch do sync_state
    → Klient s nižším key_epoch ako server musí urobiť pull pred push-om (zastaraný KEK wrap)
    → **Edge case: klient offline počas viacerých zmien hesla.** Klient má starý KEK, server má
      encrypted_keypair wrappovaný novým KEK-om. Riešenie: klient pozná AKTUÁLNE heslo →
      Cesta B recovery (stiahni encrypted_keypair, nové heslo → nový KEK → dešifruj → ready).
      Ak klient NEPOZNÁ aktuálne heslo → "zabudnuté heslo" scenár (strata dát)
13. Atomic write lokálne
```

### 9.2 Re-keying pri presune entry

```sql
BEGIN TRANSACTION;
-- 1. Snapshot do history (šifrovaný starým DEK)
INSERT INTO entry_history ...;
-- 2. Dešifruj starým DEK, zašifruj novým DEK
UPDATE entries SET encrypted_data = ?, encrypted_meta = ?, dek_id = ?, version = version + 1 ...;
COMMIT;
```

### 9.3 Re-keying pri revokácii (bulk)

**Celá operácia = jedna SQLite transakcia:**
```sql
BEGIN TRANSACTION;
-- 1. Vygeneruj nový DEK
-- 2. Pre každý entry vo vetve: dešifruj starým DEK, zašifruj novým, version++
-- 3. Archivuj starý DEK: INSERT INTO dek_archive (AEAD(nový_DEK, starý_DEK, blob_kind=6))
-- POZNÁMKA: Re-key je VŽDY admin-only operácia (len admin má KEK → oba DEK-y)
-- 4. Vytvor nové obálky (crypto_box) pre zostávajúcich userov
-- 5. Vymaž Jankovu obálku
COMMIT;
```

### 9.4 Org recovery (break-glass) — len firemný vault

Pre firemný vault existuje **org recovery kľúč**:
- Pri vytvorení firemného vaultu sa vygeneruje recovery kľúč
- Recovery kľúč sa rozdelí cez **Shamir's Secret Sharing** (3 z 5 častí)
- Časti sa distribuujú kľúčovým osobám (CEO, CTO, právnik, ...)
- Root KEK je zabalený aj recovery kľúčom (ďalšia obálka v `deks` pre root scope)
- Ak admin stratí heslo: 3 z 5 osôb sa stretnú, rekonštruujú recovery kľúč, odomknú KEK
- KEK odomkne všetky DEK-y (lebo `deks.encrypted_dek` je VŽDY KEK-wrapped, aj v multi-user)
- Recovery flow: recovery_key → KEK → DEK-y → celý vault. Nové master heslo → nový KEK → re-wrap DEK-y

**Osobný vault:** Žiadna recovery. Recovery sheet v sejfe je odporúčaný.

### 9.5 Argon2id parameter upgrade

Pri odomknutí: porovnaj params s aktuálnym štandardom → ponúkni upgrade → re-derive KEK, re-wrap DEK-y.

---

## 10. Import a export

### 10.1 Formáty

| Import | Export |
|--------|--------|
| CSV (Sezam formát, s príkladom) | Šifrovaný backup (`sezam.db` kópia) |
| KeePass `.kdbx` (cez `pykeepass`) | CSV (po explicitnom potvrdení + varovanie) |
| Bitwarden JSON | Bitwarden JSON (pre migráciu) |
| 1Password `.1pux` | |
| Plain text (`name: value` bloky) | |

**CSV príklad:**
```csv
folder,name,field_key,field_value,sensitive,tier
servers/hetzner,SSH Access,host,192.168.1.1,false,0
servers/hetzner,SSH Access,password,tajne123,true,0
```

**Import wizard (GUI):** Výber formátu → preview pred importom → tier assignment → conflict handling (skip/overwrite/duplicate) → progress bar → sumár.

### 10.2 TOTP

TOTP seed je field type `totp_secret` v `encrypted_data`:
```json
{"key": "totp_secret", "value": "JBSWY3DPEHPK3PXP", "sensitive": true, "field_type": "totp"}
```

**UI:** Countdown kruhový indikátor (30s). Ak zostáva <5s, čaká na nový kód pred kopírovaním. Import z KeePass/Bitwarden automaticky rozpozná TOTP seed.

**MCP:** `vault_use(path, action="totp_code")` → broker vygeneruje kód, vráti len 6 číslic (nie seed). Agent nikdy nevidí TOTP secret.

---

## 11. Chybové scenáre

| Scenár | Správanie | Správa |
|--------|-----------|--------|
| Zlé master heslo | Delay 2s, max 5/15min | "Nesprávne heslo. Zostáva X pokusov." |
| Zabudnuté heslo (osobné) | Žiadna recovery | "Heslo nie je možné obnoviť." |
| Zabudnuté heslo (firemné) | Break-glass (Shamir) | "Kontaktujte držiteľov recovery kľúčov." |
| Výpadok siete počas push | Idempotentný retry | "Push zlyhal. Skúste znova." |
| Sync konflikt (409) | GUI diff | "Záznam bol zmenený inde. Vyberte verziu." |
| Rollback detected | GUI varovanie | "Server vrátil staršie dáta. Možný útok." |
| Corrupted vault.db | SQLite integrity check | "Vault je poškodený. Obnovte zo zálohy." |
| Share link expirovaný | Blob vymazaný | "Odkaz vypršal. Požiadajte o nový." |
| Share PIN vyčerpaný | Link ZABLOKOVANÝ (is_locked=1), admin PATCH odomkne | "Príliš veľa pokusov. Kontaktujte admina." |
| Server nedostupný | — | "Server nie je dostupný." |
| Vault zamknutý (MCP) | 60s timeout → deny | "Odomknite vault v desktop appke." |
| JWT expirovaný počas práce | Auto-refresh / re-login | "Vaša session vypršala. Prihláste sa znova." |
| Invitation link expirovaný | 72h TTL | "Pozvánka vypršala. Požiadajte admina o novú." |
| Kolega čaká na schválenie | Polling / SSE | "Čakáte na schválenie administrátorom." |
| IndexedDB vymazaný | Re-onboarding | "Kľúč nenájdený. Importujte zálohu .sezam-key." |
| Strata VŠETKÝCH zariadení bez .sezam-key | POST /api/auth/recover | "Zadajte heslo pre password-based recovery." (rate limited) |
| Full resync (410 Gone) | GUI varovanie pred prepísaním | "Máte X nesynchronizovaných zmien. Full resync ich prepíše." |
| Share link locked (10 PIN zlyhání) | Admin PATCH unlock | "Odkaz bol zablokovaný. Kontaktujte admina." |

---

## 12. Technológie

| Komponent | Technológia | Poznámka |
|-----------|-------------|----------|
| Desktop GUI | PySide6 | Systray, hotkey |
| Šifrovanie | `pynacl` / `pysodium` | libsodium AEAD (XChaCha20-Poly1305-IETF), crypto_box, Ed25519 |
| KDF | `argon2-cffi` | Argon2id |
| Lokálne storage | SQLite (WAL) | ACID, concurrent read |
| Server | FastAPI | Async |
| Server DB | MariaDB (InnoDB) | |
| Web šifrovanie | `libsodium-wrappers` (~120KB) | libsodium AEAD, crypto_box, Ed25519 — rovnaké primitíva ako desktop |
| Web KDF | `argon2-browser` WASM (~80KB) | Argon2id v browseri |
| MCP | `mcp` Python SDK | Broker pattern |
| IDs | ULID (interné), random base64url (share) | |
| Search | FTS5 `:memory:` / JS normalizácia | |

---

## 13. Fázy implementácie

Stav overený proti repozitáru 2026-07-22. `[x]` = implementované a pokryté testami, `[~]` = čiastočné (uvedený chýbajúci rozsah), `[ ]` = neimplementované. Tento zoznam je release-readiness evidencia, nie plán odhadovaný podľa existencie súborov.

### Phase 1a — Krypto základ + CLI ✅
Dôkazy: `src/sezam/crypto/`, `src/sezam/vault/`, `src/sezam/cli.py`, `tests/test_crypto.py`, `tests/test_vault.py`, `tests/test_spec_compliance.py`.

- [x] Ed25519 + X25519 key pair generation
- [x] libsodium AEAD (`crypto_aead_xchacha20poly1305_ietf`) + ciphertext envelope format + natívna AAD
- [x] Argon2id (konfigurovateľné params + benchmark)
- [x] KEK/DEK hierarchia (root + per-folder + tier2 + audit)
- [x] SQLite vault (`sezam.db`) + schéma + indexy + migrácie
- [x] CRUD API (Python modul)
- [x] Lazy unlock
- [x] In-memory FTS5 search
- [x] Password generator
- [x] CLI (`sezam init/unlock/lock/get/set/list/search/generate/change-password`)
- [x] Entry history + DEK archive
- [x] Import CSV + KeePass + Bitwarden
- [x] Export (šifrovaný backup)
- [x] Audit log (Merkle DAG + Ed25519 podpisy)
- [x] Unit testy krypto vrstvy

### Phase 1b — Desktop GUI ✅
Dôkazy: `src/sezam/gui/`, `tests/test_gui_full.py`, `tests/test_gui_e2e_flow.py`.

- [x] PySide6: systray, hotkey, tree, search, detail, clipboard countdown
- [x] Admin panel: tím, prístupy, audit viewer
- [x] Drag & drop + re-key transakcia
- [x] Import wizard
- [x] Nastavenia
- [x] Prvé spustenie wizard

### Phase 2 — Server + Multi-user + Web + Share + TOTP
Dôkazy: `server/app/`, `web/`, `tests/test_server_spec.py`, `tests/test_e2e_scenarios.py`.

- [x] Envelope encryption (crypto_box + Ed25519 auth)
- [x] FastAPI + MariaDB (content-blind blob store)
- [x] Challenge-response auth + JWT
- [x] Invitation flow (128-bit token, 72h, one-time, TOFU)
- [x] Web UI (libsodium-wrappers, Argon2id WASM, CSP, SRI, PWA)
- [x] Kolega onboarding + `.sezam-key` backup
- [x] Delta sync + rollback protection + ETag
- [x] Tombstone GC (90d)
- [x] Secure Share (random 256-bit ID, expiry delete, PIN)
- [~] TOTP: seed v `encrypted_data` a countdown UI sú hotové; automatický import `otpauth://` nie je implementovaný
- [x] Org break-glass (Shamir)
- [x] Web read-write (ownership `write_policy`: owner_only default / shared)

### Phase 2b — Mobilná appka (Flutter)
Dôkazy: `mobile/lib/`, `mobile/pubspec.yaml`; interoperabilita je pokrytá Python golden-vector/E2E testami, samostatná Dart unit sada zatiaľ nie.

- [x] Flutter projekt (Android + iOS)
- [x] Krypto vrstva: `sodium_libs` (AEAD, crypto_box, Ed25519) + `dargon2_flutter` (KDF)
- [x] Lokálny SQLite vault (`sqflite`) — interoperabilná schéma a wire formát
- [x] Biometrická autentifikácia (FaceID, fingerprint) ako alternatíva k master heslu
- [x] Bezpečné úložisko kľúčov (iOS Keychain, Android Keystore) — žiadny IndexedDB 7-day purge
- [x] Konzumuje rovnaké server API ako web (Phase 2 endpointy)
- [x] Challenge-response auth + JWT (rovnaký flow ako web/desktop)
- [x] Delta sync (push/pull) — rovnaký protokol ako desktop
- [x] Read-write vault (rovnako ako web; ownership `write_policy` platí pre všetkých klientov)
- [x] Clipboard auto-clear (15s)
- [ ] Push notifikácie pre approval requesty (MCP tier 1)
- [x] TOTP generátor s countdown UI
- [~] Secure Share: vytváranie je zapojené v UI; konzumácia je implementovaná v službe, ale nemá mobilnú route/UI
- [x] Offline prístup k vaultu (plný, ako desktop)
- [x] Device provisioning (QR kód pre provisioning token)
- [x] Password-based recovery (Cesta B)
- [x] `.sezam-key` export/import

### Phase 3 — MCP + vault_use
Dôkazy: `src/sezam/mcp/`, `tests/test_mcp_watchtower.py`, `tests/test_spec_compliance.py`.

- [x] MCP broker (žiadny raw DEK pre MCP)
- [x] Capability-based tier enforcement vrátane dedenia `tier` a `ai_read_secret`
- [x] Async approval (in-memory, single-use, TTL)
- [~] `vault_use`: TOTP + whitelist + approval sú hotové; SSH/API proxy, sandbox a úplný bezpečnostný model nie
- [x] MCP klient auth (Unix socket/named pipe + optional token)
- [ ] MCP audit

### Phase 4 — Polish
Dôkazy hotových bodov: `src/sezam/watchtower.py`, `src/sezam/autotype.py`, tagy v `src/sezam/models.py` a CRUD/search vrstve.

- [ ] Biometria desktop/web (Windows Hello, Web Authentication API)
- [x] Watchtower (slabé/duplicitné heslá)
- [x] Tagy
- [x] Auto-type
- [ ] Attachments (SSH kľúče, certifikáty ako súbory) — vyžaduje **two-phase pull**: 1) metadáta + obálky, 2) payloady len pre entries s odomknutým DEK-om (inak veľké prílohy zaťažia všetkých userov)
- [~] Accessibility: čiastkové ARIA/semantické prvky existujú, ale WCAG 2.1 AA audit a úplné pokrytie nie

---

## 14. Settled rozhodnutia

| Rozhodnutie | Voľba | Dôvod |
|-------------|-------|-------|
| Kľúčové páry | Ed25519 (auth/podpis) + X25519 (encryption) oddelene | X25519 nedokáže podpisovať |
| Cipher (content) | `crypto_aead_xchacha20poly1305_ietf` (libsodium) | Natívna AAD podpora. NaCl secretbox AAD nemá → nepoužiteľný |
| Cipher (obálky) | NaCl `crypto_box` | Pre key wrapping — AAD nepotrebné |
| Nonce | Náhodný: `os.urandom(24)` | Uložený v envelope. XChaCha20 navrhnutý pre random nonce |
| AAD | `alg(1B) \|\| schema_version(1B) \|\| blob_kind(1B) \|\| dek_id(26B) \|\| object_id(26B) \|\| u32be(version)(4B)` = 59B fixed | Kanonická definícia v sekcii 2.6, natívny AEAD parameter |
| Server model | Content-blind (nie zero-knowledge) | Server vidí topológiu, nie obsah |
| Pull model | Server pošle všetko, klient filtruje | Content-blind. Metadata leak medzi usermi = dokumentovaný kompromis |
| Audit log | Merkle DAG + Ed25519 podpisy | Zvláda offline forky, tamper-evident |
| Audit DEK | Nezávislý od root KEK lifecycle | Zmena hesla nenarušuje chain |
| MCP model | Broker — nikdy raw DEK/secret | Agent dostáva len výsledok operácie |
| Approval state | In-memory only | Nie v DB, reštart = expiruje |
| Obálky | `crypto_box` (authenticated) | Nie `crypto_box_seal` (anonymný) |
| Share ID | 256-bit random base64url | Nie ULID (má timestamp) |
| Share default | max_views=1, expires=24h | Security default, user zvýši |
| Share po expirácii | Fyzicky vymazať riadok | Nie deaktivovať |
| PIN | Online ochrana only | Argon2id hash, ale 4-6 číslic = offline bezcenné |
| Recovery (zabudnuté heslo) | Žiadna — by design | Heslo nie je uložené nikde |
| Recovery (strata zariadení) | Password-based recovery (Cesta B) | auth_proof s oddeleným saltom, rate limited |
| Recovery (firemný) | Org break-glass (Shamir 3/5) | Pre prípad straty admin hesla |
| Invitation | 128-bit random, 72h, one-time, hashed | Nie plain text na serveri |
| Users status | pending/active/revoked | Explicitný lifecycle |
| `encrypted_meta` DEK | Folder DEK (nie globálny Metadata DEK) | Web user dešifruje len svoje vetvy |
| Tombstone GC | 90 dní | Potom fyzické vymazanie |
| Push | Idempotentný (==version + ==payload_hash = OK) | Bezpečný retry, rôzny payload = 409 |
| Sync model | Server-assigned `commit_seq` | Server je autoritatívny zdroj poradia. Klient má `is_dirty` + `version` |
| Write ACL | Server-side `write_acl(user_id, node_id)` | Content-blind pre obsah, ale nie pre write permissions |
| Device provisioning | 3 cesty: provisioning token, password-based recovery, .sezam-key | Server nemá KEK. auth_proof iný salt ako encryption |
| Encrypted keypair na serveri | Vedomý kompromis | Kompromitovaná DB → offline brute-force na master heslo (Argon2id 256MB chráni). Bezpečnosť = sila hesla |
| KEK/DEK wrap | `deks.encrypted_dek` VŽDY NOT NULL (KEK-wrapped) | Obálky sú DODATOČNÉ prístupové cesty, nie náhrada KEK wrapu |
| MCP default | `use_secret` (nie `read_secret`) | AI defaultne nevidí plaintext. `read_secret` = explicitný opt-in |
| Share PIN DoS | Rate limit per IP, nie okamžité mazanie | Deaktivácia po 10 celkových zlyhaniach |
| Audit pruning | Epoch checkpointy (180d), voliteľný prune | Podpísané adminom, overenie od epochy vpred |
| Argon2id web floor | Hard minimum time=2, mem=64MB | Klient neprijme nižšie od servera |
| Padding | Default ON | Opt-out s varovaním |
| Capability matrix | Pod tiermi | Rozšíriteľné bez zmeny tierov |
| `vault_use` security | **Open item Phase 3** — vyžaduje vlastný bezpečnostný model | Command whitelist, scope, approval — bude špecifikované pred Phase 3 implementáciou |
| Sync podpis | Viaže aj server-visible metadáta (object_type, parent_ref, target_user_id, is_deleted) | Ochrana pred topológia/ACL manipuláciou |
| Device bootstrap | Provisioning token (128-bit, 10min, one-time) | Obchádza Ed25519 auth pre prvé stiahnutie keypair |
| Tombstone GC long-offline | `gc_floor_commit_seq` + 410 Gone → full resync | Klient offline >90d musí urobiť full resync |
| Share atómovosť | SELECT FOR UPDATE → check all → increment → return | Žiadne race conditions |
| JWT server key | Ed25519, generovaný pri štarte, v config/env | Manuálna rotácia, `alg=EdDSA, crv=Ed25519` |
| Identity key rotation | Manuálny incident response: revoke → re-onboard → re-key | Sekcia 2.8 |
| Recovery rate limiting | Proof overený pred zámkom; 10 zlých/h per IP, 10 zlých per username → locked (správny proof zámok zruší) | Zámok vyprší sám / admin odomkne |
| Web závislosti | `libsodium-wrappers` (~120KB) + `argon2-browser` WASM (~80KB) | Rovnaké libsodium primitíva ako desktop |
| IndexedDB kľúč | Encrypted keypair na serveri (primárne) + `.sezam-key` (offline fallback) | Nové zariadenie bez manuálneho file managementu |
| CLI | `sezam` (nie `vault`) | Konzistentný branding |
| Ciphertext format | Štandardizovaný envelope (alg, schema, dek_id, nonce, ct, tag) | Migrovateľné |
| Mobilná appka | Flutter (Android + iOS), nie React Native | Natívny prístup k Keychain/Keystore, biometria, offline vault. `libsodium_flutter` + `argon2_ffi` = rovnaké krypto primitíva |
| Mobile vs. PWA | PWA (web) aj Flutter = read-write vault; ownership `write_policy` platí pre oba | PWA má iOS Safari 7-day IndexedDB purge limitáciu, Flutter nie |
| Mobile vault | Plný offline vault (SQLite), nie len cache | Rovnaká schéma ako desktop, plný push/pull sync |

---

*Verzia 1.1, 2026-03-18. Crypto/sync/storage/web/share architektúra uzavretá. Phase 2b (Flutter mobile) pridaná. Deferred: `vault_use` action schémy (Phase 3).*
