# Zjednotenie logiky do Rust jadra (fáza U)

Rozhodnutie operátora 2026-11-27: kým sa tá istá logika opravuje trikrát (desktop
Python, web JS, mobil Dart) a ešte raz na serveri, každé review nájde nové
rozdiely medzi klientmi (R17-T4: 15 zo 101 prípadov chybných headov dopadlo
v klientoch rôzne). Preto sa práca na review c02cc47 (vetva #468) zastavuje a
najprv sa duplicitná logika presunie do `core/` (`sezam-sync-core`), ako sa to
už raz urobilo so sync rozhodnutiami (docs/SYNC_SINGLE_SOURCE.md bod 4). Toto je
krok S3 z docs/ROOT_CAUSE_PLAN.md (INV-9), rozšírený o ďalšie duplicitné
pravidlá.

## 1. Čo je už v jadre

`core/src`: `gate`, `next_cursor`, `check_state`, `decide_pulled(_batch)`,
`against_held`, `missing_successor`, `order_pulled`, `parents_first`,
`plan_reapply`, `may_open_superseded`, `reseal_targets`, `rekey_due`
(≈2 100 riadkov Rust). Väzby: PyO3 (`core/py`), WASM (`core/wasm`,
`web/static/js/vendor/sezam-sync-core.js`), C ABI + Dart build hook
(`core/ffi`, `mobile/lib/services/sync_core.dart`). Jeden vstup
`json::call(op, input)`.

## 2. Inventár duplicít (r17-l @ 35626b4)

Skript `scripts/dupmap.py` (mená funkcií v ≥ 2 z desktop/web/mobil/server):
142 zdieľaných mien, 35 vo všetkých troch klientoch. Mená sa medzi jazykmi
často líšia, skutočný rozsah je väčší. Po doménach:

| Doména | Desktop / server (Py) | Web (JS) | Mobil (Dart) | Riadky ×kópie |
|---|---|---|---|---|
| **A. Team log**: kanonický JSON, `parse_body`, `validate_body`, `record_hash`, replay, `member.keys` (claim keys, retired), dotazy autority (`is_admin`, `may_write`, `may_hold_key`, `key_recipients`, `current_key`, `key_generation`, `is_stale`, `may_seal`), odmietnutia (`item_refusal`, `tombstone_refusal`, `move_refusal`, `admin_policy_refusal`, `todays_rules_refusal`), `envelope_valid`, `superseded_envelope_valid`, fork (`fork_refusal`, `fork_abandoned`, `resolve_change`), restore (`readmitted`, `restore_part_end`), `next_body` | `teamlog.py` (873; server ho kopíruje v Dockerfile ako `teamlog_core.py`), `team_log_state.py`, `team_log_fork.py`, `team_log_withdrawn.py` | `teamlog.js` (686) + časti `app.js` | `team_log.dart` (919), `write_authority.dart` (369) | ≈ 2 500 × 3 |
| **B. Autorita nad objektmi**: `sealing_dek_id`, `team_folder_above`, osobný strom (`in_personal_tree`, `is_personal_root`), `unauthorized_writes`, `log_admins`, `team_key_ids`, `held_genesis`, `named_by_team_log`, `team_log_refusal` | `sync_writers.py`, `personal_root.py`, `team_log_local.py`; server `sync.py`, `personal_tree.py`, `team_log.py` | `app.js` | `write_authority.dart`, `vault_service.dart`, `sync_service.dart` | ≈ 1 200 × 4 |
| **C. Key vouchers** (N1, N6/N7): položka = digest podpísanej správy, `vouched_entries`, `lists_of`, pravidlo zlyhania podpisovateľa | `key_vouchers.py`, `sync_vouchers.py`; server `key_vouchers.py` | `app.js` | `key_vouchers.dart` | ≈ 500 × 4 |
| **D. Podpisované správy a kanonické formáty**: `sign_auth_challenge`, `key_rotation_message`, `reseed_message`, `org_recovery_rewrap_message`, správa podpisu objektu (`verify_object_signature`), audit záznam (`parse_canonical_audit_record`, `validate_audit_dag`), `signed_fields` | `sync_common.py`, `reseed.py`, `key_rotation.py`, `sync_pull.py`, `sync_client.py`; server `auth.py`, `recovery.py` | `app.js` | `sync_service.dart`, `key_rotation.dart` | ≈ 800 × 3–4 |
| **E. Dátové formáty bez tajomstiev**: AAD (`build_aad`), pre-anchor (`parse/merge/add/check`), `SZACCT01` bundle encode/decode, `padded_size`, `split_for_push`, `normalize_username`, `password_forms`/`canonical_password`, validácia KDF parametrov, `removal_archive_id`, Shamir GF(256) | `aead.py`, `padding.py`, `sync_limits.py`, `usernames.py`, `kdf.py`, `keys.py`, `dek.py`, `shamir.py`; server `schemas.py` | `app.js` | `crypto_service.dart`, `sync_limits.dart`, `password_forms.dart` | ≈ 900 × 3 |
| **F. Rozhodnutia sync orchestrácie nad team logom**: catch-up, follow fork, `fail_as_served`, re-send stratených zmien, `seal_to_rotated_members`, `revive_folders_of_unsent` | `team_log_local.py`, `team_log_fork.py`, `sync_rekey.py`, `sync_state.py` | `app.js` | `team_log_client.dart`, `sync_service.dart`, `vault_service.dart` | ≈ 1 500 × 3 |
| G. Úložisko, UI, sieť, šifrovanie/KDF (libsodium) | zostáva na platforme | | | — |

Zdroj chýb posledných review: A, B, C, F. Takmer všetky nálezy R17 (N1, N4,
N6/N7, N8, N9, T2, T4, equivocation, W2, Q2, Q3, E3) sú v týchto doménach a
opravovali sa 3–4-krát.

## 3. Rozhodnutia

1. **Podpisy overuje naďalej libsodium klienta, nie jadro.** Ed25519 v Ruste
   (`ed25519-dalek`) sa od libsodium líši na okrajoch (small-order body,
   nekanonické kódovanie A/R), a to sú presne prípady z vektorov R9-A2.
   Replay preto beží v dvoch krokoch: `team_log_checks(records)` vráti zoznam
   overení (správa, verejný kľúč, podpis) za predpokladu, že všetky
   predchádzajúce prešli. Klient ich overí svojím libsodium a zavolá
   `team_log_replay(records, verified)`, kde `verified` je počet úspešných
   overení zľava. Replay sa pri prvom neoverenom zastaví s rovnakou chybou
   ako dnes (`bad_signature` pri danom seq). Rovnako `fork_refusal` a
   vouchery.
2. **SHA-256 je v jadre** (`sha2`), lebo hash je deterministický a nemá
   okrajové prípady (`record_hash`, digest voucheru, signed digest).
3. **Šifrovanie, KDF a narábanie s tajomstvami zostávajú na platforme**
   (memzero, výkon Argon2 vo WASM). Do jadra idú len formáty bez tajomstiev
   (E): skladanie AAD, rozbor a kontrola formátov, padding, limity.
4. **Stav team logu** je JSON dokument (`state_to_json` už má web). Dotazy
   autority berú stav, nie celý log, aby sa log neprehrával pri každom
   dotaze.
5. **Server** používa to isté jadro cez PyO3 wheel. Dockerfile dostane build
   stage s Rustom (pripnutý image digestom) namiesto kopírovania
   `teamlog.py`.
6. **Staré implementácie sa mažú**, nezostávajú ako orákulum. Orákulom sú
   spoločné vektory (`tests/vectors/*.json`) a conformance scenáre; kde
   vektor chýba, pred zmazaním sa doplní zo súčasného správania desktopu a
   každý rozdiel medzi klientmi sa rozhodne a zapíše.
7. **Ráčna:** test, ktorý zlyhá, keď sa meno pravidla z jadra (zoznam v
   `core/src/json.rs`) objaví ako implementácia v kóde klienta alebo servera
   mimo tenkého obalu.

## 4. Postup (ciele vetvy U)

| Krok | Obsah | Hotové keď |
|---|---|---|
| U1 | Team log v jadre: `core/src/teamlog/` (kanonický JSON, telo, validácia, hash, replay v dvoch krokoch, dotazy, odmietnutia, fork, restore, `next_body`, `resolve_change`), operácie v `json.rs`, verzia jadra 0.3.0 | `cargo test` prejde všetkými `team_log*.json` vektormi; PyO3 diferenciálny test proti `teamlog.py` na vektoroch a náhodných logoch zo state machine |
| U2 | Desktop + server na jadre: `sezam.teamlog` je obal nad `sync_core`, logika zmazaná; server cez wheel, Docker build stage | cielené testy team logu a servera zelené; Docker image naštartuje |
| U3 | Web na jadre: `teamlog.js` obal nad WASM, logika zmazaná | `test_team_log_differential`, web vektory zelené |
| U4 | Mobil na jadre: `team_log.dart` + `write_authority.dart` obal nad FFI, logika zmazaná | Flutter vektory team logu zelené |
| U5 | Autorita nad objektmi (B) a key vouchers (C) v jadre, štyri strany prepnuté | vektory `key_vouchers*.json`, `signed_fields.json` + nové vektory pre B na všetkých stranách |
| U6 | Podpisované správy a formáty (D, E) v jadre, prepnuté | `cross_client.json`, `padding.json` + nové vektory zelené na všetkých stranách |
| U7 | Rozhodnutia orchestrácie (F) ako tabuľka „rozhodnutie → akcia“ v jadre | conformance scenáre team logu zelené na troch klientoch |
| U8 | Ráčna implementácií v CI + aktualizácia AUTHORITY_MAP, ROOT_CAUSE_PLAN (S3 hotové) | test ráčne zelený, zlyhá na vloženej kópii pravidla |
| U9 | Celé suite (Python+MariaDB, Flutter, SM) raz, push na main cez Sezam-release, CI zelené; potom návrat na vetvu #468 a preverenie, ktoré nálezy R17 ešte platia | push CI zelené |

Každý krok je samostatný commit (alebo malá séria) s testami. Počas vývoja
len lint a cielené testy, celé suite iba v U9.

Rozhodnutia U5 (kde sa klienti rozišli, `tests/authority_vectors.py`
`DECISIONS`, platí pravidlo desktopu): log rozhoduje prvý aj o objekte na
najvyššej úrovni; s logom z osobného stromu odstraňuje len jeho vlastník; pod
prvou úrovňou stromu organizácie aj odstránenie len admin (H6); priamo pod
priečinkom najvyššej úrovne odstránenie potrebuje to isté ako zápis (náhrobok
osobného priečinka je zapečatený kľúčom vlastníka). Nie je prevzaté: desktop s
logom neberie adminov priamo pod vlastným horným priečinkom; zakladateľovi je
to koreň organizácie a druhý admin by tam po odovzdaní nezapísal. Cykly rodičov
jadro blokuje celé (desktop závisel od poradia). Čo desktop vie z vlastnej
databázy (zadržané uzly, osobné stromy, granty, vlastné horné priečinky),
dostane jadro ako kontext, keď sa desktop prepne.

H2 (review a159e97, capability run 698) je v jadre: zápis pod priečinkom,
ktorý volanie ani `known_nodes` nemá, jadro zadrží (výstup `held`, nesúdi
ho), ak ho nenapísal tento účet ani účet z kontextu `vouched`; pod zadržaným
priečinkom je zadržané všetko. Desktop posiela `vouched` a pri každom pulle
vráti jadru všetko predtým zadržané; v Pythone ostáva len úložisko.
Rozhodnutie: web a mobil `vouched` neposielajú, takže nezadržiavajú nič
(nemajú trvalé úložisko zadržaných zápisov ani vlastný doklad o účtoch);
ich správanie a vektory `authority.json` sú bez zmeny. Testy:
`core/tests/authority_held.rs` (odpovede desktopového `held_back` z fa0c02f)
a `tests/test_review8_unknown_parent_h2.py`.

Pravidlo pushu (U5g): `authority::write_refusal` je jeden verdikt logu nad
zápisom priečinka/položky; súdi ním pull (`unauthorized_writes`) aj push.
Server (`_team_log_refusal`), web (`assertTeamLogAllowsWrite`), mobil
(`write_authority.dart`) a desktop (`team_folder_at_or_above`) volajú op
`authority_write_refusal` / `authority_team_folder_above`; kópie
`team_folder_above`, `item/tombstone/move_refusal` v serveri sú zmazané.

Osobný strom (U5h): `authority::personal_tree` (op `authority_personal_tree`,
vektory `tests/vectors/personal_tree.json`) dáva korene (horný priečinok
`personal`, otvorený, kľúč mimo `team_keys`, podpísaný týmto účtom), ich kľúče
(čo ostáva otvorené pri odmietnutom logu), `tree` (priečinky v strome, každý
na ceste otvorený a tento účet) a `shown` (pravidlo 3 INV-7: celá cesta pod
kľúčom koreňa, položky tohto účtu pod ním alebo pod otvoreným tier-2
kľúčom). Web (`webInPersonalTree`, `refusedLogPersonalKeys`), mobil
(`refusedLogPersonalTree`, strom pre `sendableWhileRefused`) a desktop
(`in_personal_tree`, pravidlo `is_personal_root`) ho volajú. Rozhodnutia:
koreň je len priečinok najvyššej úrovne (web bral `personal` na akejkoľvek
úrovni); desktop a strom mobilu z otvorených uzlov neposielajú `own_user_id`
(držia len uzly použité podľa pravidiel autority), desktop posiela ako
`team_keys` kľúče logu a obálok. `authority_team_key_ids`: kľúče, ktoré
záznamy lokálnej kópie logu menujú, bez replayu; berie aj nekanonické telo
(viac tímových kľúčov = menej otvorených pri odmietnutom logu), desktop
predtým preskočil nekanonické. `held_genesis` a `named_by_team_log` ostávajú
na klientoch: sú to dotazy nad už replayovaným stavom alebo `record_hash`
jadra, nie samostatné pravidlo.

Podpis objektu (U6a): správu podpisu sync objektu (spec 8.2) skladá len
jadro (`key_voucher_signed_message`, `vouchers::signed_message`). Web
(`signSyncObject`, `signedObjectMessage`), mobil (`buildSyncSignatureData`)
a server (`_verify_sync_signature`, predtým orezával dlhé id) ju volajú;
desktop už od U5a. Pole, ktoré správa presne neudrží, sa odmietne (web
predtým pri podpise verziu orezal `>>> 0`). Vektory
`cross_client.json` `sync_signature` v `core/tests/cross_client_vectors.rs`.

Formáty (U6b, `core/src/formats.rs`): AAD obálky (`aad`, verzia mimo u32 sa
odmietne), `padded_size`, `split_for_push` (klient posiela veľkosti objektov
v bajtoch svojho JSON enkódera, jadro vráti počty v dávkach) a
`normalize_username` (NFC + orezanie zjednotenej množiny znakov). Desktop
(`aead.build_aad`, `padding.padded_size`, `sync_limits.split_for_push`,
`usernames`), server (`schemas.normalize_username`), web (`app.js`) a mobil
(`crypto_service`, `sync_limits`, `auth_service`) volajú jadro, ich kópie a
konštanty limitov sú zmazané. Vektory `tests/vectors/formats.json`
(115 mien, 31 okrajových znakov, 22 delení) v `core/tests/formats_vectors.rs`.
Node harnessy webu načítajú `sezam-sync-core.js` a čakajú `SezamSyncCore.ready`.

Podpisované správy (U6c, `core/src/messages.rs`): prihlásenie
(`auth_challenge_message`, aj dôkaz aktuálneho kľúča), certifikát rotácie
kľúča, reseed/rejoin a org-recovery rewrap. Server (`auth.py`,
`routers/recovery.py`), desktop (`sync_common`, `reseed`, `key_rotation`),
web (`signAuthChallenge`, `keyRotationMessage`, `orgRecoveryRewrapMessage`) a
mobil (`signAuthChallenge`, `keyRotationMessage`, `rejoinMessage`) volajú
jadro; kontexty (`sezam-…-v1`) sú len v jadre. `reseed_message` v Pythone
berie `rejoin=` namiesto bajtov kontextu. Id, ktoré správa presne neudrží, sa
odmietne (server ho predtým orezal na 26 bajtov). Vektory
`tests/vectors/signed_messages.json` (zo servera pred zmenou) v
`core/tests/signed_messages_vectors.rs`, `tests/test_signed_messages_vectors.py`
(desktop, server, web) a `mobile/test/signed_messages_vectors_test.dart`.

Audit záznam (U6d, `core/src/audit.rs`): podpisované bajty (`audit_message`),
sync payload (`audit_payload`, kanonický JSON ako Python `json.dumps` s
`ensure_ascii`), parse stiahnutého záznamu (`audit_parse`: úplný, kanonický,
verzia 2, nezmazaný, bez seba v rodičoch; vráti aj podpisované bajty) a DAG
(`audit_dag`: všetci rodičia, žiadny cyklus). Desktop (`AuditLog._build_canonical`,
`serialize_audit_row`, `_parse_audit_payload`, `_validate_audit_dag`; vlastná
kontrola verzie v `_apply_audit` zmazaná), web (`parseCanonicalAuditRecord`,
`buildAuditCanonical`, DAG vo `verifyAuditGraph`) a mobil (tie isté mená +
`validateAuditDag`; vlastná kontrola zmazaného objektu zmazaná) volajú jadro.
Overenie podpisu ostáva v libsodium platformy. Oprava: web a mobil porovnávali
payload so svojím JSON enkóderom, ktorý necháva ne-ASCII znaky, a desktopový
záznam s takou akciou odmietli. Sprísnenie: base64 detailov len v kanonickom
tvare (desktop predtým prijal nenulové výplňové bity, web a mobil nie). Web
berie podpisované bajty z parse jadra (JS číslo nad 2**53 časovú pečiatku
presne neudrží). Vektory `tests/vectors/audit.json` (z desktopu pred zmenou:
24 správ, 24 payloadov, 18 parse, 30 odmietnutí, 8 DAG) v
`core/tests/audit_vectors.rs`, `tests/test_audit_vectors.py` (desktop, web) a
`mobile/test/audit_vectors_test.dart`.

Známe zlyhanie mimo vetvy U: `tests/test_review13_handover_rekey.py::
test_the_new_admin_rekeys_what_the_former_admin_held` (409 „target_user_id is
admin only“) padá od R17 commitu e55ddb8 (7f9a191 zelené); opraviť pred U9.

Rozpracovaný stav #480 je odložený v `git stash` na `r17-l`
(„R17 #480 WIP before unification pause“) a v `%TEMP%\r17_480_wip.patch`.
