# Návrh: podpísaný tímový denník

Stav: návrh (TL0, cieľ #346). Podklad: review `main@a159e97`, časť „Prečo sa diery stále vracajú“.

## 1. Problém

O členstve, právach a aktuálnom kľúči priečinka dnes žiadny podpísaný záznam nerozhoduje. Každý klient
to odhaduje zo stôp, ktoré server alebo člen tímu vie podvrhnúť: kto podpísal ktorý objekt, ktorý ULID
je najnovší, nepodpísaný `scope`, `tier` v metadátach, `access_level` v envelope, `/api/users`. Každá
oprava (H1–H5, H8, D5b/c/d, #347) pridala ďalšie pravidlo nad tými istými stopami a pravidlá sú trikrát
(Python, JS, Dart).

Cieľ: jeden zoznam podpísaných faktov, do ktorého sa len pridáva. Každý klient aj server z neho
**prehratím** vypočíta tie isté odpovede. Čo v denníku nie je, neplatí.

## 2. Model

- Jeden server = jedna organizácia = jeden denník.
- Denník je reťaz záznamov `0, 1, 2, …`. Záznam `n` nesie hash záznamu `n-1`.
- Server denník uloží a rozošle, ale nevie ho sfalšovať (podpisy) ani prepísať (hash reťaz + kotva
  v klientoch). Vie ho zadržať — pozri §8.
- Server prijme pridanie len na aktuálnu hlavu (compare-and-swap na `prev`). Dve súbežné zmeny tej
  istej veci teda nemôžu vzniknúť obe: druhá dostane `team_log_head_moved` a musí sa prebaseovať.

## 3. Záznam

### 3.1 Telo

Telo je JSON objekt v **obmedzenom kanonickom tvare** (§3.3):

| Pole | Typ | Význam |
|---|---|---|
| `v` | int | verzia pravidiel, podľa ktorých sa záznam posudzuje: `1` (do review 1141a20: člen mohol dostať späť vyradený kľúč — `member.remove`→`member.add` alebo rotácia späť), `2` (vyradený kľúč ostáva vyradený). Nové záznamy nesú najnovšiu verziu; pozdĺž denníka verzia neklesá (`rules_downgrade`). Denník uložený podľa starších pravidiel sa tak po ich sprísnení stále prehrá (review 8595ec1, R10-B); server, ktorému uložený denník naozaj neprejde, odpovie 503 `team_log_unreadable` s `seq`, nie 500. |
| `seq` | int | poradie v reťazi, genesis = 0 |
| `prev` | hex64 | SHA-256 hash predchádzajúceho záznamu; genesis 64× `0` |
| `type` | string | typ záznamu (§3.2) |
| `author` | ULID | `user_id` podpisovateľa |
| `data` | objekt | obsah podľa typu |

Čas v zázname nie je. O ničom nerozhodujú hodiny.

### 3.2 Typy

| `type` | Podpisuje | `data` | Podmienky pri prehratí |
|---|---|---|---|
| `genesis` | zakladajúci admin | `org` (ULID), `user_id`, `signing_pk`, `encryption_pk` | len `seq = 0`; `author = user_id`; podpis kľúčom z `data` |
| `member.add` | admin | `user_id`, `signing_pk`, `encryption_pk`, `role` ∈ `admin`/`member` | používateľ nie je aktívny člen; kľúče nie sú kľúče iného člena ani (od `v = 2`) archivované |
| `member.role` | admin | `user_id`, `role` | aktívny člen; posledný admin sa nedá znížiť |
| `member.remove` | admin | `user_id` | aktívny člen; posledný admin sa nedá odobrať; zruší všetky jeho prístupy (§4.2) |
| `member.keys` | člen sám (starý kľúč) | `user_id`, `signing_pk`, `encryption_pk`, `new_key_sig` | `author = user_id`, aktívny; `new_key_sig` = podpis **novým** kľúčom nad `sezam-team-log-newkey-v1\0 ‖ prev ‖ user_id ‖ signing_pk ‖ encryption_pk` |
| `folder.key` | admin | `folder` (ULID uzla), `gen`, `dek_id`, `prev_dek_id` | `gen = 0` a `prev_dek_id = null`, ak priečinok v denníku nie je; inak `gen = aktuálna+1` a `prev_dek_id = aktuálny dek_id`; `dek_id` sa v denníku ešte nevyskytol |
| `access.set` | admin | `folder`, `user_id`, `level` ∈ `read`/`write`/`null` (= žiadny) | `folder` má `folder.key`; `user_id` je aktívny člen (pri `null` stačí, že bol); zníženie prístupu (§4.2) |
| `org.recovery` | admin (za seba) | `recovery_pk` (Ed25519 kľúč Shamir obnovy, hex) | len od `v = 2`; autor je aktívny admin; kľúč nie je kľúč člena; po `member.role`/`member.remove` autora neplatí (review 8595ec1 #4) |
| `org.recovery.wrap` | admin (za seba) | `wrapped_kek` (72 B hex), `key_epoch`, `threshold`, `total_shares` | len od `v = 2`; autor má v denníku kľúč obnovy (`no_recovery_key`); `1 ≤ threshold ≤ total_shares ≤ 255` (`bad_shares`); nový `org.recovery` autora ho zruší (capability run 316) |

Pravidlá spoločné všetkým: `seq` = predchádzajúci + 1, `prev` = hash predchádzajúceho, `author` je
v stave **pred** záznamom aktívny člen s potrebnou rolou a podpis platí jeho `signing_pk` z denníka.
Záznam, ktorý pravidlo poruší, je **chyba celého denníka** — prehratie skončí a klient nerozhoduje nič
(nie „preskočiť a pokračovať“).

`folder` je uzol, ktorému kľúč patrí (`deks.node_id`); podpriečinky, ktoré si kľúč požičiavajú od
rodiča, v denníku nie sú. Root organizácie je tiež `folder`.

### 3.3 Kanonický tvar, podpis, hash

Aby boli tri implementácie zhodné bez knižnice na JCS, je JSON obmedzený:
- hodnoty sú len objekty, reťazce, celé čísla `0 … 2^53-1` a `null`; žiadne polia, desatinné čísla,
  `true`/`false`;
- reťazce obsahujú len tlačiteľné ASCII bez `"` a `\` (ULID, hex, názvy typov a rolí) — netreba escapovať;
- kľúče objektov zoradené podľa bajtov, bez medzier: `{"a":1,"b":"x"}`.

Parser, ktorý nájde čokoľvek iné (aj duplicitný kľúč, chýbajúce alebo navyše pole), záznam odmietne.

- `body_bytes = canonical(telo)`
- `sig = Ed25519(author_sk, "sezam-team-log-v1\0" ‖ body_bytes)` (hex)
- `hash = SHA-256("sezam-team-log-hash-v1\0" ‖ body_bytes ‖ sig_bytes)` (hex)
- Prenos: `{"body": "<body_bytes ako reťazec>", "sig": hex}`. Telo sa prenáša ako presný kanonický
  reťazec; príjemca ho rozparsuje, znova kanonizuje a musí dostať ten istý reťazec (inak
  `bad_encoding`). Podpis aj hash sú teda nad bajtmi, ktoré prišli, a duplicitné kľúče či iné poradie
  neprejdú v žiadnom jazyku.

## 4. Stav po prehratí a rozhodnutia

### 4.1 Stav

```
members[user_id]  = {signing_pk, encryption_pk, role, active}
                    (staré podpisy objektov overuje ďalej archív kľúčov s retired_seq, §10.2 spec)
folders[folder]   = [dek_id gen0, dek_id gen1, …]          # lineárna reťaz, aktuálny = posledný
access[folder][user_id] = read | write                       # chýba = žiadny
needs_rekey[folder] = množina user_id                        # odobratí, ktorí ešte držia aktuálny kľúč
head = (seq, hash), org, genesis_hash
```

### 4.2 Zníženie prístupu

`member.remove` aj `access.set` na nižšiu úroveň (`write`→`read`, čokoľvek→`none`) urobia priečinok
**neaktuálnym**: kto ho stratil, aktuálny kľúč pozná. Aktuálny je priečinok zase až po `folder.key`
s ďalšou generáciou. Klient preto posiela zníženie prístupu spolu s `folder.key` (a re-key batchom
objektov) v jednom pridaní (§5). Medzitým (zníženie bez nového kľúča — napr. iné zariadenie admina
re-key ešte neposlalo):
- do priečinka sa nepečatí nič nové (`may_seal` = nie) a nikomu sa kľúč nedáva,
- re-key ho dokončí ktorékoľvek zariadenie admina.

`write`→`read` po novom kľúči tiež nestačí sám: objekty, ktoré člen podpísal, ostávajú podpísané ním.
Re-key ich prezapečatí a podpíše adminom (už dnes), takže po novej generácii platí pravidlo §4.3.4.

### 4.3 Rozhodovacie funkcie

Všetky vracajú áno/nie alebo hodnotu; chýbajúci údaj = **nie / chyba**, nikdy predvolené „áno“.

1. **`key_recipients(folder)`** → presne `{(user_id, encryption_pk, level)}` z `access[folder]` aktívnych
   členov. Re-key, prebalenie, grant znova a `abandon-rekey` pečatia len týmto, s úrovňou z denníka.
   Envelope ani `/api/users` o príjemcoch nerozhodujú (zmizne H1, H3, H4, D5c, c494af0).
2. **`current_key(folder)`** → `dek_id` najvyššej generácie. Kľúč, ktorý v reťazi priečinka nie je, je
   „neznámy“: nepoužiť a nepečatiť ním; ak ním server podpísal objekty, objekty odložiť a denník
   stiahnuť znova (zmizne H5 a ULID/hodiny).
3. **`key_generation(folder, dek_id)`** → `current` / `old(gen)` / `unknown`. Starým kľúčom sa dá čítať
   história, živý objekt zapečatený starou generáciou je neplatný.
4. **`may_write(folder, user_id)`** → `admin` alebo `access = write`. Objekt v tímovom priečinku platí,
   len ak jeho overený podpisovateľ teraz smie zapisovať a je zapečatený aktuálnou generáciou. Server
   overuje to isté pri pushi (zmizne H8, N2/N7). Tombstone platí rovnako.
5. **`may_hold_key(user_id, dek_id)`** → envelope pre `dek_id` prijať len ak je `dek_id` aktuálna
   generácia priečinka, kde má `user_id` prístup, a podpisovateľ envelope je admin.
6. **`is_team_folder(folder)`** → priečinok má `folder.key`. Vlastný kľúč, ktorý v denníku nie je, je
   osobný (neplatia preň tímové pravidlá). Cudzí kľúč (z envelope), ktorý v denníku nie je → odmietnuť.

## 5. Server

- Tabuľka `team_log(seq PK, prev, hash UNIQUE, body, sig, author)`; hlava = najvyššie `seq`.
- `GET /api/team-log?since=<seq>` → záznamy `> since` + hlava. Pull `/api/sync` vracia aj
  `team_log_head {seq, hash}`, aby klient zistil, že denník zaostal.
- Pridanie ide **v tom istom požiadavku ako push**: `POST /api/sync {…, team_log: [záznamy]}`. Server
  v jednej transakcii pod zámkom sekvencie overí, že `team_log[0].prev` = hlava (inak 409
  `team_log_head_moved`), prehrá nové záznamy jadrom (§4) a až potom aplikuje objekty. Odmietnutie
  záznamu zruší celý push. Samostatne (bez objektov) to isté cez `POST /api/team-log`.
- Prehratie na serveri robí to isté jadro (Python, `sezam.teamlog`), stav drží v pamäti/cache tabuľke
  (odvodená, dá sa kedykoľvek prepočítať).
- Keď denník existuje:
  - `write_acl`, `users.is_admin` a `users.status = revoked` sú **odvodené** z denníka (cache);
  - push objektu v tímovom priečinku: §4.3.4 (podpisovateľ smie písať, objekt zapečatený aktuálnou
    generáciou; hlavičku blobu server už číta);
  - envelope: §4.3.5;
  - `DELETE /api/users/:id` vyžaduje `member.remove` v denníku (bez neho 409), `PATCH approve`
    aktivuje účet na prihlásenie, ale tímové práva dá až `member.add`.
  - Implementované (TL3): pravidlá platia aj pre admina z JWT — admin, ktorého denník nemenuje, nemá
    v tímových priečinkoch žiadne práva. Položka zapečatená kľúčom z denníka: kľúč patrí priečinku nad
    ňou (alebo uzlu samému), je aktuálnou generáciou, priečinok nečaká na re-key, autor smie písať.
    Pod tímovým priečinkom kľúčom mimo denníka pečatí len vlastný osobný kľúč autora (DEK bez
    `parent_ref`), a aj to len autor, ktorému denník dáva v tom priečinku `may_write` (nález 204);
    tier-2 v zdieľanom priečinku patrí do samostatného priečinka s vlastným kľúčom (TL7, §10).
    Presun položky alebo priečinka von z tímového priečinka je odobratie z neho: potrebuje
    `may_write` v priečinku, ktorý opúšťa (`move_refusal`, nález 205; server pri pushi, klienti pri pulle).
    Tombstone položky zapečatenej tímovým kľúčom vyžaduje `may_write`. Nový DEK objekt tímového
    priečinka bez `folder.key` je odmietnutý. Envelope tímového kľúča: autor je admin v denníku,
    priečinok nečaká na re-key, `may_hold_key`, úroveň = `access`; envelope `write_acl` nemení.
- Kým denník neexistuje (organizácia pred migráciou), platí dnešné správanie.
- Endpointy bez prihlásenia denník nečítajú ani nezamykajú.
- **Obnova servera (review `1141a20`, R9-E):** server obnovený zo zálohy alebo presunutý stratí
  koniec denníka a každé zariadenie predtým hlásilo `TEAM LOG MISMATCH` natrvalo. Zariadenie, ktoré
  záznamy prijalo (desktop, web v relácii, mobil), ich teraz nahrá späť cez
  `POST /api/team-log/restore` po stránkach do 1000 — ale **len na prefix** vlastnej kópie: server
  bez denníka, alebo s rovnakou genesis a rovnakým hashom na svojej hlave. Fork, iná genesis alebo
  odmietnuté nahratie ostáva mismatch; nič sa nestavia na cudzí denník a pin sa nikdy sám nezahodí.
  Server prijme záznamy akéhokoľvek autora, ak pokračujú jeho hlavu a prejdú replay (podpisy autorov
  a pravidlá jadra rozhodujú). Tabuľka `users` stále rozhoduje kľúče: posledné kľúče, ktoré obnovený
  denník dáva každému menovanému aktívnemu členovi, musia byť tie, ktorými sa účet prihlasuje, a
  genesis potrebuje zakladateľa, ktorý je tu admin, alebo nahrávajúceho, ktorý je tu admin aj
  posledným adminom obnoveného denníka — inak by obnova bola cestou okolo pravidiel `append`.
  Výnimka (capability run 277): záloha spred rotácie identity nemá ani `member.keys`, ani rotovaný
  riadok `users`. Obnova `member.keys` vráti, ak sa účet ešte prihlasuje kľúčmi, ktoré obnovený
  denník tomuto členovi sám vyradil (rotáciu podpísal starý kľúč, `new_key_sig` nový). Rotujúce
  zariadenie potom pri prevzatí kľúčov (heslo účtu, SM14) neprejde späť na vyradený keypair: z key
  material servera zostaví tú istú rotáciu (starý → držaný keypair) a pošle ju znova
  (`tests/test_review9_team_log_restore.py`, člen aj admin). Kľúče, ktoré denník nikdy nemal, sa
  stále odmietnu. Takú stratenú rotáciu vráti len admin tímu (review `c78fd19` #2: aktívny admin v
  `users`, alebo admin, ktorým obnovený denník končí): predtým ju nahral ktokoľvek a zlodej
  identitného kľúča člena (bez hesla) si tak podpísal `member.keys` na vlastné kľúče a prevzal miesto
  člena v tíme. Rotujúci admin ju vráti zo svojho zariadenia a potom sa znova prihlási (session
  dokazovala kľúč, ktorý vrátený `member.keys` práve vyradil). 409 (hlava nie je tá, ktorú server ohlásil: súbeh dvoch
  obnovujúcich zariadení alebo lož v pulle) nechá tento pull ako mismatch; ďalší porovná znova.
- **Server R9-F (review `1141a20`):**
  - *Rezervované ID:* `folder.key` ohlási priečinok a kľúč skôr, než prídu ich objekty. Nový objekt
    s takým ID vytvorí len admin alebo autor záznamu, a len ako typ, ktorý denník uvádza (priečinok =
    `node`, kľúč = `dek`); člen si ID predtým obsadil a priečinok admina potom skončil ako „not owner“
    (`team_log.reserved_refusal`).
  - *Replay:* prehratie denníka (studená cache, append, restore) beží vo vlákne mimo event loopu a
    batch robí jednu kópiu stavu (`teamlog.replay_steps`), nie kópiu na každý záznam. Pravidlá
    `users` sa aplikujú po zázname z toho istého prehratia.
  - Overené aj na skutočnej MariaDB (`tests/test_review9_server_mariadb.py`): CAS hlavy cez viac
    workerov bez spoločného zámku a cache (z 8 súbežných appendov prejde 1, ostatné 409), rollback
    `users` pri odmietnutom appende, fronta staged gate, rezervované ID a slučka voľná počas
    studeného replay.

## 6. Klienti

- Denník si držia lokálne (desktop tabuľka `team_log`, web IndexedDB, mobil SQLite) a pri každom
  pulle si stiahnu záznamy od svojej hlavy.
- **Kotva:** prvý záznam (genesis) a jeho hash. Pripnutý `genesis_hash` sa nikdy nemení; iný = stop.
- **Hlava v checkpointe:** posledná videná `(seq, hash)` je súčasť šifrovaného sync checkpointu. Server,
  ktorý pošle kratší denník alebo iný hash na už videnom `seq`, je rollback (rovnako ako
  `server_rollback_head`).
- Rozhodnutia §4.3 robí len prehratý stav. Zmeny tímu (schválenie, grant, odobratie, re-key) najprv
  vyrobia záznamy, ktoré idú v tom istom pushi ako objekty.
- Implementované na desktope (TL4): grant = `access.set` (+ prvý `folder.key`) len pre člena denníka;
  odobratie = `member.remove`; re-key pečatí presne `key_recipients` s úrovňou z denníka a `folder.key`
  ide v tom istom pushi. Zmeny čakajú v `team_log_pending` a pri pushi sa postavia znova na hlavu.
  Trvácnosť (review `1141a20` H4, R9-D): odmietnutý alebo neodoslaný `member.remove` zostáva vo fronte
  aj po reštarte, `revoke_member` hlási `RekeyPending` (nie úspech) a člen je dovtedy lokálne odobratý
  (`queued_for_removal`: žiadny grant, re-key ani reissue mu nič nezapečatí). Zmena z fronty, ktorú
  pravidlá na aktuálnej hlave (napr. `member_exists`) alebo server (`400 team_log_refused` so `seq`
  záznamu) odmietnu, už neblokuje každý push (review `8595ec1` #2, R10-C): presunie sa do
  `team_log_set_aside` s dôvodom, ostatné zmeny a push idú ďalej. `sezam status` ukáže frontu aj odložené
  zmeny, `sezam team-log queue` ich vypíše, `retry` ich vráti do fronty a `discard N|--all` (s
  potvrdením) zahodí. Odložený `member.remove` drží člena v `queued_for_removal`, kým ho admin nezahodí.
  Odmietnutie bez `seq` (prechodné) frontu nemení. Grant
  (`access.set` + prvý `folder.key`) čaká v `team_log_grants` a ide len v jednom atomickom `/api/sync`
  spolu so svojou obálkou, po bežnom pushi; odmietnutá obálka = žiadny záznam v denníku a grant sa
  stiahne, stratená odpoveď = opakovanie nájde záznamy v denníku a pošle len obálku. Re-key: pri každom
  pushi a po posune hlavy (409) sa obálky nového kľúča znova postavia z `key_recipients` aktuálnej
  hlavy (iné zariadenie admina zmenilo prístup) a batch sa pošle znova. Web: odmietnutý
  `member.remove` (400) nechá žurnál, takže prehliadač nezačne iné odobratie a člena nehlási ako
  odobratého; zvyšok Retry pokračuje.
  Pull: v tímovom priečinku platí folder/položka len podľa `teamlog.item_refusal(..., sealing=False)`
  (to isté pravidlo ako server, bez podmienky „nečaká na re-key“, lebo stiahnutá kópia bola zapečatená
  skôr); obálky a staré pravidlá (write envelope, admin podľa servera) tam nerozhodujú. Kľúčom
  priečinka je len `current_key`; staršia generácia sa odpojí, kľúč mimo denníka nikdy nie je kľúčom
  priečinka (najviac tier-2). Pozor pri migrácii (TL6/TL7): existujúce tier-2 kľúče v zdieľanom
  priečinku nie sú v denníku, takže ich položky server aj klient odmietnu, kým nedostanú vlastný priečinok.
- Implementované na webe a mobile (TL5): pull prehrá denník od hlavy z checkpointu (rollback, fork,
  iný genesis = stop), zobrazenie/uloženie v tímovom priečinku rozhoduje `itemRefusal(sealing=false)`,
  `tombstoneRefusal` a `moveRefusal`; odmietnutá zmena nechá doterajšiu kópiu (aj pri full resync).
  Kľúč na zápis je len `currentKey`; zápis, ktorý denník odmietne, sa nezaradí. Web: odobratie člena
  = `member.remove` a re-key presne `keyRecipients` s `folder.key` v tom istom atomickom pushi (len
  zakladajúci admin s kľúčmi, ktoré prehliadač drží). Mobil členov nespravuje (nemá grant ani odobratie).
- **Web a mobil R9-G (review `1141a20`):**
  - `moveRefusal` dostáva `ownPersonal` ako desktop (`sync_writers.py`): vlastná položka
    zapečatená kľúčom autora mimo denníka smie ísť z tímového priečinka do jeho osobného koreňa;
    predtým ju mobil aj web pri pulle zahodili.
  - Mobil: neodoslané zápisy zapečatené kľúčom priečinka, ktorý medzitým dostal re-key, sa po pulle a
    pred pushom zapečatia znova `currentKey` (starý kľúč sa rozbalí len z riadku pod KEK účtu).
    Predtým denník odmietal celý push natrvalo. Úprava riadku, ktorý re-key zapečatil znova na
    serveri, je konflikt ako na desktope.
  - Stránkovaný pull: denník sa posudzuje podľa `team_log_head` **poslednej** stránky (ako desktop
    `_fetch_pull_pages`), nie prvej; objekty neskorších stránok môžu potrebovať záznamy pridané medzi
    stránkami (tímový priečinok zdieľaný počas pullu ostal skrytý).
  - Mobil, QR provisioning: kým sa zariadenie neprevezme na naskenovaný účet, token predošlého
    servera sa naskenovanému serveru neposiela a zlyhanie (aj pred prihlásením) vráti predošlý server
    a reláciu.
  - Testy: `tests/test_team_log_phone_personal_move.py`, `tests/test_review9_web_personal_move.py`,
    `tests/test_team_log_phone_unsent_rekey.py`, `tests/test_team_log_phone_paged_pull.py`,
    `tests/test_review9_web_paged_pull.py`, `tests/test_review9_phone_qr_foreign_server.py`.
- Rozhodovacie vektory `tests/vectors/team_log.json`: scenár = zoznam podpísaných záznamov (+ otázky),
  očakávanie = stav, odpovede rozhodovacích funkcií alebo presná chyba na danom `seq`. Python, JS aj
  Dart musia dať rovnaké odpovede. Súbor sa generuje raz z Pythonu a nikdy sa neprepisuje, aby prešiel
  klient.

### Rotácia identity (opravy review `1141a20`, R9-A)

Desktop pri rotácii identity pridáva `member.keys` do atomického pushu epochy účtu.
Záznam podpisuje starý kľúč a nový podpisuje potvrdenie viazané na aktuálnu hlavu.
Pri CAS retry sa potvrdenie vytvorí znova; pri strate odpovede a reštarte sa už prijatý
záznam neduplikuje. Server odmietne rotáciu člena, ak výsledné kľúče v denníku
nesúhlasia s novou identitou účtu. Nasledujúci re-key používa nový kľúč člena.

Člen (nie admin) si obálky na nový `encryption_pk` zapečatiť nemôže (§4.3.5). Desktop
admina preto po pulle prejde nové záznamy `member.keys` (značka
`team_rotation_sealed_seq`, posúva sa v tej istej transakcii ako obálky) a aktuálny kľúč
každého priečinka, ktorý drží a smie pečatiť, zapečatí členovi na nový kľúč s úrovňou z
denníka; obálka ide von s priečinkom pri ďalšom pushi. Opakovanie po páde nepridá druhú
obálku (vlastná obálka otvorená pre nový kľúč sa počíta) a pri dvoch rotáciách pred pullom
dostane obálku len posledný kľúč. To isté robí prehliadač admina (`sealToRotatedMembers`
po každom pulle, aj pri 304): obálky na aktuálne kľúče priečinkov, ktoré drží, pošle jednou
atomickou dávkou a značku `rotation_sealed:<účet>:<genesis>` v IndexedDB posunie až po
prijatí; obálka toho istého účtu (z desktopu alebo zo stratenej odpovede) otvorená pre nový
kľúč sa počíta, takže sa nezdvojí (capability run 286). Mobil členov nespravuje, nepečatí.
Kým admin nepulluje, člen sa odomkne a nečíta len tímové priečinky. Regresie `test_review9_member_rotation_envelope.py` (desktop, prehliadač, pád,
chyba zápisu, dve rotácie), `test_team_log_phone.py` (`member-rotated-honest`) a
členská vetva `test_review9_team_log_restore.py` (goal #369). Tam sa ukázalo aj, že úplný
resync počas čakajúcej zmeny kľúča nastavil lokálnemu audit DEK, ktorý server nemal,
verziu 1, hoci jeho wrap patril vyššej verzii (verzia je v AAD); odomknutie potom padlo.
Resync teraz ponechá pôvodnú verziu.

Web a mobil nemajú operáciu rotácie existujúcej identity: preberajú identitu zmenenú
na desktope. Webová org recovery mení KEK a prebalí pôvodnú identitu. Regresie
`test_review9_team_identity.py`, `test_team_log_web_rekey.py` a tímový variant
`test_review6_phone_identity_rotation_offline.py` overujú desktop/server retry,
webový zápis a re-key aj telefónny offline zápis po prevzatí rotácie.
Python/JS/Dart odmietajú návrat vyradených kľúčov; opätovné pridanie s poslednými
platnými kľúčmi zostáva možné. Konkrétny odlišný scenár z review „54/55“ ešte
nie je identifikovaný; zhoda nových vektorov sama osebe tento bod neuzatvára.

## 7. Kotva dôvery

**Stav po review `1141a20`:** nasledujúce body opisujú cieľový protokol, nie úplne
implementovanú ochranu. Desktop a web už vydávajú pozvánku s `#g=` iba z lokálne
potvrdeného denníka (serverový hash ignorujú); bez denníka vydajú legacy odkaz bez kotvy.
Desktop `team-log confirm-genesis HASH_ALEBO_POZVÁNKA` uloží nezávisle získanú kotvu
aj pred prvým pullom. Nezmení konfliktný pozorovaný ani potvrdený pin; po reštarte
odmietne iný/chýbajúci genesis aj platne podpísaný cudzí denník. Kým očakávaný denník
nie je stiahnutý, nedovolí tímové zápisy, push, podpisovanie ani vydanie pozvánky.
Dôvera pretrvá pri rotácii zakladateľa. Web onboarding prijíma `#g=`, odmietne
poškodený/duplicitný hash pred registráciou a uloží ho pred čakaním na schválenie.
Kotva je samostatný AEAD záznam viazaný na účet, zapečatený kľúčom prehliadača
nezávislým od KEK; pozorovaný checkpoint ju nevytvára ani nenahrádza. Prvý pull
každej relácie ju načíta a pred rozbalením kľúčov odmietne chýbajúci/iný genesis.
Poškodená kotva či chýbajúci kľúč sú chyba, nie návrat k TOFU; konflikt kotvu
neprepíše. Bez stiahnutého potvrdeného denníka nevydá pozvánku ani nezaradí zápis.
Webový zápis, zmazanie aj presun z/do priečinka známeho denníku teraz vyžaduje
externú kotvu alebo overenú líniu vlastného zakladateľského kľúča, nielen pozorovaný
checkpoint. Kontrola je pred frontou aj sieťou; neodoslaný zápis po reštarte bez
kotvy zostane zachovaný a po obnovení kotvy sa môže odoslať. Osobné zápisy mimo
priečinkov denníka a legacy režim ostávajú použiteľné. Web pri príjme známych tímových
DEK (aj KEK wrap) vyžaduje potvrdený denník a `mayHoldKey`; to isté kontroluje pre
už držané kľúče pri delta pulle. Tímová obálka navyše vyžaduje `envelopeValid`, vlastný
prijímací kľúč a podpis aktuálneho správcu. Bez kotvy neprijme ani legacy obálku
v organizácii s denníkom. Po odobratí prístupu odstráni kľúč aj predtým zobrazený
plaintext; po platnom opätovnom pridelení vie otvoriť uloženú obálku a ciphertext
bez ich opätovného odoslania serverom. Ciphertext a dirty frontu pri odmietnutí nemaže.
Historické obálky po rotácii správcu a úplné pokrytie neosobného stromu ostávajú otvorené.
Desktop `provision-device` už pridáva do QR payloadu fragment `#g=` z lokálne
overenej kotvy; nepotvrdený či očakávaný nestiahnutý denník zastaví vydanie tokenu.
Hash z odpovede servera sa nepoužije ani v legacy účte bez denníka. Mobil prijíma
QR `#g=` a po overení identity uloží kotvu viazanú na účet do systémového zabezpečeného
úložiska, pred odomknutím a pullom. Kotva je nezávislá od KEK a vymieňanej SQLite DB;
pri neúspešnom join sa lokálne dáta obnovia, no explicitná kotva daného účtu zostane.
Konflikt alebo poškodený záznam sa neprepíše. Pull odmieta chýbajúci/iný genesis pred
prijatím dát; cache sa kontroluje pri unlock/reload, kotva aj pred lokálnym zápisom/pushom.
Prázdny nový trezor môže čakať na prvý pull, nie prijímať zápisy bez očakávaného denníka.
Mobil prijíma aj celý odkaz pozvánky (rovnaký server) alebo token s `#g`; fragment
validuje pred sieťou a pin uloží pod kanonickým ID pred uploadom keypairu. Otvorený
trezor prepne z dočasnej lokálnej identity na kanonickú, aby už schvaľovací pull
použil správnu kotvu a príjemcu obálok. Rozpracovanú registračnú odpoveď drží v OS
secure storage pre opakovanie po zlyhaní zápisu pinu/uploadu; zmenený kontext odmietne.
Strata samotnej registračnej odpovede či zlyhanie zápisu tohto journalu ešte nie sú
obnoviteľné touto cestou; onboarding token má existujúcu časovú platnosť.
Mobil pri otváraní KEK obalu známeho tímového DEK vyžaduje externú kotvu alebo
podpísanú líniu vlastného zakladateľského kľúča a `mayHoldKey`. Pozorovaný checkpoint
ani podvrhnuté opätovné pridanie vlastného verejného kľúča nestačia. Rovnaká kontrola
platí pri reload aj offline odomknutí; predošlé DEK bajty v pamäti sa nulujú a
ciphertext zostáva uložený pre legitímne potvrdenie alebo opätovný grant.
Aj lokálny zápis do známeho tímového priečinka (vrátane importu tier-2), zmazanie
či opakovanie tombstone konfliktu vyžaduje externú kotvu alebo vlastnú podpísanú
zakladateľskú líniu pred uložením. Rovnaká kontrola pred pushom zachová neodoslaný
ciphertext po strate kotvy a reštarte; po opätovnom potvrdení možno frontu odoslať.
Kontrola posudzuje zdroj aj cieľ kandidátneho presunu a známe tímové kľúče, nie iba
kľúč v novom payloade. Osobné zápisy mimo denníka ostávajú použiteľné; celý neosobný
strom vrátane dosiaľ nezaznamenaných kľúčov zostáva predmetom R9-C.
Mobil otvára `crypto_box` obálky len pri externe potvrdenom genesis a po kontrole
`envelopeValid`, vlastného príjemcu/kľúča a podpisu aktuálneho správcu. Historické
obálky po rotácii odosielateľa vyžadujú ďalší krok, nie použitie neovereného kľúča.
Mobilné prihlásenie s rovnakou identitou ani čakanie na schválenie už nepotláča
zlyhanie pullu/overenia denníka ako úspešné pripojenie. Obrazovka po odmietnutí
zostáva otvorená s chybou a umožní explicitné opakovanie; kotvu ani dáta nezahodí.
Po registrácii s kotvou, ale pred prvým pullom, online odomknutie aj QR rovnakého
účtu najprv stiahnu iba podpísaný denník a overia externý genesis aj oznámenú hlavu.
Až potom sa odomknú lokálne dáta. Bootstrap nenahrádza existujúcu cache ani checkpoint;
ich poškodenie zostáva fail-closed. Bez siete a bez prvej overenej kópie denníka sa
neodomkne ani offline; odmietnutý bootstrap nemení objekty, kotvu ani checkpoint.
Šifrované dedenie kotvy účtu novým zariadením a úplné web/mobile kontroly bez explicitného
potvrdenia sú stále otvorené v R9-B. Lokálny pin NIE JE prenosná kotva účtu;
web už ponúka „Dôvera tímu“ aj členom so starou pozvánkou bez `#g`. Formulár
nepredvyplní odtlačok: používateľ zadá SHA-256(signing_pk || encryption_pk) získaný
od zakladateľa nezávislým kanálom. Prijme iba genesis alebo jeho dvojpodpísanú líniu
`member.keys`, nie cudzie kľúče vložené cez `member.add`. Uloží šifrovaný lokálny pin,
nezmení checkpoint a znovu posúdi uložený ciphertext aj bez nových serverových dát
(bez `If-None-Match`, pod synchronizačným zámkom). Potvrdenie je viazané na účet,
reláciu a zobrazený genesis. Chyba zápisu pin nezverejní; chyba následného pullu
zachová úspešne uložený pin a umožní opakovanie. Overené sú reštart, starý aj nový
odtlačok po rotácii a skutočné čítanie zdieľaného hesla. Mobil má rovnaký prázdny
formulár v nastaveniach „Dôvera tímu“: pred potvrdením znovu overí cache denníka
voči checkpointu a hlave v pamäti, prijme iba genesis/dvojpodpísanú zakladateľskú
líniu a uloží kotvu do OS secure storage konkrétneho účtu. Potvrdenie je viazané
na reláciu a genesis; starý dialóg po zamknutí nemôže potvrdiť novú reláciu.
Po zápise znovu otvorí lokálny ciphertext bez zmeny checkpointu alebo fronty.
Zlyhaný zápis umožní opakovanie; zlyhané načítanie dát po zápise zachová platnú
kotvu, ale zamkne trezor. Prenosná šifrovaná kotva účtu stále nie je dokončená.
Je pripravený spoločný kodek Python/JS/Dart: plaintext `SZACCT01` (8 ASCII bajtov)
+ Ed25519 seed (32) + X25519 secret (32) + potvrdený genesis (32), spolu 104 bajtov.
Celý obsah je v existujúcej KEK `KEYPAIR_WRAP` obálke, AAD viaže kanonické ID účtu;
nepridáva sa nezávisle odstrániteľné serverové pole ani nový typ sync objektu.
Staré 64/96-bajtové kľúče vracajú výslovne neprítomnú kotvu. Neznáma verzia,
poškodený formát, cudzí účet alebo neplatná obálka sa odmietnu. Testy overujú
obojsmernú výmenu všetkých troch kodekov a skutočné serverové uloženie/obnovu.
Desktopový `KeyPair` už uchová autentifikovanú kotvu cez serverovú obnovu,
serializáciu, `.sezam-key`, rebind/adoption, zmenu hesla, rotáciu identity a Shamir
obnovu. Rebind ju zapíše atomicky s identitou; unlock/recovery ju overia pred
sprístupnením DEK. Rozpor s potvrdeným/pozorovaným genesis alebo lokálnym logom
sa odmietne, nie prepíše. Už ukotvená identita odmietne obnovu starého balíka bez
kotvy. Overené sú storage failure/retry, offline restart aj serverová rotácia so
stratenou odpoveďou. Nový desktop zakladateľa aj člena obnoví skutočné heslo vrátane
offline reštartu. `DEKManager.unlock_dek` pred KEK aj cache overí dôveru a
`may_hold_key`; cudzie tímové kľúče otvára cez platnú neodvolanú obálku podľa
`envelope_valid` a aktuálneho kľúča správcu z overeného denníka. Cache obálky sa
pri čítaní znovu kontroluje; odmietnutie vynuluje otvorené kľúče, nie ciphertext.
Testy pokrývajú odobratie/opätovný grant, odstránenie/re-add člena, poškodenú obálku,
nesúlad práv, chýbajúcu dôveru aj rovnaké odmietnutie KEK obalu. Vlastníctvo DEK pri
zmene hesla a migrácii sa naďalej zisťuje iba KEK, nie úspešným otvorením obálky.
Zakladateľ počas neodoslanej rotácie zachová kotvu cez starú identitu v šifrovanom
žurnáli. Desktop pri prijatí tímovej obálky uloží podpis a hlavu denníka, iba ak
podpis overí aktuálny kľúč správcu. Po jeho rotácii otvára presne túto obálku
kľúčom z overeného prefixu denníka; znovu overí podpis ciphertextu, ID, DEK,
príjemcu a verzie aj historické a aktuálne oprávnenia. Dôkaz prežije offline
reštart, ale nedovolí nový ciphertext podpísaný vyradeným kľúčom. Odvolanie,
strata dôvery či poškodený dôkaz stále odmietnu čítanie vrátane cache.
Desktopová rotácia správcu znovu vydáva obálky aktuálnych držaných tímových DEK
podľa príjemcov, úrovní a kľúčov overeného denníka, aj keď lokálne chýbajú staré
obálky alebo `known_keys`. Nové obálky sú v atomickom epochovom zápise rotácie;
známe staré obálky sa v ňom stiahnu. Nepotvrdený denník alebo priečinok čakajúci
na rekey rotáciu odmietne. Nový príjemca tak dostane aktuálnu obálku, nie výnimku
pre historický kľúč. Rotácie z web/mobile a staré už dokončené rotácie bez nového
vydania zostávajú otvorené; skúšanie serverových archívnych kľúčov nie je povolené.
Web už prijíma existujúcu autentifikovanú kotvu pri novom prihlásení, otvorení
cache, obnove zastaranej cache a importe desktopového `.sezam-key`. Ukladá ju
pred prvým pullom do nezávislého account-bound device pinu; chyba zápisu zamkne
reláciu a umožní retry po reštarte. Kotva sa zachová pri Shamir obnove aj v
šifrovanom žurnáli zmeny KEK vrátane výpadku pred odoslaním a straty odpovede.
Náhrada už ukotvenej otvorenej cache odmietne odstránenú alebo inú kotvu ešte
pred prepísaním keypairu. Legacy účet bez kotvy nezíska dôveru z pozorovaného logu.
Testy overujú skutočné zdieľané heslo, nový profil, restart a výsledný serverový
balík otvorený Pythonom. Mobil už otvára balík pri online/offline/biometrickom
prihlásení, pripojení účtu, provisioningu a prevzatí rotácie. Autentifikovanú kotvu
potvrdí pred otvorením tímových dát; null legacy kotvu nevytvára. Migračné žurnály
uchovávajú celú šifrovanú obálku, nie iba extrahované kľúče. Reálne testy overujú
nového člena, cudzí genesis, konflikt pinu, zlyhaný zápis a retry, aj prevzatie
rotácie s neodoslanou položkou a prerušením Keychain zápisu. Mobilný import
`.sezam-key` dekóduje kotvu, overí obe verejné časti aj zhodu s otvoreným trezorom.
Náhodné ID desktopovej zálohy je iba šifrovací kontext: obálku vrátane kotvy
prebalí na kanonické ID otvoreného účtu a zachová ju v migračnom žurnáli.
Testy overujú skutočné zdieľané heslo, offline/biometrické otvorenie, Keychain crash,
konflikt pinu, chybu úložiska a cudzie kľúče bez zmeny pôvodného trezoru.
Import a náhrada otvoreného mobilného účtu odmietnu odstránenie alebo zmenu kotvy
oproti autentifikovanej lokálnej obálke ešte pred migráciou DEK. Samostatný pin pri
legacy balíku nie je dôvod na odmietnutie. Testy overujú nezmenené dáta/Keychain,
offline reštart a legitímny retry rotácie s neodoslanou položkou. Pri zamknutej
zastaranej cache mobil najprv otvorí pôvodnú obálku lokálnym KEK; ak treba, vyžiada
predchádzajúce heslo. Kontinuitu overí pred pinom a migráciou aj bez lokálnych DEK.
Password recovery pôvodnú obálku nemaže. Same-key connect po autentifikácii uloží
celý balík a KDF parametre žurnálom v transakcii s migráciou DEK a checkpointu.
Pamäť nasleduje nový KEK, automatické zamknutie sa neobíde. Reálne testy overujú
rovnaký aj zmenený KEK, odmietnutie downgrade/conflictu, sieťové zlyhanie pred
migráciou, Keychain crash/restart, offline/biometrické čítanie aj neodoslanú položku
na novom desktope. QR provisioning prijíma kotvu aj zo šifrovaného balíka bez
fragmentu; ak sú prítomné obe, musia sa zhodovať ešte pred zápisom device pinu.
Odmietnutý konflikt nesmie zanechať cudzí pin, ktorý by zablokoval legitímny retry.
QR testy pokrývajú nový telefón aj zlúčenie lokálnych dát, chýbajúci/cudzí denník,
sieťový a Keychain výpadok, retry a offline obnovu pinu zo zachovaného balíka.
QR opätovné pripojenie rozpozná vlastný účet podľa kanonického ID aj po rotácii
identity. Zamknutá existujúca cache overí pôvodnú obálku heslom a lokálnym KDF;
ak ju heslo neotvorí, vyžaduje lokálne odomknutie, aj bez DEK, pred prijatím kotvy.
Otvorený účet migruje DEK/checkpoint a celý balík cez žurnál, znovu podpíše
neodoslané objekty novou identitou a rešpektuje automatické zamknutie počas siete.
Testy overujú nový desktop čítajúci neodoslanú položku, downgrade/conflict bez
mutácie, autentifikačný výpadok a Keychain crash/restart s legitímnym retry.
Mobilná pozvánková registrácia porovná fragment s autentifikovanou kotvou lokálnej
obálky a samostatným pinom ešte pred spotrebovaním pozvánky. Bez fragmentu zachová
existujúcu kotvu. Prebalenie na kanonické ID zachová celý šifrovaný balík; retry po
zlyhaní zápisu pinu alebo uploadu zachová registračný zámer zapísaný pred sieťou.
`auth/registration-resume` vyžaduje čerstvú jednorazovú výzvu podpísanú aktuálnym
kľúčom a vydá iba `keypair_upload` token, nikdy plnú reláciu pending účtu.
Pred uploadom je uložená presná obálka; po strate odpovede retry porovná jej hash
so serverom a už prijaté kľúče neprepíše. Retry overí aj aktuálny KEK a kotvu obálky.
Prvý upload sa znova overuje pod zámkom účtu v zapisovacej transakcii.
Reálne testy pokrývajú stratu odpovede, vypršaný token, Keychain výpadky a nový
desktop čítajúci zdieľané heslo po reštarte. Zamknutý preapproval restart pokračuje
podpisom z heslom overenej lokálnej obálky bez odomknutia dát; zámer zostáva do
schválenia a bežné Pripojiť ho obnoví. Pri rozpracovanej registrácii potvrdená kotva
platí aj pred uložením URL relácie; čisto lokálny import bez registrácie tým nemení režim. Osem crash/retry scenárov zachová vlastnú neodoslanú položku, odmietne
nesprávne heslo/kontext pred sieťou a falošný denník pred odomknutím. Reálny UI
test overuje pokračovanie pollingom. Bežné online prihlásenie tiež ukončí registračný zámer, ale až po plnej autentifikácii, overení denníka a otvorení trezoru. Cudzí registračný kontext odmietne pred sieťou; výpadok alebo falošný denník zámer zachová. Reálny test overuje následné Pripojiť aj neodoslané a zdieľané heslá na novom desktope; nejde o dokončenie všetkých aplikačných ciest.
**Publikovanie kotvy (desktop):** každá zmena hesla/KDF/identity na desktope vloží do
balíka účtu genesis, ktorému zariadenie dôveruje nezávisle od servera (explicitný pin
`#g=`/`confirm-genesis`/ukotvený balík, vlastná zakladateľská línia alebo potvrdený
odtlačok zakladateľa), a v tej istej transakcii ho zapíše ako potvrdený pin; iba
pozorovaný genesis sa nepublikuje. **Ochranu nového zariadenia dáva len zmena na NOVÉ
heslo** (capability run 264): obal kľúčov neviaže epochu ani kotvu, takže pod tým istým
heslom by server novému zariadeniu podstrčil starší salt + `encrypted_keypair` bez
genesis, otvorili by sa a pin by chýbal. Nové heslo staré obaly neotvorí. **Nikdy
späť na heslo spred kotvy** (capability run 269): ukotvený balík `SZACCT02` (= `SZACCT01`
+ `count u8` + najviac 8 stavov po 60 B: salt 16, Argon2 time/memory/lanes u32be,
SHA-256(`sezam-pre-anchor-kek-v1` ‖ KEK)) zaznamená stavy hesla, ktoré otvárali balík
bez genesis a ktoré zverejňujúce zariadenie pozná: stav opustený pri zverejnení a
(capability run 273) každý starší stav, ktorý toto zariadenie opustilo bez kotvy —
desktop (zmena hesla, Shamir obnova, prevzatie zmeny z iného zariadenia) ho drží vo `vault_meta.pre_anchor_history`, web
(Shamir obnova) v IndexedDB `pre_anchor_history:<user_id>`, mobil (prevzatie zmeny z
iného zariadenia) v `sezam_pre_anchor_history`; zverejnenie ich vloží všetky (najviac 8,
najnovšie). **Hranica:** stav, ktorý zverejňujúce zariadenie nikdy nevidelo (zmena
hesla na inom zariadení pred kotvou, ktorú toto neprevzalo; účty spred tejto verzie),
klient rozpoznať nevie — server s takým starým balíkom ho môže podstrčiť, ak sa
používateľ k tomu heslu vráti. Preto nepoužívať znova žiadne skoršie heslo. Každá
ďalšia zmena hesla, rotácia identity a Shamir obnova na desktope aj webe (mobil mení
heslo len zverejnením) odmietne nové heslo, ktoré v ktorejkoľvek forme NFC/typed/NFD
odvodí zaznamenaný KEK; ponechanie hesla (KDF upgrade) nie je návrat. Stavy sa
prenášajú pri každom prebalení a rebind ich zlúči s lokálnymi, server ich teda
nevymaže; spoločné vektory Python/JS/Dart (`tests/test_pre_anchor_cross_client.py`).
Preto
`sezam team-log publish-anchor` vyžaduje nové heslo (rovnaké odmietne, nič neodošle)
a pošle jeden atomický epochový push (žiadny nový mutovateľný endpoint). Zmena s
rovnakým heslom (KDF upgrade, rotácia identity) kotvu do balíka tiež vloží, ale
proti serveru ju nechráni. Zlyhanie zápisu nič nezmení, strata odpovede sa dopošle z
journalu; nový desktop s novým heslom denníku dôveruje a otvorí zdieľané heslo, server
vracajúci riadok účtu spred kotvy sa s novým heslom neotvorí. **Web:** obnova zo Shamir
podielov (nové heslo) vloží pin prehliadača; potvrdenie zakladateľa so súčasným a novým
heslom účtu ho zverejní zmenou hesla (nový salt a KEK, vlastné DEK prebalené,
`current_auth_proof` starého hesla, v journale zapečatený pod novým KEK pre dokončenie
po strate odpovede). Rovnaké nové heslo, zlé súčasné heslo, neodoslané zmeny aj účet
s vlastnou org recovery (zmena hesla v prehliadači by ju zneplatnila) nič neodošlú.
Účet bez vlastného DEK (člen, ktorý len číta zdieľané priečinky) smie posunúť epochu
bez DEK. **Bez pinu** (účet ukotvený len na inom zariadení bez zmeny hesla, alebo
návrat starého obalu so starým heslom) nové zariadenie nedôveruje žiadnemu denníku,
neprijme zdieľaný kľúč ani nezapíše tímový záznam, kým používateľ nepotvrdí odtlačok
zakladateľa z nezávislého kanála alebo nepríde pozvánka `#g=`. Zvyšok: opätovné
použitie hesla spred ukotvenia znovu otvorí starý obal. **Mobil:** v nastaveniach
„Dôvera tímu pre nové zariadenia“ (súčasné + nové heslo) zverejní zakladateľa, ktorého
telefón sám potvrdil: lokálne overí súčasné heslo, odmietne rovnaké heslo, nepotvrdený
denník, neodoslané zmeny a vlastnú org recovery, potom jedným atomickým epochovým
pushom pošle nový salt, balík s genesis, vlastné DEK na ďalšej verzii a
`current_auth_proof`; zmenu prevezme ako zmenu z iného zariadenia (DEK, checkpoint,
Keychain, biometria). Stratenú odpoveď rozozná podľa saltu, ktorý server podáva. Celá dvojica account-KEK adoption + rebind v CLI nie je jednou
transakciou; pri konflikte sa môže KEK zmeniť pred odmietnutím rebindu.
Prehratie celého platného starého balíka na novom zariadení sa nedá odlíšiť od
legacy účtu iba serverovým `key_epoch`: starý balík nesmie automaticky získať
dôveru. Kotva genesis tiež nenahrádza lokálnu kontrolu rollback/fork hlavy.
Desktop už zastaví pull, full resync, push a podpisovanie zmien známeho nepotvrdeného
logu; samotný denník zostáva dostupný cez `team-log status`/`confirm-founder`.
Neúspešný pull neposunie checkpoint ani neprijme objekty; po potvrdení a reštarte
sa dá dávka opakovať. Obálky známych tímových kľúčov kontroluje `envelope_valid`,
priradenie aktuálneho kľúča priečinku `may_hold_key`. Desktop blokuje aj lokálne
tímové CRUD a obnovu z koša pri nepotvrdenom denníku; osobný strom ostáva použiteľný.
Web/mobil, prenos kotvy a ich už uložené dáta ešte vyžadujú kontrolu.
Desktop už zachová dôveru aj pri odtlačku zakladateľa potvrdenom medzi
dvoma rotáciami: hľadá ho aj v overených `member.keys`, nie iba v genesis a na
konci reťaze. Desktop aj web pritom uznávajú iba kľúče nadväzujúce dvojpodpísanou
rotáciou na genesis: samotné odobratie a nové `member.add` s verejným kľúčom
skutočného zakladateľa nedá útočníkovmu genesis dôveru. Samostatná TOFU kontrola
podpisovateľov objektov tým nie je obídená. CLI `confirm-founder` prijíma aj
odtlačok z medziľahlej alebo aktuálnej dvojpodpísanej rotácie a `status` vypisuje
všetky takto nadväzujúce odtlačky. Potvrdenie pretrvá po reštarte.
Mobil pri pulle kontroluje `envelope_valid` pre živé obálky kľúčov z denníka pred
zápisom dávky; odmieta podvrhnutú úroveň, chýbajúci prístup a neadmina ako
podpisovateľa. Pre vlastné obálky porovnáva aj lokálny verejný šifrovací kľúč.
Pri odomknutí mobil načíta denník pred kľúčmi a `mayHoldKey` kontroluje aj pred
rozbalením skôr uloženého tímového DEK. Odobratý člen ho už nepoužije ani po
opätovnom odomknutí; šifrované riadky na disku ostávajú zachované (nejde o vymazanie
už prezradeného kľúča). Práva a priradenia kľúčov tímových priečinkov pochádzajú
z denníka, nie z nepodpísaných `access_level` alebo `parent_ref` v lokálnej cache.
Mobil pri odomknutí aj opätovnom načítaní overí podpisy cache a jej nadväznosť
na šifrovaný checkpoint aj hlavu v pamäti, ešte pred použitím kľúčov. Poškodený,
prázdny, odstránený pripnutý, skrátený alebo rozvetvený denník trezor zamkne;
nezmení šifrované dáta ani checkpoint a neprepne na staré pravidlá bez denníka.
Platné pokračovanie pred uložením novšieho checkpointu aj legacy trezor bez
denníka/pinu ostávajú použiteľné. To ešte nerieši nepotvrdený mobilný genesis,
jeho potvrdenie a prenos kotvy; tieto časti R9-B zostávajú otvorené.

- **Admin, ktorý denník založil:** genesis podpísal sám, kotvu má.
- **Nový člen:** pozvánka (odkaz/QR od admina mimo servera) nesie `genesis_hash` (vo fragmente `#g=`,
  server ho nevidí). Klient pri registrácii denník stiahne a genesis porovná. Nesedí = stop.
- **Existujúci člen alebo zariadenie bez pozvánky:** prvý videný genesis sa pripne (TOFU) a klient
  zobrazí odtlačok zakladajúceho admina na potvrdenie (ako `confirmed_member_keys`). Kým nie je
  potvrdený, denník nesmie autorizovať prijímanie kľúčov ani tímové zápisy. Desktop
  konzervatívne zastaví celú synchronizáciu, nie iba tímovú časť; načítanie denníka
  na porovnanie odtlačku je samostatná operácia a nepreberá objekty.
- **Admin pridávajúci člena:** `member.add` sa vystaví len pre kľúč s potvrdeným odtlačkom
  (dnešné `MemberKeyUnconfirmed`).

## 8. Čo denník nerieši a hranice

- **Zadržanie:** server môže prestať posielať nové záznamy. Klient to zistí, keď uvidí objekt alebo
  envelope s kľúčom, ktorý v denníku nie je (§4.3.2: odložiť), keď `team_log_head` v pulle nesedí
  so stiahnutým denníkom, alebo keď hlava zaostáva za tým, čo sám pridal. Úplne skrytý odobratý člen
  (server mu ďalej posiela staré objekty) zostáva limitom modelu bez druhého kanála — rovnako ako dnes.
- **Admin v spolku so serverom** môže pridať koho chce; denník to len urobí viditeľným a podpísaným.
- **Nerieši:** dostupnosť servera (H6/H7), org recovery pri výpadku siete (H9), neaktuálny stav
  v inom procese (H10 — rieši generácia trezoru, TL6), audit (H11).
- **Generácia trezoru (TL6, implementované):** `vault_meta.vault_generation` dostane nové ULID pri
  každej zmene toho, čo si proces načíta pri odomknutí (`kek_dek_id`, Argon2 soľ/parametre,
  `encrypted_keypair`, `signing_pk`, `encryption_pk`, `user_id`, `key_epoch`, `server_url`), v tej
  istej transakcii (`VaultDB.set_meta`). Proces si generáciu pripne pri otvorení a odomknutí; prijme
  len ňu a tie, ktoré sám zapísal (rollback nič nepokazí, generácia nie je počítadlo). Inak
  (`VaultChangedElsewhere`) nezabalí DEK, nezapíše audit, nesynchronizuje a nezmení ani tieto kľúče —
  kým sa trezor nezamkne a neodomkne. `KeyChangedElsewhere` a `IdentityChangedElsewhere` sú jej
  podtriedy. Desktop; web a mobil majú jeden proces na trezor.

## 9. Migrácia existujúcej organizácie

1. Server s novou verziou: denník prázdny, dnešné správanie.
2. Admin (desktop `sezam team-log init`, GUI, web) vyrobí v jednom pridaní:
   - `genesis` so svojimi kľúčmi,
   - `member.add` pre každého aktívneho používateľa s **potvrdeným** odtlačkom (nepotvrdených sa
     najprv spýta; kto nepotvrdený ostane, nedostane nič a admin ho vidí v zozname),
   - `folder.key gen 0` pre aktuálny kľúč každého zdieľaného priečinka, ktorý tento admin otvorí,
   - `access.set` podľa envelope, ktoré vytvoril tento účet (úroveň len ak ju vie doložiť, inak `read`
     — princíp H3); cudzie envelope sa do denníka nedostanú.
3. Ostatní admini dostanú `member.add role=admin` od zakladajúceho admina po potvrdení odtlačku.
4. Klienti pri ďalšom pulle denník stiahnu (§7) a od tej chvíle rozhodujú len z neho. Kto má kľúč
   bez záznamu v denníku, pri najbližšom re-key ho nedostane.

Implementované na desktope (TL6, `src/sezam/vault/team_migration.py`, `sezam team-log`):
- `sezam team-log init [--admin ID]... [--fingerprint ID=FP]...` urobí body 2–3 v jednom pridaní
  (najprv pull). Admin denníka je len zakladajúci a kto je menovaný `--admin` (s potvrdeným kľúčom);
  príznak admina zo servera nič nedokladá a server sa potom riadi denníkom (ostatní admini stratia
  admina). Zakladajú sa len priečinky s vlastným kľúčom (scope `folder`), ktorých **aktuálny** kľúč
  má obálku pre iný účet; root a iné zdieľané kľúče sa vypíšu a do denníka nejdú. Najviac 1000
  záznamov (limit servera na jedno pridanie).
- `sezam team-log add-member ID [--fingerprint FP]` neskôr pridá schválený účet
  s potvrdeným odtlačkom (len dôveryhodné zariadenie admina).
- `sezam team-log status` ukáže hlavu, zakladateľa s odtlačkom, či je denník dôveryhodný, členov,
  priečinky (generácia, prístup); `sezam team-log confirm-founder FP` ho člen potvrdí (§7).
- Review `8595ec1` (R10-C):
  - Založenie skryje staršie položky autora, ktorému denník nedá zápis do priečinka (envelope `read`
    alebo nepotvrdený kľúč). `init` ich pred podpisom vypíše (položka, autor, priečinok, dôvod
    `read`/`unconfirmed`/`no access`) a pýta sa; po podpise to zopakuje. Cesta von:
    `grant-access USER_ID FOLDER --write` v denníku zmení len úroveň (`access.set`).
  - Klienti si pulled kópiu odmietnutú len pre chýbajúci zápis odložia (desktop meta
    `writes_without_log_write_access`, mobil nastavenie `team_log_writes_without_access`) a pri každom
    pulle ju posúdia znova; keď denník autorovi dá zápis, položka sa ukáže bez plného resyncu. Web ju
    posúdi pri ďalšom plnom pulle (prihlásenie).
  - Založenie, ktoré prehralo súboj s iným zariadením (`founded_elsewhere`), sa odloží a nezníži
    nikomu `write` na `read`; zastaraný `member.add` z fronty člena odobraného medzitým
    (`removed_meanwhile`) neoživí.

## 10. Poradie implementácie

| Krok | Obsah |
|---|---|
| TL1 | `src/sezam/teamlog.py` (kódovanie, podpis, prehratie, §4.3) + vektory + Python runner |
| TL2 | `web/static/js/teamlog.js`, `mobile/lib/services/team_log.dart` cez tie isté vektory |
| TL3 | server: tabuľka, endpointy, CAS, overenie, odvodené `write_acl`/`is_admin`/`status` |
| TL4 | desktop: záznamy pri tímových zmenách, pull/kotva/checkpoint, rozhodnutia z denníka |
| TL5 | web a mobil: to isté |
| TL6 | migrácia, generácia trezoru medzi procesmi, dokumentácia |
| TL7 | osobný koreň, jeden admin, tier-2 → samostatný priečinok |

**Jeden admin (TL7, implementované):** bez denníka server druhého admina nevyrobí (admin vzniká len
bootstrapom prázdneho servera, registrácia dáva `is_admin = 0`). S denníkom server odmietne pridanie,
po ktorom by mal denník viac ako jedného aktívneho admina (`admin_policy_refusal` v jadre,
`team_log_refused`, nič z pridania neostane). Rolu možno odovzdať: `member.role` nový admin + `member.role`
starý → `member` v tom istom pridaní. Desktop zakladá denník so sebou ako jediným adminom
(`sezam team-log init` už nemá `--admin`, `add-member` nemá `--admin`). Záznamy jadra môžu prejsť cez
dvoch adminov (odovzdanie v jednom pridaní), hlavu s dvoma aktívnymi adminmi však odmietne každý klient
(review 1141a20: desktop `_sync_team_log`, web `syncWebTeamLog`, mobil `syncTeamLog` — `admin_policy_refusal`
/ `adminPolicyRefusal`, vektory `two_admins_at_the_head`). Obmedzenie padne, keď budú tím z denníka
spravovať všetci klienti (desktop GUI, web pečatí len z denníka, ktorý sám založil).

**Jediný admin a jeho obnova (review 8595ec1 #3/#4, R10-D):** `sezam team-log hand-over USER_ID
[--fingerprint FP]` odovzdá rolu potvrdenému členovi (`member.role` pár v jednom pridaní); `sezam status`
ukáže `lone_admin_without_recovery`, kým denník nemenuje kľúč obnovy jediného admina, a radu
`allow-key-reset` (nemožnú — iný admin nie je) v organizácii s denníkom nedá. Kľúč Shamir obnovy admina
menuje záznam `org.recovery`: desktop ho pridá pri `org-recovery-setup` (aj nahradí starší) a pri pushi,
ak denník pre admina nemenuje žiadny; web pri nastavení obnovy (`anchorWebOrgRecovery`; keď ho denník
neprijme, povie to adminovi, nie len konzole). Server po obnove
zo zálohy staršej ako registrácia berie dôkaz obnovy (`/org-recovery/challenge`, `key_change_needs_proof`)
aj pre kľúč, ktorý menuje denník, a blob podpísaný týmto kľúčom uloží aj bez hesla. Platí však vždy len
jedna obnova, najnovšia (review 4acfdde R11 #2, `_current_recovery`): uložený blob má poradie hlavy
denníka v čase uloženia (`org_recovery_blobs.log_seq`), kľúč z denníka poradie svojho posledného záznamu
`org.recovery`. Nastavenie, o ktorom denník nevie, tak zneplatní diely staršieho kľúča, ktorý denník ešte
menuje, nastavenie iného admina (`replace_other_admin`) zneplatní diely nahradeného a denník vrátený na
server obnovený zo zálohy prebije starší blob zálohy. `/org-recovery/blob?recovery_signing_pk=` podá blob
len aktuálneho kľúča. Blob z webu bol len
na serveri: desktop admina si pri pushi (`adopt_logged_org_recovery`) zabalí KEK aj lokálne na X25519 tvar
kľúča, ktorý menuje denník a ktorý server ešte drží (`/org-recovery/status` `recovery_signing_pk`), takže
`sezam org-recovery` s webovými podielmi funguje aj po obnove servera a blob vráti. Samotný blob
(webový formát, nonce ‖ XChaCha20-Poly1305 KEK, ktorý otvoria podiely) nesie záznam `org.recovery.wrap`
(capability run 316): web ho pridá spolu s `org.recovery` aj po obnove podielmi (nový KEK, ďalšia epocha;
review 4acfdde R11, nízke — dovtedy denník nechal zábal zabudnutého hesla), desktop pri pushi z
`org_recovery_server_wrap` (nastavenie aj prebalenie po obnove; novší v denníku nechá). Denník vráti na obnovený server zariadenie
ktoréhokoľvek člena, a `/org-recovery/blob` (`?recovery_signing_pk=`, web ho posiela) aj `/status` ho
podávajú, keď tabuľka blob nemá alebo drží iný kľúč, než denník menuje pre jeho admina; `stale` z epochy
v zázname. Admin len s webom sa tak obnoví v prehliadači aj bez desktopu. Mobil obnovu nenastavuje.

**Znovuprijatie člena po obnove spred jeho rotácie (review 8595ec1, nízke, R10-F):** server obnovený zo
zálohy spred rotácie identity člena pozná len kľúč K1, ktorý denník vyradil (`member.keys` → K2), a
zariadenie s K2 je stratené. K1 číta len denník a kľúče (capability run 300) a `member.keys` by musel
podpísať K2. Cesta: admin `sezam allow-key-reset USER_ID` (grant 1 h) → relácia K1 dostane
`key_rotation` scope (pull, push rotácie) → člen `sezam rotate-identity` na kľúče K3, ktoré denník nikdy
nevidel (server `_readmission_rotation`: K1 vyradený, K3 nevidený, živý grant sa spotrebuje, heslo ako
pri každej rotácii; klient `member.keys` nepridá, lebo starý kľúč je vyradený; vlastné objekty podpísané
K1 zariadenie číta len pre vlastný účet) → admin `sezam team-log readmit USER_ID [--fingerprint FP]`
(`readmit_member`): odtlačok K3 sa pýta vždy, `member.remove` + `member.add` (K3, tá istá rola) v jednom
pridaní (re-add po odobratí v jednej dávke nie je `removed_meanwhile`), re-key priečinkov člena (stratené
zariadenie ich kľúče malo) a `access.set` + obálky na pôvodnú úroveň; prerušené dokončí druhé spustenie
(`team_log_readmit`). Bez grantu zostáva K1 len na čítanie denníka. Pár ide na server celý alebo vôbec
(review 4acfdde R11 #4): zmeny jedného pridania nesú `_batch` a odmietnutá zmena odloží aj ostatné z
neho (`_with_batch_partners`), takže samotný `member.remove` neodíde; readmit odmietnutý pár zahodí a
povie, že sa nič nezmenilo a ako ho spustiť znova. Server pri `member.remove`, po ktorom v tej istej
dávke ide `member.add` toho istého člena, nemaže jeho share linky. `member.role` admin (odovzdanie) server
prijme len na aktívny účet, ktorý sa prihlasuje kľúčmi z denníka (R11 #5): nie na účet bez riadku v
`users` ani na člena, ktorý čaká na readmit.

**Odovzdanie admina (review 1141a20):** po `member.role` admin → `member` platí, čo starý admin zapísal.
Mimo tímových priečinkov sú admini všetky aktívne účty, ktoré denník kedy urobil adminom (desktop
`log_admins`, web `webLogAdmins`, mobil `logAdmins`), nie podpisovatelia ani `is_admin` zo servera. V tímovom
priečinku jadro drží `former_admins` (priečinok → admini odovzdaní počas jeho aktuálneho kľúča): stiahnutá kópia
(`item_refusal(..., sealing=False)`) zapečatená aktuálnym kľúčom je platná, nový zápis nie. Re-key priečinka,
odobratie člena alebo priečinok založený neskôr to končí (vektory `handover_*`). Pole nie je v `to_json`,
staré vektory ostali bajt po bajte.

**Strom mimo tímových priečinkov s denníkom (review 1141a20 H5/H6):** neplatí nepodpísaný `access_level` ani
admin podľa podpisov; uzol najvyššej úrovne je adminov (koreň organizácie) alebo osobný strom podpisovateľa
pod jeho vlastným kľúčom; pod prvou úrovňou stromu organizácie zapisuje a maže len admin (desktop
`sync_writers`, web a mobil `unauthorizedWrites`). Web berie vlastný koreň podľa toho, či ho otvorí vlastný KEK,
nie podľa podpisovateľa kópie (prepodpísaný koreň „Eve“), a pri odobratí člena re-keyuje cez denník aj
priečinok, ktorého aktuálny kľúč člen drží obálkou spred denníka.
Kľúč iného účtu prichádza s denníkom len cez denník: obálku iného účtu na kľúč bez `folder.key` klient
neprijme (desktop `_apply_envelope`, web `keyEnvelopesForUser`; mobil otvára len obálky, ktoré schváli
`envelopeValid`) a re-key priečinka mimo denníka nový kľúč nikomu inému nezapečatí (§9). Koreň
organizácie (scope `root`) sa nezdieľa a do denníka nejde. Platí iba obálka, ktorú podpísal tento účet.

**Osobný koreň (TL7):** osobné veci člena nevisia pod koreňom organizácie. Osobný priečinok je uzol
najvyššej úrovne (`parent_ref` NULL), jeho meta je zapečatená DEK-om autora (scope `personal`, bez
obálky) a nesie `personal: true`. Pod ním má autor svoje priečinky a položky vrátane tier-2.
- Koreň organizácie je uzol najvyššej úrovne, ktorý nie je osobný. Klient pri hľadaní koreňa
  (desktop `_adopt_server_root`, web `rootNodeId`, mobil) osobné korene preskočí; cudzie osobné
  korene sa nedajú otvoriť a nezobrazia sa.
- Server: člen smie vytvoriť uzol najvyššej úrovne len zapečatený vlastným DEK-om (ako začiatok
  osobného stromu, `own_seal`); položka bez priečinka a uzol najvyššej úrovne s cudzím kľúčom
  ostávajú odmietnuté. Osobný koreň nie je tímový priečinok, pravidlá denníka preň neplatia.
- Tier-2 položka v tímovom priečinku sa nevytvorí (jej kľúč nie je v denníku, nikto iný ju
  neprečíta a server ju odmietne): patrí do samostatného priečinka s vlastným kľúčom, t. j. do
  osobného koreňa, alebo do nového tímového priečinka s `folder.key` v denníku, zdieľaného tým, kto
  ju smie čítať. Desktop (`Vault._refuse_tier2_in_team_folder`) odmietne vytvorenie, zmenu na tier 2,
  úpravu aj presun tier-2 položky do tímového priečinka; von do osobného koreňa ju presunúť smie.
  Web ani mobil tier-2 nevytvárajú; starú tier-2 položku v tímovom priečinku (spred denníka)
  neukážu ani neupravia (jej kľúč nie je v denníku; úprava by ju zapečatila kľúčom priečinka),
  von ju presunie desktop (`tests/test_team_log_tier2_phone.py`). Kľúč v strome osobného koreňa (koreňa aj tier-2 položky) ide na server bez
  `parent_ref` (server berie kľúč člena len tak); druhé zariadenie ho podľa toho, čo pečatí,
  označí `tier2` (`_derive_unbound_scope`).
- Osobný strom má jeden kľúč: priečinok pod osobným koreňom nedostane vlastný DEK, berie kľúč
  rodiča (desktop `create_node`, rovnako ako web a mobil). Starší desktop mu dával vlastný kľúč
  s `parent_ref` na priečinok; ten server členovi odmietne, takže meno priečinka na server prišlo,
  ale jeho položky boli na ostatných zariadeniach nečitateľné. Pri odomknutí desktop takýto kľúč,
  ktorý server nemá, zloží do stromu (`personal_root.fold_personal_tree_keys`): položky, mená
  podpriečinkov aj históriu prepečatí kľúčom rodiča a kľúč zahodí. Kľúč, ktorý server má, ostáva.
- Presun priečinka cez hranicu osobného stromu (review `1141a20`, R9-E): desktop `move_node`
  prepečatil len meno presúvaného priečinka. Von z osobného stromu ostali jeho položky,
  podpriečinky a história pod osobným kľúčom vlastníka (v tímovom priečinku nečitateľné, server
  ich odmieta), dnu pod tímovým kľúčom, ktorý drží každý člen pôvodného priečinka. Teraz
  (`personal_root.moved_subtree_keys`/`reseal_moved_subtree`) v jednej transakcii: priečinok bez
  vlastného kľúča berie kľúč nového rodiča, priečinok s vlastným kľúčom ho ponechá, v osobnom
  strome berie každý priečinok kľúč vlastníka; položky, ich história a mená podpriečinkov sa
  prepečatia. Tímový priečinok denníka do osobného stromu nejde (`ValueError`; jeho členovia by ho
  stratili), presúva sa jeho obsah. Osobný koreň pri presune ponechá vlastný kľúč
  (`tests/test_review9_move_node_reseal.py`).
- Kto zapísal uzol najvyššej úrovne zapečatený vlastným kľúčom bez priečinka (osobný koreň), nie je
  preto pre klienta „admin podľa servera“ (heuristika bez denníka: desktop `_unauthorized_writes`,
  web/mobil `unauthorizedWrites`).
- Server starší ako TL7 (`d150605`) odmietne osobný koreň člena ako `write_acl denied (top-level)`
  (review `4acfdde` R11, nízke). Desktop si koreň zapíše (`personal_roots_waiting_for_server`),
  `sezam push` a `sezam status` povedia, že osobné priečinky aj ich položky čakajú na aktualizáciu
  servera; ostatné ide ďalej a po aktualizácii ich ďalší push pošle
  (`tests/test_review11_personal_root_old_server.py`).
- Presun von (`move_refusal`): vlastný osobný objekt (uložený ako autorov a zapečatený jeho kľúčom
  mimo denníka) smie z tímového priečinka odísť bez `may_write`, ak cieľ nie je v tímovom
  priečinku. Je to jediná cesta, ako staré osobné priečinky pod koreňom a tier-2 položky
  v zdieľaných priečinkoch dostať do osobného koreňa (migrácia); cudzí objekt tak odísť nesmie.
- Keď sú klienti migrovaní, výnimka nálezu 204 (osobný kľúč pod tímovým priečinkom s `may_write`)
  a osobný strom priamo pod koreňom (H4/H8) padnú: pod tímovým priečinkom len kľúče z denníka.

Medzitým sa nepridávajú nové tímové funkcie.
